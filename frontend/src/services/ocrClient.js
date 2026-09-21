/**
 * ocrClient.js
 * ────────────────────────────────────────────────────────────────────────────
 * Dedicated API client for the SecureChain OCR + NLP + Forensics pipeline.
 *
 * The pipeline runs on Kaggle (GPU) and is exposed via a static ngrok tunnel.
 * It is completely separate from the main FastAPI backend (localhost:8000).
 *
 * Endpoints consumed:
 *   GET  /api/health
 *   POST /api/case/submit   (multipart/form-data)
 *
 * Case-mode strings (must match core/case_validation.py exactly):
 *   NEW_FIR_MODE      = "Register New FIR (first time)"
 *   EXISTING_CASE_MODE = "Existing Case Folder (update / add documents)"
 */

// Read from frontend/.env → VITE_OCR_PIPELINE_URL
// Falls back to the static ngrok URL if env var is not set.
const OCR_BASE_URL =
  import.meta.env.VITE_OCR_PIPELINE_URL ||
  'https://constable-stiffness-purplish.ngrok-free.dev';

// ngrok free-tier shows an HTML splash page for browser GETs.
// Sending this header bypasses it for all API calls.
const NGROK_HEADERS = {
  'ngrok-skip-browser-warning': 'true',
};

export const OCR_CASE_MODES = {
  NEW_FIR: 'Register New FIR (first time)',
  EXISTING_CASE: 'Existing Case Folder (update / add documents)',
};

/**
 * Health-check — confirms Kaggle kernel + ngrok tunnel are alive.
 * @returns {Promise<{status: string, service: string}|null>}
 */
export async function checkOCRHealth() {
  try {
    const res = await fetch(`${OCR_BASE_URL}/api/health`, {
      headers: NGROK_HEADERS,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Submit a case (FIR and/or supporting documents) to the OCR pipeline.
 *
 * @param {object} params
 * @param {string}   params.caseMode          - OCR_CASE_MODES.NEW_FIR | OCR_CASE_MODES.EXISTING_CASE
 * @param {File}    [params.firFile]          - Mandatory for NEW_FIR mode
 * @param {File[]}  [params.supportingFiles]  - Optional additional documents
 * @param {boolean} [params.quickMode=true]   - Process only first 5 pages (faster)
 * @param {string}  [params.linkedFirNumber]  - FIR number to link supporting doc
 * @param {string}  [params.officerId]        - Officer employee ID for audit tagging
 *
 * @returns {Promise<OCRCaseResponse>}
 *
 * @typedef {object} OCRCaseResponse
 * @property {object[]} records                     - One extracted record per uploaded file
 * @property {SensitivityResult} sensitivity        - Highest sensitivity tier across all docs
 * @property {object[]} worm_log                    - WORM audit entries per document
 * @property {string|null} ela_preview_base64_png   - ELA forensic image as base64 PNG (or null)
 *
 * @typedef {object} SensitivityResult
 * @property {string} suggested_sensitivity_tier    - "Low" | "Medium" | "High"
 * @property {string} suggested_quorum              - Human-readable quorum requirement
 * @property {string[]} matched_high_risk_terms
 * @property {string[]} matched_medium_risk_terms
 * @property {string} note
 */
export async function submitCaseToOCR({
  caseMode,
  firFile,
  supportingFiles = [],
  quickMode = true,
  linkedFirNumber = '',
  officerId = '',
}) {
  const formData = new FormData();
  formData.append('case_mode', caseMode);
  formData.append('quick_mode', String(quickMode));
  formData.append('linked_fir_number', linkedFirNumber);
  formData.append('officer_id', officerId);

  if (firFile) {
    formData.append('fir_file', firFile);
  }

  supportingFiles.forEach((file) => {
    formData.append('supporting_files', file);
  });

  const res = await fetch(`${OCR_BASE_URL}/api/case/submit`, {
    method: 'POST',
    headers: NGROK_HEADERS, // Do NOT set Content-Type — let browser set multipart boundary
    body: formData,
  });

  if (!res.ok) {
    let detail = `OCR pipeline returned HTTP ${res.status}`;
    try {
      const errBody = await res.json();
      if (errBody?.detail) detail = errBody.detail;
    } catch { /* ignore parse error */ }
    throw new Error(detail);
  }

  return await res.json();
}

/**
 * Extract the most useful structured fields from the first OCR record
 * returned by the pipeline. Falls back to empty strings when a field
 * is absent (Qwen2-VL may omit optional fields for some document types).
 *
 * @param {object[]} records  - `response.records` from submitCaseToOCR
 * @returns {ExtractedFields}
 *
 * @typedef {object} ExtractedFields
 * @property {string} caseTitle
 * @property {number} caseTitleConf
 * @property {string} complainant
 * @property {number} complainantConf
 * @property {string} actsAndSections
 * @property {number} actsConf
 * @property {string} stolenValue
 * @property {number} stolenValueConf
 * @property {string} accused
 * @property {number} accusedConf
 * @property {string} policeStation
 * @property {number} policeStationConf
 * @property {string} incidentSummary
 * @property {number} incidentConf
 */
export function extractFieldsFromOCRRecord(records) {
  // Support both array of records or a single record object
  let rec = {};
  if (Array.isArray(records) && records.length > 0) {
    rec = records[0];
  } else if (records && typeof records === 'object') {
    rec = records.record || records;
  }

  // Helper to pick the first non-empty value among multiple key candidates
  const pick = (keys, defaultVal = '') => {
    for (const k of keys) {
      if (rec[k] !== undefined && rec[k] !== null && rec[k] !== '') {
        const val = rec[k];
        if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
          if (val.value !== undefined && val.value !== null) return val.value;
          if (val.name !== undefined && val.name !== null) return val.name;
        }
        return val;
      }
    }
    return defaultVal;
  };

  const pickConf = (keys, defaultConf = 95) => {
    for (const k of keys) {
      const confKey = `${k}_confidence`;
      if (rec[confKey] !== undefined && rec[confKey] !== null) return Math.round(Number(rec[confKey]));
      if (typeof rec[k] === 'object' && rec[k]?.confidence !== undefined)
        return Math.round(Number(rec[k].confidence));
    }
    return defaultConf;
  };

  // 1. Acts and sections (often returned as an array of strings by Qwen2-VL)
  let acts = pick(['acts_and_sections', 'sections', 'ipc_sections', 'bns_sections', 'applicable_sections'], '');
  if (Array.isArray(acts)) {
    acts = acts.map(a => (typeof a === 'object' ? (a.section || a.name || JSON.stringify(a)) : String(a))).join(', ');
  } else if (typeof acts === 'object' && acts !== null) {
    acts = JSON.stringify(acts);
  }

  // 2. Accused details (often returned as an array of objects by Qwen2-VL: [{name, alias, address}])
  let accusedVal = pick(['accused_details', 'accused_name', 'accused', 'suspect_name', 'accused_names'], '');
  if (Array.isArray(accusedVal)) {
    accusedVal = accusedVal.map(acc => {
      if (typeof acc === 'object' && acc !== null) {
        let str = acc.name || acc.accused_name || '';
        if (acc.alias) str += ` (alias ${acc.alias})`;
        if (acc.address) str += ` [Address: ${acc.address}]`;
        return str;
      }
      return String(acc);
    }).filter(Boolean).join(', ');
  }

  // 3. Stolen / Property value (total_value_inr or items_of_interest in Qwen2-VL)
  let valInr = pick(['total_value_inr', 'property_value', 'stolen_value', 'amount_involved', 'value_involved'], '');
  const itemsOfInterest = pick(['items_of_interest', 'property_details'], '');
  let finalStolenValue = '';
  if (valInr && itemsOfInterest) {
    finalStolenValue = `₹${valInr} (${itemsOfInterest})`;
  } else if (valInr) {
    finalStolenValue = `₹${valInr}`;
  } else if (itemsOfInterest) {
    finalStolenValue = itemsOfInterest;
  }

  // 4. Police Station & District
  const ps = pick(['police_station', 'station_name', 'ps_name'], '');
  const district = pick(['district', 'city'], '');
  let fullStation = ps;
  if (ps && district && !ps.toLowerCase().includes(district.toLowerCase())) {
    fullStation = `${ps}, ${district}`;
  } else if (!ps && district) {
    fullStation = district;
  }

  // 5. Incident Summary / English Narrative (fir_description_english in Qwen2-VL)
  const summary = pick([
    'fir_description_english',
    'fir_contents',
    'incident_summary',
    'statement_of_facts',
    'description',
    'contents',
    'incident_details',
    'summary'
  ], '');

  // 6. Complainant Name
  const complainantName = pick([
    'complainant_name',
    'complainant',
    'informant',
    'complainant_full_name',
    'victim_name'
  ], '');

  // 7. Case Title / Subject (Synthesize if not explicitly present)
  let title = pick(['case_title', 'title', 'fir_subject', 'subject'], '');
  const firNum = pick(['fir_number', 'case_number', 'fir_no'], '');
  if (!title) {
    if (firNum) {
      title = `FIR No. ${firNum}${fullStation ? ` - PS ${fullStation}` : ''}`;
    } else if (complainantName) {
      title = `Complaint by ${complainantName}${acts ? ` (u/s ${acts})` : ''}`;
    } else if (acts) {
      title = `Case under ${acts}`;
    } else {
      title = 'Scanned Legal Record Dossier';
    }
  }

  // 8. Explicit Jurisdiction, FIR No, and Year metadata
  const firNumber = pick(['fir_number', 'case_number', 'fir_no'], '');
  const yearVal = pick(['year', 'fir_year'], '');
  const dateOfFir = pick(['date_of_fir', 'fir_date', 'date'], '');
  const timeOfFir = pick(['time_of_fir', 'fir_time', 'time'], '');
  const dateOfOccurrence = pick(['date_of_occurrence', 'occurrence_date'], '');
  const placeOfOccurrence = pick(['place_of_occurrence', 'occurrence_place', 'incident_place'], '');
  const investigatingOfficer = pick(['investigating_officer', 'io_name', 'io'], '');
  const firRegisteredBy = pick(['fir_registered_by', 'registered_by', 'sho_name'], '');

  return {
    firNumber:        String(firNumber || ''),
    firNumberConf:    pickConf(['fir_number', 'case_number'], 95),

    district:         String(district || ''),
    districtConf:     pickConf(['district', 'city'], 90),

    policeStation:    String(ps || fullStation || ''),
    policeStationConf: pickConf(['police_station', 'station_name'], 95),

    year:             String(yearVal || ''),
    yearConf:         pickConf(['year'], 95),

    dateOfFir:        String(dateOfFir || ''),
    timeOfFir:        String(timeOfFir || ''),
    dateOfOccurrence: String(dateOfOccurrence || ''),
    placeOfOccurrence: String(placeOfOccurrence || ''),

    caseTitle:        String(title || ''),
    caseTitleConf:    pickConf(['case_title', 'title', 'fir_number'], 95),

    complainant:      String(complainantName || ''),
    complainantConf:  pickConf(['complainant_name', 'complainant', 'informant'], 90),

    actsAndSections:  String(acts || ''),
    actsConf:         pickConf(['acts_and_sections', 'sections', 'ipc_sections'], 90),

    stolenValue:      String(finalStolenValue || ''),
    stolenValueConf:  pickConf(['total_value_inr', 'property_value', 'stolen_value'], 90),

    accused:          String(accusedVal || ''),
    accusedConf:      pickConf(['accused_details', 'accused_name', 'accused'], 90),

    incidentSummary:  String(summary || ''),
    incidentConf:     pickConf(['fir_description_english', 'fir_contents', 'incident_summary'], 90),

    investigatingOfficer: String(investigatingOfficer || ''),
    firRegisteredBy:      String(firRegisteredBy || ''),
  };
}
