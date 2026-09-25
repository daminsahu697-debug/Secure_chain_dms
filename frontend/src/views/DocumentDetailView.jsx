import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  Lock, 
  Clock, 
  FileEdit, 
  Copy, 
  Check, 
  Hash, 
  FileCheck2, 
  ShieldCheck, 
  Printer, 
  AlertTriangle,
  User,
  Building2,
  Calendar,
  Layers,
  Sparkles,
  Gavel,
  Download,
  FileText,
  RefreshCw,
  AlertCircle,
  CheckCircle2
} from 'lucide-react';
import AshokaEmblem from '../components/AshokaEmblem';
import { translations } from '../i18n/translations';
import { useToast } from '../context/ToastContext';
import apiClient from '../services/apiClient';

/**
 * Dedicated Document Viewer per Master Spec Section 11:
 * - Its own dedicated page (NOT squeezed alongside case list)
 * - Rendered exactly like a real Indian FIR form under CrPC Section 154 / BNSS Section 173
 * - Serif font, thin black border, Ashoka Stambh emblem centered top
 * - In dark mode, form stays on a white "paper" card with dark text
 * - All 14 numbered fields
 * - Below the form: hash fingerprint (copyable), version badge ("Version 1.0 — Locked"),
 *   and amber "Request Edit / Add Update" button
 * - Clicking Request Edit instantly activates "🔴 PENDING QUORUM" banner with zero delay
 */
export default function DocumentDetailView({ 
  document: initialDoc, 
  onRequestEdit, 
  onOpenQuorum, 
  activeUser, 
  onBackToDashboard,
  lang = 'en'
}) {
  const t = translations[lang] || translations.en;
  const toast = useToast();
  const [selectedDoc, setSelectedDoc] = useState(initialDoc);
  const [backendDoc, setBackendDoc] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);

  // Verification & API State
  const [verificationResult, setVerificationResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [loadingMetadata, setLoadingMetadata] = useState(false);

  const sanitizeFilename = (name) => {
    if (!name) return 'document.pdf';
    let clean = name.replace(/[\/\\:\*\?"<>\|]/g, '_').trim();
    if (!clean) return 'document.pdf';
    if (!clean.toLowerCase().endsWith('.pdf')) {
      clean += '.pdf';
    }
    return clean;
  };

  const handleDownloadDocument = async () => {
    if (!selectedDoc?.id || downloading) return;
    try {
      setDownloading(true);
      const { blob, filename: headerFilename } = await apiClient.getBlob(`/documents/${selectedDoc.id}/download`);

      const finalFilename = headerFilename
        ? headerFilename.replace(/[\/\\:\*\?"<>\|]/g, '_')
        : sanitizeFilename(selectedDoc.title || selectedDoc.caseTitle || selectedDoc.firNo || 'document.pdf');

      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = finalFilename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);

      toast.success(`Downloaded document: ${finalFilename}`);
    } catch (err) {
      console.error("Download error:", err);
      toast.error(err.message || "Failed to download document.");
    } finally {
      setDownloading(false);
    }
  };

  // Edit Modal State
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editSummary, setEditSummary] = useState('');
  const [editSections, setEditSections] = useState('Section 120B / 468 IPC & Section 66 IT Act');
  const [additionalFacts, setAdditionalFacts] = useState('');
  const [proposalFile, setProposalFile] = useState(null);
  const [justTriggeredPending, setJustTriggeredPending] = useState(false);

  useEffect(() => {
    setSelectedDoc(initialDoc);
    setVerificationResult(null);
  }, [initialDoc]);

  // Fetch full document metadata from backend API
  useEffect(() => {
    const fetchMetadata = async () => {
      if (!initialDoc?.id) return;
      try {
        setLoadingMetadata(true);
        const data = await apiClient.get(`/documents/${initialDoc.id}`);
        if (data) {
          setBackendDoc(data);
          setSelectedDoc(prev => ({
            ...prev,
            ...data,
            title: data.title || prev?.title,
            firNo: data.case_number || prev?.firNo || (data.case_id && !String(data.case_id).startsWith('11111111') ? `CASE-${String(data.case_id).substring(0, 8).toUpperCase()}` : `DOC-${String(data.id).substring(0, 8).toUpperCase()}`),
            sha256: data.sha256_hash || data.stored_hash || prev?.sha256,
            status: data.status || (data.is_sealed ? 'LOCKED' : prev?.status),
            currentVersion: data.version_number ? `1.${data.version_number - 1}` : (data.current_version_id ? '1.0' : prev?.currentVersion),
          }));
        }
      } catch (err) {
        console.warn("Could not fetch document metadata", err);
      } finally {
        setLoadingMetadata(false);
      }
    };
    fetchMetadata();
  }, [initialDoc?.id]);

  const [linkedDocs, setLinkedDocs] = useState([]);
  // NEW: Fetch interlinked digital evidence for the SAME case
  useEffect(() => {
    let isMounted = true;
    if (initialDoc?.case_id) {
      const fetchLinked = async () => {
        try {
          const res = await apiClient.get(`/documents`);
          if (res?.items && isMounted) {
            // Filter to same case_id, excluding the current document itself
            const related = res.items.filter(d => String(d.case_id) === String(initialDoc.case_id) && d.id !== initialDoc.id);
            setLinkedDocs(related);
          }
        } catch (err) {
          console.warn("Could not fetch linked digital evidence", err);
        }
      };
      fetchLinked();
    }
    return () => { isMounted = false; };
  }, [initialDoc?.case_id]);

  // Real Integrity Verification via GET /api/v1/documents/{id}/verify
  const handleVerifyIntegrity = async () => {
    if (!selectedDoc?.id) return;
    setVerifying(true);
    try {
      const res = await apiClient.get(`/documents/${selectedDoc.id}/verify`);
      if (res) {
        setVerificationResult(res);
        if (res.status === 'INTEGRITY_VERIFIED' || res.is_valid) {
          toast.success("Document integrity verified! Stored hash matches calculated fingerprint.");
        } else if (res.status === 'TAMPER_DETECTED') {
          toast.error("TAMPER DETECTED! Stored hash does not match current file bytes.");
        } else {
          toast.info(res.detail || `Verification status: ${res.status}`);
        }
      }
    } catch (err) {
      console.error("Verification error:", err);
      toast.error(err.message || "Failed to verify document integrity.");
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyHash = () => {
    const hashToCopy = verificationResult?.stored_hash || selectedDoc?.sha256;
    if (hashToCopy) {
      navigator.clipboard.writeText(hashToCopy);
      setCopiedHash(true);
      toast.success('Cryptographic SHA-256 hash copied to clipboard');
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleSubmitEdit = (e) => {
    e.preventDefault();
    if (!editSummary.trim()) {
      toast.error("Please provide an amendment rationale summary.");
      return;
    }

    if (!proposalFile) {
      toast.error("Please select a proposed amendment PDF file.");
      return;
    }

    const isPdf = proposalFile.type === 'application/pdf' || proposalFile.name.toLowerCase().endsWith('.pdf');
    if (!isPdf) {
      toast.error("Only PDF files are supported for proposed amendments.");
      return;
    }

    const reason = editSections.trim()
      ? `${editSummary.trim()} [Sections: ${editSections.trim()}]`
      : editSummary.trim();

    setJustTriggeredPending(true);
    setEditModalOpen(false);

    // Call onRequestEdit
    if (onRequestEdit) {
      onRequestEdit(selectedDoc.id, {
        reason,
        proposalFile,
        editSummary,
        editSections,
        additionalFacts
      });
    }

    setProposalFile(null);
  };

  const isLocked = selectedDoc.status === 'LOCKED' && !justTriggeredPending;
  const isPending = selectedDoc.status === 'PENDING_QUORUM' || justTriggeredPending;

  return (
    <div className="flex-1 bg-[#FFF9F2] dark:bg-slate-950 flex flex-col min-h-[calc(100vh-140px)] w-full py-4 sm:py-8 px-3 sm:px-6 transition-colors">
      <div className="max-w-4xl mx-auto w-full space-y-6">
        
        {/* Top Breadcrumb & Actions Bar */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl px-4 sm:px-6 py-3 flex items-center justify-between shadow-xs transition-colors">
          <button
            onClick={onBackToDashboard}
            className="text-xs font-bold text-slate-600 dark:text-slate-400 hover:text-[#FF6A1A] dark:hover:text-[#FF6A1A] flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>{lang === 'hi' ? 'डैशबोर्ड पर वापस जाएं' : 'Back to Case Records'}</span>
          </button>

          <div className="flex items-center space-x-3 text-xs">
            <span className="font-mono text-slate-500 dark:text-slate-400">
              DOCKET: <strong className="text-slate-900 dark:text-slate-100">{selectedDoc.id}</strong>
            </span>

            {/* Real Download Original Document Action Button */}
            <button
              onClick={handleDownloadDocument}
              disabled={downloading}
              className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-700 text-white font-bold flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors shadow-xs"
              title="Download original decrypted PDF document"
            >
              {downloading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>{downloading ? 'Downloading...' : 'Download Original File'}</span>
            </button>

            {/* Real Verify Integrity Action Button */}
            <button
              onClick={handleVerifyIntegrity}
              disabled={verifying}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors shadow-xs"
              title="Verify document integrity via FastAPI SecurityAdapter"
            >
              {verifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{verifying ? 'Verifying...' : 'Verify Integrity'}</span>
            </button>

            <button
              onClick={() => window.print()}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 cursor-pointer"
              title="Print Official CrPC 154 Form"
            >
              <Printer className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* INSTANT RED / AMBER BANNER WHEN PENDING QUORUM (SECTION 11) */}
        {isPending && (
          <div className="p-4 rounded-2xl bg-amber-50 dark:bg-amber-950/60 border-2 border-amber-400 dark:border-amber-600 text-amber-900 dark:text-amber-200 flex flex-wrap items-center justify-between gap-3 shadow-md animate-in fade-in slide-in-from-top-2">
            <div className="flex items-center space-x-3">
              <span className="flex h-3.5 w-3.5 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-red-500"></span>
              </span>
              <div>
                <div className="font-bold text-xs uppercase tracking-wide flex items-center gap-2 text-red-700 dark:text-red-400">
                  <span>🔴 PENDING QUORUM</span>
                  <span>— Supplementary Amendment Draft Active (v{selectedDoc.draftVersion || '1.1'})</span>
                </div>
                <div className="text-[11px] text-slate-700 dark:text-slate-300 mt-0.5">
                  An edit request has been registered. It requires multi-officer quorum consensus before being committed to the head ledger.
                </div>
              </div>
            </div>

            <button
              onClick={() => onOpenQuorum && onOpenQuorum(selectedDoc)}
              className="px-4 py-2 bg-[#FF6A1A] hover:bg-[#E85B0E] text-white font-bold rounded-xl text-xs shadow-xs transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <FileCheck2 className="w-4 h-4" />
              <span>Open Quorum Board</span>
            </button>
          </div>
        )}

        {/* AUTHENTIC OFFICIAL CrPC 154 / BNSS 173 FORM (ALWAYS WHITE PAPER CARD WITH DARK TEXT) */}
        <div className="bg-white text-slate-900 border-2 border-slate-900 p-6 sm:p-12 shadow-2xl rounded-sm relative watermark-emblem font-serif leading-relaxed text-xs sm:text-sm w-full mx-auto">
          
          {/* Header: Centered Ashoka Stambh Emblem Silhouette */}
          <div className="text-center space-y-2 border-b-2 border-slate-900 pb-5 mb-6">
            <AshokaEmblem className="w-16 h-20 mx-auto mb-1" color="#000000" />
            
            <h2 className="text-base sm:text-xl font-extrabold uppercase tracking-wider text-slate-900">
              FIRST INFORMATION REPORT / प्रथम सूचना रिपोर्ट
            </h2>
            <p className="text-xs font-semibold italic text-slate-800">
              (Under Section 154 Cr.P.C. / धारा 154 दंड प्रक्रिया संहिता एवं धारा 173 BNSS)
            </p>
            
            {/* Form Metadata Header Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-3 text-xs border-t border-slate-400 mt-2 font-mono text-slate-900">
              <div><strong>District / जिला:</strong> {selectedDoc.district || "New Delhi"}</div>
              <div><strong>P.S. / थाना:</strong> {selectedDoc.policeStation?.split(',')[0]}</div>
              <div><strong>Year / वर्ष:</strong> {selectedDoc.year || "2024"}</div>
              <div><strong>FIR No. / प्र.सू.सं.:</strong> {selectedDoc.firNo}</div>
              <div><strong>Date / तिथि:</strong> {new Date(selectedDoc.dateReported).toLocaleDateString()}</div>
            </div>
          </div>

          {/* 14 Numbered Standard Form Fields Field-For-Field */}
          <div className="space-y-4">
            
            {/* 1. Acts & Sections */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">1. Acts & Sections / अधिनियम एवं धाराएं:</span>
              <span className="ml-2 font-mono text-xs font-semibold text-slate-900">
                {selectedDoc.actsAndSections}
              </span>
            </div>

            {/* 2. Occurrence of Offence */}
            <div className="border-b border-slate-300 pb-2 space-y-1">
              <span className="font-bold block">2. Occurrence of Offence / अपराध की घटना:</span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs pl-4">
                <div><strong>(a) Day/Date/Time:</strong> {selectedDoc.occurrenceDate || "14/08/2024 09:30 IST"}</div>
                <div><strong>(b) Information received at P.S.:</strong> {new Date(selectedDoc.dateReported).toLocaleTimeString()}</div>
                <div><strong>(c) General Diary Reference:</strong> GD Entry No. 24A at 10:15 IST</div>
              </div>
            </div>

            {/* 3. Type of Information */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">3. Type of Information / सूचना का प्रकार:</span>
              <span className="ml-2 font-semibold">{selectedDoc.typeOfInformation || "Written Official Report"}</span>
            </div>

            {/* 4. Place of Occurrence */}
            <div className="border-b border-slate-300 pb-2 space-y-1">
              <span className="font-bold block">4. Place of Occurrence / घटनास्थल:</span>
              <div className="text-xs pl-4 space-y-0.5">
                <div><strong>(a) Direction & distance from P.S.:</strong> 4.2 KM West from Station</div>
                <div><strong>(b) Address / पता:</strong> {selectedDoc.placeOfOccurrence || "Corporate Banking Division, Central Sector"}</div>
              </div>
            </div>

            {/* 5. Complainant / Informant */}
            <div className="border-b border-slate-300 pb-2 space-y-1">
              <span className="font-bold block">5. Complainant / Informant / शिकायतकर्ता:</span>
              <div className="text-xs pl-4">
                <strong>Name & Particulars:</strong> {selectedDoc.complainant}
              </div>
            </div>

            {/* 6. Details of Known / Suspected / Unknown Accused */}
            <div className="border-b border-slate-300 pb-2 space-y-1">
              <span className="font-bold block">6. Details of Known / Suspected / Unknown Accused / अभियुक्त का विवरण:</span>
              <div className="text-xs pl-4 font-mono font-medium text-slate-800">
                {selectedDoc.accused}
              </div>
            </div>

            {/* 7. Reasons for delay in reporting */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">7. Reasons for delay in reporting (if any) / विलंब का कारण:</span>
              <span className="ml-2 text-xs">{selectedDoc.delayReasons || "Nil / Immediate Reporting"}</span>
            </div>

            {/* 8. Particulars of properties stolen / involved */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">8. Particulars of properties stolen / involved / संपत्ति का विवरण:</span>
              <span className="ml-2 text-xs">{selectedDoc.propertiesInvolved || "Forensic hardware exhibits and transaction ledgers"}</span>
            </div>

            {/* 9. Total value of properties stolen */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">9. Total value of properties stolen / involved / कुल मूल्य:</span>
              <span className="ml-2 text-xs font-mono font-bold text-[#FF6A1A]">{selectedDoc.stolenValue || "Under statutory audit assessment"}</span>
            </div>

            {/* 10. Inquest Report / U.D. Case No., if any */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">10. Inquest Report / U.D. Case No., if any / मृत्यु समीक्षा रिपोर्ट:</span>
              <span className="ml-2 text-xs font-mono">{selectedDoc.inquestNo || "N/A"}</span>
            </div>

            {/* 11. F.I.R. Contents (Statement of facts) */}
            <div className="border-b border-slate-300 pb-3 space-y-1.5">
              <span className="font-bold block">11. F.I.R. Contents (body text) / प्रथम सूचना रिपोर्ट के तथ्य:</span>
              <div className="p-4 bg-slate-50 border border-slate-300 rounded-xl text-xs whitespace-pre-line leading-relaxed font-sans text-slate-800">
                {selectedDoc.incidentSummary}
              </div>
            </div>

            {/* 12. Action Taken */}
            <div className="border-b border-slate-300 pb-2">
              <span className="font-bold">12. Action Taken / की गई कार्रवाई:</span>
              <span className="ml-2 text-xs">{selectedDoc.actionTaken || "Case registered, digital exhibits cryptographically sealed, and investigation initiated under Section 154 CrPC."}</span>
            </div>

            {/* 13 & 14 Signatures & Dispatch */}
            <div className="pt-4 grid grid-cols-1 sm:grid-cols-2 gap-6 text-xs">
              {/* 13. Complainant Signature */}
              <div className="border p-3.5 rounded-xl border-slate-300 bg-slate-50 text-center space-y-3">
                <span className="font-bold block text-[11px]">13. Signature / Thumb Impression of Informant:</span>
                <div className="h-8 flex items-center justify-center font-mono italic text-slate-600 text-xs">
                  [Digitally Sealed / e-Sign Verified]
                </div>
              </div>

              {/* 14. Officer in Charge Signature (Generic Role Title ONLY) */}
              <div className="border p-3.5 rounded-xl border-slate-300 bg-slate-50 text-center space-y-1.5">
                <span className="font-bold block text-[11px]">14. Signature of Officer in Charge / थाना प्रभारी:</span>
                <div className="text-xs space-y-0.5">
                  <div>Name: <strong>Police Official (Investigating Officer)</strong></div>
                  <div>Rank: <strong>Sub-Inspector</strong> • No.: <strong>DL-4892</strong></div>
                  <div className="text-[10px] text-slate-500 font-mono">Date & Time of dispatch to court: Same Day 17:00 IST</div>
                </div>
              </div>
            </div>

          </div>
        </div>

        {/* ================= OFFICIAL JUDICIAL VERDICT (NEW FEATURE) ================= */}
        {selectedDoc?.verdict && (
          <div className="bg-white dark:bg-slate-900 border border-sky-300 dark:border-sky-700/70 rounded-3xl p-6 sm:p-8 shadow-sm space-y-4 animate-in fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-sky-100 dark:bg-sky-950 text-[#4FA8E0] flex items-center justify-center">
                  <Gavel className="w-5 h-5" />
                </div>
                <div>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-sky-100 dark:bg-sky-950 text-[#4FA8E0] border border-sky-200 dark:border-sky-800">
                    Authoritative Adjudication (Document Type: Judgment)
                  </span>
                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1 font-serif">
                    {selectedDoc.verdict.verdictTitle}
                  </h3>
                </div>
              </div>
              <div className="flex items-center gap-2 self-start sm:self-auto">
                <span className="px-3 py-1 rounded-full text-xs font-extrabold uppercase bg-sky-100 dark:bg-sky-900 text-[#4FA8E0] border border-sky-300 dark:border-sky-700">
                  {selectedDoc.verdict.disposition}
                </span>
                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 flex items-center gap-1">
                  <Lock className="w-3 h-3" />
                  <span>Sealed & Final</span>
                </span>
              </div>
            </div>

            <div className="p-4 bg-slate-50 dark:bg-slate-800/60 rounded-2xl border border-slate-200 dark:border-slate-700/60 space-y-2 font-serif text-slate-800 dark:text-slate-200">
              <div className="text-xs font-bold text-slate-500 dark:text-slate-400 font-sans uppercase tracking-wider">
                Human-Confirmed Operative Order (CrPC / BNSS)
              </div>
              <p className="text-xs sm:text-sm leading-relaxed italic">
                "{selectedDoc.verdict.summary || 'Judicial ruling entered and immutably locked on the ledger.'}"
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-slate-600 dark:text-slate-400 font-sans">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/50">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Presiding Bench</span>
                <span className="font-bold text-slate-800 dark:text-slate-200">{selectedDoc.verdict.bench || selectedDoc.verdict.presidingCourt}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/50">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Adjudicating Judicial Officer</span>
                <span className="font-bold text-slate-800 dark:text-slate-200">{selectedDoc.verdict.judgeName} ({selectedDoc.verdict.judgeBadge})</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/50">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Pronouncement Timestamp</span>
                <span className="font-bold text-slate-800 dark:text-slate-200">{new Date(selectedDoc.verdict.deliveredAt).toLocaleString()}</span>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-sky-50/60 dark:bg-sky-950/30 rounded-xl border border-sky-200 dark:border-sky-900/60 text-xs">
              <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate max-w-lg">
                SHA-256 Judgment Digest: <strong className="text-sky-800 dark:text-sky-300">{selectedDoc.verdict.fileSha256}</strong>
              </div>
              <button
                type="button"
                onClick={() => {
                  const element = document.createElement("a");
                  const file = new Blob([
                    `OFFICIAL JUDICIAL VERDICT & FINAL COURT ORDER\n` +
                    `Case FIR: ${selectedDoc.firNo}\n` +
                    `Docket Title: ${selectedDoc.caseTitle}\n` +
                    `Presiding Bench: ${selectedDoc.verdict.bench || selectedDoc.verdict.presidingCourt}\n` +
                    `Presiding Officer: ${selectedDoc.verdict.judgeName} (${selectedDoc.verdict.judgeBadge})\n` +
                    `Pronounced: ${selectedDoc.verdict.deliveredAt}\n` +
                    `Operative Disposition: ${selectedDoc.verdict.disposition}\n` +
                    `SHA-256 Digest: ${selectedDoc.verdict.fileSha256}\n\n` +
                    `OPERATIVE COURT RULING:\n${selectedDoc.verdict.summary}\n`
                  ], { type: 'text/plain' });
                  element.href = URL.createObjectURL(file);
                  element.download = `Verdict_${selectedDoc.firNo.replace(/[\/\\:]/g, '_')}.txt`;
                  document.body.appendChild(element);
                  element.click();
                  document.body.removeChild(element);
                  toast.success("Certified Court Order downloaded.");
                }}
                className="px-3.5 py-1.5 bg-[#4FA8E0] hover:bg-[#3B97D1] text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center justify-center gap-1.5 cursor-pointer self-start sm:self-auto"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Judgment</span>
              </button>
            </div>
          </div>
        )}

        {/* Real Backend Integrity Verification Panel */}
        {verificationResult && (
          <div className={`p-4 sm:p-6 rounded-2xl border-2 transition-all space-y-3 animate-in fade-in ${
            verificationResult.integrity_verified
              ? 'bg-emerald-50/70 dark:bg-emerald-950/40 border-emerald-400 dark:border-emerald-700 text-emerald-950 dark:text-emerald-200'
              : verificationResult.status === 'TAMPER_DETECTED'
              ? 'bg-rose-50/80 dark:bg-rose-950/60 border-rose-400 dark:border-rose-700 text-rose-950 dark:text-rose-200'
              : 'bg-amber-50/80 dark:bg-amber-950/60 border-amber-400 dark:border-amber-700 text-amber-950 dark:text-amber-200'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 font-bold text-xs">
                {verificationResult.integrity_verified ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                ) : verificationResult.status === 'TAMPER_DETECTED' ? (
                  <AlertTriangle className="w-5 h-5 text-rose-600 dark:text-rose-400" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                )}
                <span className="uppercase tracking-wider font-mono font-extrabold text-sm">
                  {verificationResult.integrity_verified ? 'INTEGRITY VERIFIED' : verificationResult.status}
                </span>
              </div>
              <span className="text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded bg-white/70 dark:bg-slate-900/60 border">
                Version {verificationResult.version || '1.0'}
              </span>
            </div>

            <p className="text-xs leading-relaxed font-sans">{verificationResult.detail}</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono pt-1 border-t border-slate-200 dark:border-slate-800">
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 block">Stored Digest</span>
                <span className="break-all font-semibold">{verificationResult.stored_hash || 'N/A'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 block">Calculated Digest</span>
                <span className="break-all font-semibold">{verificationResult.calculated_hash || 'N/A'}</span>
              </div>
            </div>
          </div>
        )}

        {/* ================= CONTROLS BELOW THE FORM (SECTION 11) ================= */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 sm:p-6 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 transition-colors">
          
          {/* Hash Fingerprint (Copyable) */}
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 text-[#4FA8E0]">
              <Hash className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-bold tracking-wider">
                Cryptographic Fingerprint (SHA-256)
              </div>
              <div className="font-mono text-xs text-[#000080] dark:text-sky-300 font-semibold flex items-center gap-2">
                <span>{verificationResult?.stored_hash ? `${verificationResult.stored_hash.substring(0, 24)}...` : selectedDoc.sha256 ? `${selectedDoc.sha256.substring(0, 24)}...` : '3d5f8a0e889c2b4c10294e77da1b1c3e...'}</span>
                <button 
                  onClick={handleCopyHash} 
                  className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition-colors cursor-pointer"
                  title="Copy full 64-character hash"
                >
                  {copiedHash ? <Check className="w-3.5 h-3.5 text-[#5FA777]" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          </div>

          {/* Action Buttons: Download Original File, Verify Integrity, Version Badge, Request Edit */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleDownloadDocument}
              disabled={downloading}
              className="px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-bold text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors shadow-sm"
              title="Download original decrypted PDF document"
            >
              {downloading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              <span>{downloading ? 'Downloading...' : 'Download Original File'}</span>
            </button>

            <button
              onClick={handleVerifyIntegrity}
              disabled={verifying}
              className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors shadow-sm"
            >
              {verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              <span>{verifying ? 'Verifying...' : 'Verify Integrity'}</span>
            </button>

            <span className={`px-3 py-1.5 rounded-xl text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 border ${
              isLocked 
                ? 'bg-emerald-50 dark:bg-emerald-950 text-[#307044] dark:text-emerald-300 border-emerald-300 dark:border-emerald-800' 
                : 'bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800'
            }`}>
              {isLocked ? <Lock className="w-3.5 h-3.5 text-[#5FA777]" /> : <Clock className="w-3.5 h-3.5 text-amber-600" />}
              <span>Version {selectedDoc.currentVersion || verificationResult?.version || '1.0'} — {isLocked ? 'Locked' : 'Pending Quorum'}</span>
            </span>

            {/* Amber "Request Edit / Add Update" Button */}
            {isLocked && (
              <button
                onClick={() => setEditModalOpen(true)}
                className="px-5 py-2.5 bg-amber-500 hover:bg-amber-600 text-white font-bold rounded-xl text-xs shadow-md hover:shadow-lg transition-all flex items-center gap-1.5 cursor-pointer"
              >
                <FileEdit className="w-4 h-4 stroke-[2.5]" />
                <span>Request Edit / Add Update</span>
              </button>
            )}
          </div>

        </div>

        {/* ================= LINKED DIGITAL EVIDENCE SECTION ================= */}
        {linkedDocs.length > 0 && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-sm mt-6 animate-in fade-in transition-colors max-w-5xl mx-auto">
            <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 mb-4">
              <div className="p-2.5 rounded-xl bg-sky-50 dark:bg-sky-900/40 text-[#4FA8E0]">
                <Layers className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Linked Digital Evidence & Connected Records
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Forensic reports and other documents explicitly linked to Case Ref {selectedDoc.firNo || selectedDoc.case_id}
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {linkedDocs.map(doc => (
                <div key={doc.id} className="p-4 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 hover:border-sky-300 transition-colors flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                      {doc.document_type || 'DIGITAL EVIDENCE'}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono flex items-center gap-1">
                      <Lock className="w-3 h-3 text-[#5FA777]" /> Locked
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-800 dark:text-slate-200 truncate">{doc.title}</h4>
                  <div className="text-[10px] text-slate-500 font-mono bg-slate-100 dark:bg-slate-800 p-1.5 rounded truncate">
                    SHA256: {doc.sha256_hash || doc.stored_hash || 'Pending...'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>

      {/* ================= EDIT REQUEST MODAL ================= */}
      {editModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 shadow-2xl max-w-lg w-full p-6 sm:p-8 space-y-4 animate-in fade-in">
            
            <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                Request Supplementary Amendment (CrPC 173(8))
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Submitting this update creates Draft v{parseFloat(selectedDoc.currentVersion || 1.0) + 0.1}. It requires multi-officer quorum consensus before being committed.
              </p>
            </div>

            <form onSubmit={handleSubmitEdit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">
                  Amendment Summary Rationale *
                </label>
                <textarea
                  rows={3}
                  value={editSummary}
                  onChange={(e) => setEditSummary(e.target.value)}
                  placeholder="e.g. Supplementary evidence addition under CrPC 173(8) following forensic confirmation of financial routing..."
                  className="w-full px-3.5 py-2.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#FF6A1A]"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">
                  Amended PDF Proposal File *
                </label>
                <input
                  type="file"
                  accept="application/pdf"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
                        setProposalFile(file);
                      } else {
                        toast.error("Only PDF files are supported for proposed amendments.");
                        e.target.value = '';
                        setProposalFile(null);
                      }
                    }
                  }}
                  className="w-full px-3.5 py-2 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#FF6A1A] file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-orange-100 file:text-[#FF6A1A] hover:file:bg-orange-200 cursor-pointer"
                />
                {proposalFile && (
                  <p className="text-[11px] text-emerald-600 font-medium mt-1">
                    ✓ Selected proposal: <strong>{proposalFile.name}</strong> ({(proposalFile.size / 1024).toFixed(1)} KB)
                  </p>
                )}
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">
                  Applicable Statutory Sections
                </label>
                <input
                  type="text"
                  value={editSections}
                  onChange={(e) => setEditSections(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#FF6A1A]"
                />
              </div>

              <div className="p-3 bg-orange-50 dark:bg-orange-950/40 rounded-xl text-[11px] text-orange-900 dark:text-orange-300 border border-orange-200 dark:border-orange-800">
                <strong>Rule 4B Enforcement:</strong> As the requesting officer, your account is mathematically blocked from approving this amendment. Independent supervisory reviewers must vote to confirm consensus.
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className="px-4 py-2 text-xs font-bold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2.5 bg-[#FF6A1A] hover:bg-[#E85B0E] text-white font-bold text-xs rounded-xl shadow-md cursor-pointer"
                >
                  Submit for Quorum Approval
                </button>
              </div>
            </form>

          </div>
        </div>
      )}

    </div>
  );
}
