"""
routes/documents.py — The complete document upload and retrieval pipeline.

Upload pipeline (13 steps):
  1. Receive file + metadata
  2. JWT Auth + Role check
  3. Case participant check
  4. DSC certificate check
  5. AI-OCR scan (sensitivity + ELA forgery detection)
  6. Forgery decision (bump sensitivity if tampered, log AI_FORGERY_ATTEMPT)
  7. AES-256-GCM encryption via Security Layer (VaultRouter)
  8. Store encrypted blob in Cloudflare R2 (Vault 2)
  9. Store key material + chain hash in PostgreSQL (Vault 1)
  10. Create Quorum Approval Request
  11. Write to WORM Audit Log
  12. DB trigger auto-fires notifications
  13. Return 201 with document_id, chain_hash, sensitivity, tamper_score
"""
import uuid
import sys
import os
import logging
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import StreamingResponse
from typing import Optional

# Add security layer to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'security-and-database'))
from securechain_security.vault_router import VaultRouter
from securechain_security.adapters.db_adapter import DatabaseAdapter
from securechain_security.adapters.storage_adapter import CloudflareR2Adapter
from securechain_security.chain_verifier import ChainVerifier

from database import db_cursor
from auth.rbac import get_current_user, require_roles, require_case_access
from services.ocr_client import scan_document
from services.quorum_client import create_approval_request

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Documents"])

# Initialise singletons
vault_router = VaultRouter()
db_adapter = DatabaseAdapter()
r2_adapter = CloudflareR2Adapter()
chain_verifier = ChainVerifier()

UPLOAD_ALLOWED_ROLES = (
    "INVESTIGATING_OFFICER", "STATION_HOUSE_OFFICER",
    "FORENSIC_EXPERT", "FORENSIC_LAB_HEAD", "SENIOR_POLICE_OFFICER"
)


# ------------------------------------------------------------------
# GET /documents — Flat list of all documents for current user
# ------------------------------------------------------------------
@router.get("/documents")
def list_all_documents(current_user: dict = Depends(get_current_user)):
    """Return all documents accessible to the current user."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT d.id, d.title, d.document_type, d.sensitivity_level,
                   d.status, d.created_at, d.case_id,
                   dv.version_number, dv.chain_hash AS sha256_hash
            FROM documents d
            LEFT JOIN document_versions dv ON dv.id = d.current_version_id
            WHERE d.created_by = %s::uuid
               OR d.case_id IN (
                   SELECT case_id FROM case_participants
                   WHERE participant_id = %s::uuid AND removed_at IS NULL
               )
            ORDER BY d.created_at DESC
        """, (current_user["sub"], current_user["sub"]))
        docs = cur.fetchall()

    # Also fetch active edit requests for each document
    items = []
    for d in docs:
        doc = dict(d)
        with db_cursor() as cur2:
            cur2.execute("""
                SELECT id, status, requester_id
                FROM edit_requests
                WHERE document_id = %s::uuid AND status = 'PENDING'
                ORDER BY created_at DESC LIMIT 1
            """, (doc["id"],))
            req = cur2.fetchone()
            if req:
                doc["active_edit_request"] = dict(req)
                doc["active_edit_request_id"] = req["id"]
        items.append(doc)

    return {"items": items, "total": len(items)}


# ------------------------------------------------------------------
# GET /personas — Role persona definitions for the UI
# ------------------------------------------------------------------
@router.get("/personas")
def get_personas():
    """Return static role persona definitions for the frontend portal."""
    return {
        "personas": [
            {"id": "POLICE", "label": "Police Officer", "prefix": ["DL-IO", "DL-SHO", "DL-SPO", "POL"]},
            {"id": "FORENSIC", "label": "Forensic Expert", "prefix": ["DL-FE", "DL-FLH", "DL-FA", "FSL"]},
            {"id": "JUDICIAL", "label": "Judicial Officer", "prefix": ["DL-MAG", "DL-JDG", "DL-PP", "DL-CR"]},
            {"id": "AUDITOR", "label": "System Auditor", "prefix": ["SYS-AUD", "SYS-SUPER", "SYS-ADMIN"]},
        ]
    }




def _check_dsc(user_id: str) -> None:
    """Verify that the officer has a valid, non-expired DSC certificate."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT dsc_certificate, dsc_expires_at
            FROM users WHERE id = %s
        """, (user_id,))
        user = cur.fetchone()
    if not user or not user["dsc_certificate"]:
        raise HTTPException(status_code=403, detail="DSC certificate not configured for this user.")
    if user["dsc_expires_at"] and user["dsc_expires_at"] < date.today():
        raise HTTPException(status_code=403, detail="DSC certificate is expired. Upload blocked.")


def _write_audit_log(cur, event_type: str, case_id: str, document_id: str,
                     actor_id: str, severity: str, metadata: dict):
    log_id = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO audit_logs (id, event_type, case_id, document_id, actor_id, severity, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
    """, (log_id, event_type, case_id, document_id, actor_id, severity,
          __import__('json').dumps(metadata)))


# ------------------------------------------------------------------
# POST /upload — The 13-Step Pipeline
# ------------------------------------------------------------------
@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(
    case_id: str = Form(...),
    document_type: str = Form(...),
    title: str = Form(...),
    sensitivity_override: Optional[str] = Form(None),  # Officer can override AI suggestion
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(*UPLOAD_ALLOWED_ROLES))
):
    officer_id = current_user["sub"]
    document_id = str(uuid.uuid4())

    # STEP 3 — Case participant check
    require_case_access(case_id, current_user)

    # STEP 4 — DSC certificate check
    _check_dsc(officer_id)

    # Read file bytes into memory
    file_bytes = await file.read()
    filename = file.filename or f"{document_id}.bin"

    # STEP 5 — AI-OCR scan
    logger.info(f"[UPLOAD] Running AI scan for doc {document_id}")
    scan_result = await scan_document(file_bytes, filename, officer_id)

    suggested_sensitivity = scan_result["suggested_sensitivity"]
    tamper_score = scan_result["tamper_score"]
    forgery_detected = scan_result["forgery_detected"]

    # STEP 6 — Forgery decision
    final_sensitivity = sensitivity_override or suggested_sensitivity
    if forgery_detected:
        final_sensitivity = "CRITICAL"
        logger.warning(f"[UPLOAD] AI forgery detected for {document_id}. Score={tamper_score}. Bumping to CRITICAL.")

    # STEP 7 — Encrypt via Security Layer
    logger.info(f"[UPLOAD] Encrypting document {document_id}")
    vault_package = vault_router.process_upload(
        plaintext=file_bytes,
        case_id=case_id,
        document_id=document_id,
        officer_id=officer_id
    )

    # STEP 8 — Store in Cloudflare R2 (Vault 2)
    r2_stored = False
    storage_key = vault_package.vault2_blob_ref
    try:
        r2_adapter.store_blob(storage_key, vault_package.vault2_blob)
        r2_stored = True
        logger.info(f"[UPLOAD] Blob stored in R2: {storage_key}")
    except Exception as e:
        logger.error(f"[UPLOAD] R2 storage failed for {document_id}: {e}")
        raise HTTPException(status_code=503, detail="Encrypted storage is temporarily unavailable. Upload aborted.")

    # STEP 9 — Store metadata in PostgreSQL (Vault 1)
    try:
        db_adapter.connect()
        db_adapter.store_vault_package(
            package=vault_package,
            title=title,
            document_type=document_type,
            sensitivity_level=final_sensitivity,
            file_size=len(file_bytes),
            mime_type=file.content_type or "application/octet-stream",
            original_filename=filename
        )
        logger.info(f"[UPLOAD] Vault 1 metadata committed for {document_id}")
    except Exception as e:
        # Atomic rollback: delete the R2 blob if DB write fails
        if r2_stored:
            try:
                r2_adapter.s3_client.delete_object(
                    Bucket=r2_adapter.bucket_name, Key=storage_key
                )
                logger.warning(f"[UPLOAD] Rolled back R2 blob {storage_key} after DB failure.")
            except Exception:
                pass
        logger.error(f"[UPLOAD] DB storage failed for {document_id}: {e}")
        raise HTTPException(status_code=500, detail="Database write failed. Upload rolled back.")

    # STEP 10 — Create Quorum Approval Request
    chain_hash = vault_package.vault1_metadata["chain_record"]["chain_hash"]
    quorum_result = await create_approval_request(
        document_id=document_id,
        case_id=case_id,
        requester_id=officer_id,
        sensitivity=final_sensitivity,
        proposed_content=f"New upload: {title} ({document_type})"
    )

    # STEP 11 — Write to WORM Audit Log
    audit_severity = "CRITICAL" if forgery_detected else ("HIGH" if final_sensitivity in ("HIGH", "CRITICAL") else "INFO")
    with db_cursor() as cur:
        _write_audit_log(cur, "DOCUMENT_UPLOAD", case_id, document_id, officer_id, audit_severity, {
            "filename": filename,
            "sensitivity": final_sensitivity,
            "tamper_score": tamper_score,
            "forgery_detected": forgery_detected,
            "chain_hash": chain_hash,
            "storage_key": storage_key,
        })
        if forgery_detected:
            _write_audit_log(cur, "AI_FORGERY_ATTEMPT", case_id, document_id, officer_id, "CRITICAL", {
                "tamper_score": tamper_score,
                "filename": filename,
                "auto_action": "Sensitivity bumped to CRITICAL. Notified FORENSIC_LAB_HEAD and MAGISTRATE."
            })

    # STEP 12: DB trigger auto-fires notifications (handled by trg_notify_upload in PostgreSQL)

    # STEP 13 — Respond
    return {
        "document_id": document_id,
        "title": title,
        "case_id": case_id,
        "sensitivity_level": final_sensitivity,
        "ai_suggested_sensitivity": suggested_sensitivity,
        "tamper_score": tamper_score,
        "forgery_detected": forgery_detected,
        "chain_hash": chain_hash,
        "storage_key": storage_key,
        "quorum_request": quorum_result,
        "message": "Document uploaded, encrypted, and queued for quorum approval."
    }


# ------------------------------------------------------------------
# GET /cases/{case_id}/documents — List all documents in a case
# ------------------------------------------------------------------
@router.get("/cases/{case_id}/documents")
def list_documents(case_id: str, current_user: dict = Depends(get_current_user)):
    require_case_access(case_id, current_user)
    with db_cursor() as cur:
        cur.execute("""
            SELECT d.id, d.title, d.document_type, d.sensitivity_level,
                   d.status, d.created_at,
                   u.name AS uploaded_by,
                   dv.version_number AS latest_version,
                   dv.chain_hash
            FROM documents d
            JOIN users u ON u.id = d.created_by
            LEFT JOIN document_versions dv ON dv.id = d.current_version_id
            WHERE d.case_id = %s
            ORDER BY d.created_at DESC
        """, (case_id,))
        docs = cur.fetchall()
    return {"documents": [dict(d) for d in docs]}


# ------------------------------------------------------------------
# GET /documents/{document_id}/versions — Version history
# ------------------------------------------------------------------
@router.get("/documents/{document_id}/versions")
def get_document_versions(document_id: str, current_user: dict = Depends(get_current_user)):
    with db_cursor() as cur:
        # Get case_id to check access
        cur.execute("SELECT case_id FROM documents WHERE id = %s", (document_id,))
        doc = cur.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")

    require_case_access(doc["case_id"], current_user)

    with db_cursor() as cur:
        cur.execute("""
            SELECT version_number, doc_hash, chain_hash, prev_chain_hash,
                   created_at, original_filename, file_size, mime_type,
                   status, quorum_token
            FROM document_versions
            WHERE document_id = %s
            ORDER BY version_number ASC
        """, (document_id,))
        versions = cur.fetchall()

    return {
        "document_id": document_id,
        "versions": [dict(v) for v in versions],
        "total": len(versions)
    }
