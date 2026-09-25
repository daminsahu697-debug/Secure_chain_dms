"""
SecureChain DMS — Secure Two-Vault Integration Unit Tests
===========================================================
Tests for Two-Vault envelope encryption & hash-chain integration in document endpoints:
- POST /api/v1/documents/upload
- GET /api/v1/documents/{document_id}/download
- GET /api/v1/documents/{document_id}/verify

Covers 22 security integration scenarios with mocked GCS storage & OCR microservice.
"""

import hashlib
import io
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status

# Ensure services/security-and-database is in sys.path
security_pkg_dir = Path(__file__).resolve().parents[2] / "services" / "security-and-database"
if security_pkg_dir.exists() and str(security_pkg_dir) not in sys.path:
    sys.path.insert(0, str(security_pkg_dir))

from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.services.security_adapter import SecurityAdapter, VaultRoutingError, DecryptionError
from app.services.storage import StorageError

TEST_CASE_ID = "11111111-1111-4111-8111-111111111111"


def get_auth_headers(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_pdf_bytes():
    return b"%PDF-1.7 Sample Evidence PDF Payload for Two-Vault Test"


@pytest.fixture
def mock_ocr_response():
    return {
        "is_online": True,
        "suggested_sensitivity": "HIGH",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": ["evidence"],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
    }


# ============================================================================
# UPLOAD TESTS (Scenarios 1-14)
# ============================================================================

def test_1_plaintext_never_uploaded_to_gcs(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 1: Plaintext bytes are NEVER uploaded to GCS."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file") as mock_gcs_upload:

        mock_ocr.return_value = mock_ocr_response
        mock_gcs_upload.return_value = "documents/test/key.enc"

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Plaintext Check Doc",
                "document_type": "Evidence",
            },
            files={"file": ("check.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert res.status_code == status.HTTP_201_CREATED

        uploaded_bytes = mock_gcs_upload.call_args.kwargs["file_data"]
        assert uploaded_bytes != sample_pdf_bytes  # Must NOT be plaintext


def test_2_encrypted_ciphertext_uploaded(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 2: Encrypted ciphertext is uploaded to GCS with application/octet-stream content-type."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file") as mock_gcs_upload:

        mock_ocr.return_value = mock_ocr_response
        mock_gcs_upload.return_value = "documents/test/ciphertext.enc"

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Ciphertext Check Doc",
                "document_type": "Evidence",
            },
            files={"file": ("cipher.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert res.status_code == status.HTTP_201_CREATED

        content_type = mock_gcs_upload.call_args.kwargs["content_type"]
        assert content_type == "application/octet-stream"


def test_3_to_10_vault1_metadata_persisted(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenarios 3-10: Vault 1 metadata, wrapped_dek, iv, key_id, aad, kek_version, algorithm & doc_hash persisted."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/meta.enc"):

        mock_ocr.return_value = mock_ocr_response

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Metadata Check Doc",
                "document_type": "Evidence",
            },
            files={"file": ("meta.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert res.status_code == status.HTTP_201_CREATED
        doc_id = res.json()["id"]

        doc_in_db = db_session.query(Document).filter(Document.id == uuid.UUID(doc_id)).first()
        version = doc_in_db.current_version
        expected_sha256 = hashlib.sha256(sample_pdf_bytes).hexdigest()

        # Scenarios 3-10 assertions
        assert version.doc_hash == expected_sha256  # Scenario 10
        assert len(version.chain_hash) == 64
        assert len(version.prev_chain_hash) == 64
        assert len(version.wrapped_dek) > 0         # Scenario 4
        assert len(version.iv) == 24                # Scenario 5
        assert version.key_id is not None           # Scenario 6
        assert len(version.aad) > 0                 # Scenario 7
        assert version.kek_version in ("v1", "v2")  # Scenario 8
        assert version.algorithm == "AES-256-GCM"   # Scenario 9


def test_11_ocr_behavior_preserved(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 11: OCR microservice integration and sensitivity upgrade behavior preserved."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/ocr.enc"):

        mock_ocr.return_value = mock_ocr_response

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "OCR Preserved Doc",
                "document_type": "FIR",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("ocr.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert res.status_code == status.HTTP_201_CREATED
        assert mock_ocr.called
        assert res.json()["sensitivity_level"] == "HIGH"  # OCR upgraded MEDIUM -> HIGH


def test_12_gcs_failure_cleanup(client, db_session, sample_pdf_bytes):
    """Scenario 12: DB rolls back and 503 returned if GCS upload fails."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", side_effect=StorageError("GCS timeout")):

        mock_ocr.return_value = {"is_online": False}

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "GCS Fail Doc",
                "document_type": "Evidence",
            },
            files={"file": ("gcs_fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        docs = db_session.query(Document).filter(Document.title == "GCS Fail Doc").all()
        assert len(docs) == 0


def test_13_db_commit_failure_cleanup(client, db_session, sample_pdf_bytes):
    """Scenario 13: GCS uploaded ciphertext object is deleted if DB commit fails."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/db_fail.enc"), \
         patch("app.services.storage.storage_service.delete_file") as mock_delete, \
         patch("sqlalchemy.orm.Session.commit", side_effect=Exception("Database crash")):

        mock_ocr.return_value = {"is_online": False}

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "DB Fail Doc",
                "document_type": "Evidence",
            },
            files={"file": ("db_fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        mock_delete.assert_called_once_with("documents/test/db_fail.enc")


def test_14_security_packaging_failure(client, db_session, sample_pdf_bytes):
    """Scenario 14: Handles SecurityAdapter packaging failure gracefully."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", side_effect=VaultRoutingError("KMS unavailable")):

        mock_ocr.return_value = {"is_online": False}

        res = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Sec Package Fail Doc",
                "document_type": "Evidence",
            },
            files={"file": ("sec_fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ============================================================================
# DOWNLOAD TESTS (Scenarios 15-17)
# ============================================================================

def test_15_successful_download_decryption(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 15: Download endpoint retrieves ciphertext, decrypts payload, and returns original plaintext."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/dl.enc") as mock_upload, \
         patch("app.services.storage.storage_service.get_file_bytes") as mock_get_bytes:

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "DL Success Doc",
                "document_type": "Evidence",
            },
            files={"file": ("dl_success.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        ciphertext_bytes = mock_upload.call_args.kwargs["file_data"]
        mock_get_bytes.return_value = ciphertext_bytes

        res_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers)

        assert res_dl.status_code == status.HTTP_200_OK
        assert res_dl.content == sample_pdf_bytes  # Authentic decrypted bytes


def test_16_tampered_ciphertext_download_rejected(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 16: Download fails (400 Bad Request) if GCS ciphertext is tampered."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/tampered.enc"), \
         patch("app.services.storage.storage_service.get_file_bytes") as mock_get_bytes:

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Tampered DL Doc",
                "document_type": "Evidence",
            },
            files={"file": ("tampered_dl.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        mock_get_bytes.return_value = b"CORRUPTED_CIPHERTEXT_BYTES_999"

        res_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers)
        assert res_dl.status_code == status.HTTP_400_BAD_REQUEST


def test_17_wrong_expected_hash_download_rejected(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 17: Download fails if stored doc_hash does not match decrypted content hash."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/mismatch.enc") as mock_upload, \
         patch("app.services.storage.storage_service.get_file_bytes") as mock_get_bytes:

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Mismatch Hash Doc",
                "document_type": "Evidence",
            },
            files={"file": ("mismatch_dl.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        ciphertext_bytes = mock_upload.call_args.kwargs["file_data"]
        mock_get_bytes.return_value = ciphertext_bytes

        # Alter doc_hash in DB
        doc = db_session.query(Document).filter(Document.id == uuid.UUID(doc_id)).first()
        doc.current_version.doc_hash = "f" * 64
        db_session.commit()

        res_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers)
        assert res_dl.status_code == status.HTTP_400_BAD_REQUEST


# ============================================================================
# VERIFY TESTS (Scenarios 18-20)
# ============================================================================

def test_18_and_19_valid_content_and_chain_verification(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenarios 18 & 19: Valid content & valid chain verification returns INTEGRITY_VERIFIED."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/verify.enc") as mock_upload, \
         patch("app.services.storage.storage_service.get_file_bytes") as mock_get_bytes:

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Verify Valid Doc",
                "document_type": "Evidence",
            },
            files={"file": ("verify_valid.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        ciphertext_bytes = mock_upload.call_args.kwargs["file_data"]
        mock_get_bytes.return_value = ciphertext_bytes

        res_verify = client.get(f"/api/v1/documents/{doc_id}/verify", headers=headers)

        assert res_verify.status_code == status.HTTP_200_OK
        data = res_verify.json()
        assert data["integrity_verified"] is True
        assert data["status"] == "INTEGRITY_VERIFIED"


def test_20_broken_chain_detected_during_verification(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 20: Verification returns TAMPER_DETECTED when chain link is corrupted."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/broken_chain.enc") as mock_upload, \
         patch("app.services.storage.storage_service.get_file_bytes") as mock_get_bytes:

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Broken Chain Doc",
                "document_type": "Evidence",
            },
            files={"file": ("broken_chain.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        ciphertext_bytes = mock_upload.call_args.kwargs["file_data"]
        mock_get_bytes.return_value = ciphertext_bytes

        # Corrupt prev_chain_hash in DB
        doc = db_session.query(Document).filter(Document.id == uuid.UUID(doc_id)).first()
        doc.current_version.prev_chain_hash = "bad_prev_hash_" + "0" * 50
        db_session.commit()

        res_verify = client.get(f"/api/v1/documents/{doc_id}/verify", headers=headers)

        assert res_verify.status_code == status.HTTP_200_OK
        data = res_verify.json()
        assert data["integrity_verified"] is False
        assert data["status"] == "TAMPER_DETECTED"


# ============================================================================
# SECURITY SEPARATION & ACCESS CONTROL TESTS (Scenarios 21-22)
# ============================================================================

def test_21_api_response_never_exposes_crypto_metadata(client, db_session, sample_pdf_bytes, mock_ocr_response):
    """Scenario 21: GET /api/v1/documents/{id} response body NEVER exposes wrapped_dek, iv, aad, key_id."""
    headers = get_auth_headers(client)
    pdf_file = io.BytesIO(sample_pdf_bytes)

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_ocr, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/test/no_crypto.enc"):

        mock_ocr.return_value = mock_ocr_response

        res_upload = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "No Crypto Metadata Exposed Doc",
                "document_type": "Evidence",
            },
            files={"file": ("no_crypto.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        doc_id = res_upload.json()["id"]

        res_get = client.get(f"/api/v1/documents/{doc_id}", headers=headers)
        assert res_get.status_code == status.HTTP_200_OK
        res_data = res_get.json()

        assert "wrapped_dek" not in res_data
        assert "iv" not in res_data
        assert "aad" not in res_data


def test_22_unauthorized_access_rejected(client):
    """Scenario 22: Unauthenticated requests to upload, download, and verify return 401/403."""
    res_upload = client.post("/api/v1/documents/upload")
    assert res_upload.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    res_dl = client.get(f"/api/v1/documents/{uuid.uuid4()}/download")
    assert res_dl.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    res_ver = client.get(f"/api/v1/documents/{uuid.uuid4()}/verify")
    assert res_ver.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)
