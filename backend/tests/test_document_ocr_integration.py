import io
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.audit_log import AuditLog
from app.models.tamper_alert import TamperAlert
from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.services.hashing import calculate_sha256
from app.services.storage import StorageError

TEST_CASE_ID = "11111111-1111-4111-8111-111111111111"


def get_auth_headers(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    return {"Authorization": f"Bearer {token}"}, user_id


def test_a_upload_with_ocr_online(client, db_session):
    headers, user_id = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 Standard OCR Online Test Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_response = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.05,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": ["case"],
        "ela_preview_base64_png": None,
        "ocr_records": [{"text": "Extracted FIR text"}],
        "worm_log": [{"pixel_anomaly_coefficient": 0.05}],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/file.pdf"):

        mock_scan.return_value = mock_ocr_response

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "OCR Online Document",
                "document_type": "FIR",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("ocr_online.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        assert doc_data["title"] == "OCR Online Document"
        assert doc_data["sensitivity_level"] == "MEDIUM"

        # Verify AuditLog created
        audit = db_session.query(AuditLog).filter(AuditLog.document_id == uuid.UUID(doc_data["id"])).first()
        assert audit is not None
        assert "ONLINE" in audit.metadata_json


def test_b_upload_with_ocr_high_sensitivity_upgrade(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 High Sensitivity Upgrade Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_response = {
        "suggested_sensitivity": "HIGH",
        "tamper_score": 0.12,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": ["CONFIDENTIAL_EVIDENCE"],
        "matched_medium_risk_terms": [],
        "ela_preview_base64_png": None,
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/high.pdf"):

        mock_scan.return_value = mock_ocr_response

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Upgrade Sensitivity Report",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",  # User asked for MEDIUM
            },
            files={"file": ("upgrade.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        # Upgraded to HIGH
        assert doc_data["sensitivity_level"] == "HIGH"


def test_c_upload_ocr_medium_retains_user_high_sensitivity(client):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 Retain High Sensitivity Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_response = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/retain.pdf"):

        mock_scan.return_value = mock_ocr_response

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "User High Sensitivity",
                "document_type": "Evidence",
                "sensitivity_level": "HIGH",  # User asked for HIGH
            },
            files={"file": ("retain.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        # Preserves HIGH, never downgraded to MEDIUM
        assert doc_data["sensitivity_level"] == "HIGH"


def test_d_upload_ocr_offline_graceful_degradation(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 OCR Offline Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_offline = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "SERVICE_OFFLINE",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": False,
        "error_detail": "OCR connection refused",
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/offline.pdf"):

        mock_scan.return_value = mock_ocr_offline

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "OCR Offline Upload",
                "document_type": "Evidence",
                "sensitivity_level": "HIGH",
            },
            files={"file": ("offline.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        assert doc_data["sensitivity_level"] == "HIGH"

        # Ensure no TamperAlert created for service offline
        alerts = db_session.query(TamperAlert).filter(TamperAlert.document_id == uuid.UUID(doc_data["id"])).all()
        assert len(alerts) == 0

        # Ensure AuditLog records SERVICE_OFFLINE
        audit = db_session.query(AuditLog).filter(AuditLog.document_id == uuid.UUID(doc_data["id"])).first()
        assert audit is not None
        assert "SERVICE_OFFLINE" in audit.metadata_json


def test_e_upload_ocr_timeout_handling(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 OCR Timeout Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_timeout = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "SERVICE_TIMEOUT",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": False,
        "error_detail": "OCR request timed out",
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/timeout.pdf"):

        mock_scan.return_value = mock_ocr_timeout

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "OCR Timeout Upload",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("timeout.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()

        # AuditLog records SERVICE_TIMEOUT
        audit = db_session.query(AuditLog).filter(AuditLog.document_id == uuid.UUID(doc_data["id"])).first()
        assert "SERVICE_TIMEOUT" in audit.metadata_json


def test_f_upload_ocr_http_failure_handling(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 OCR HTTP 500 Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_http_err = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "HTTP_ERROR_500",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": False,
        "error_detail": "OCR service 500 Internal Server Error",
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/http500.pdf"):

        mock_scan.return_value = mock_ocr_http_err

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "OCR HTTP 500 Upload",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("http500.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()

        audit = db_session.query(AuditLog).filter(AuditLog.document_id == uuid.UUID(doc_data["id"])).first()
        assert "HTTP_ERROR_500" in audit.metadata_json


def test_g_upload_ocr_forgery_tamper_alert_creation(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 Forged Document Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_tampered = {
        "suggested_sensitivity": "HIGH",
        "tamper_score": 0.88,
        "forgery_detected": True,
        "forensic_alert_level": "POTENTIAL ELA ANOMALY DETECTED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [{"pixel_anomaly_coefficient": 0.88}],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/tampered.pdf"):

        mock_scan.return_value = mock_ocr_tampered

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Tampered Document FIR",
                "document_type": "FIR",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("tampered.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        doc_id = uuid.UUID(doc_data["id"])

        # Check TamperAlert created in DB
        alert = db_session.query(TamperAlert).filter(TamperAlert.document_id == doc_id).first()
        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert "0.8800" in alert.description
        assert alert.detected_by == "AI-OCR Pipeline"


def test_h_upload_ocr_clean_no_tamper_alert(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 Clean Document Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_clean = {
        "suggested_sensitivity": "LOW",
        "tamper_score": 0.15,  # Below 0.75 threshold
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/clean.pdf"):

        mock_scan.return_value = mock_ocr_clean

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Clean Document",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("clean.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()

        # No TamperAlert created
        alert = db_session.query(TamperAlert).filter(TamperAlert.document_id == uuid.UUID(doc_data["id"])).first()
        assert alert is None


def test_i_gcs_upload_failure_rollback(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 GCS Failure Test"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_online = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", side_effect=StorageError("GCS unreachable")):

        mock_scan.return_value = mock_ocr_online

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "GCS Failure Doc",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("gcs_fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 503
        assert "Storage service is unavailable" in upload_resp.json()["detail"]


def test_j_db_commit_failure_triggers_gcs_rollback(client):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 DB Commit Fail Payload"
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_online = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    mock_storage_key = "documents/test_id/mock_key.pdf"

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value=mock_storage_key), \
         patch("app.services.storage.storage_service.delete_file") as mock_delete, \
         patch("sqlalchemy.orm.Session.commit", side_effect=Exception("DB Error")):

        mock_scan.return_value = mock_ocr_online

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "DB Fail Doc",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("db_fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 500
        # Verify orphaned storage file deletion was invoked
        mock_delete.assert_called_once_with(mock_storage_key)


def test_k_sha256_matches_original_uploaded_bytes(client, db_session):
    headers, _ = get_auth_headers(client)
    pdf_bytes = b"%PDF-1.4 SHA256 Verification Payload 12345"
    expected_hash = calculate_sha256(pdf_bytes)
    pdf_file = io.BytesIO(pdf_bytes)

    mock_ocr_online = {
        "suggested_sensitivity": "MEDIUM",
        "tamper_score": 0.0,
        "forgery_detected": False,
        "forensic_alert_level": "INTEGRITY CHECK PASSED",
        "matched_high_risk_terms": [],
        "matched_medium_risk_terms": [],
        "ocr_records": [],
        "worm_log": [],
        "is_online": True,
    }

    with patch("app.services.ocr_client.ocr_client.scan_document", new_callable=AsyncMock) as mock_scan, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/mock/sha.pdf"):

        mock_scan.return_value = mock_ocr_online

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "SHA-256 Test Doc",
                "document_type": "Evidence",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("sha_test.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        doc_id = uuid.UUID(doc_data["id"])

        ver = db_session.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        assert ver is not None
        assert ver.doc_hash == expected_hash
