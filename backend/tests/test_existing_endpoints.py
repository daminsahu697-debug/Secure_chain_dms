import io
import uuid
from unittest.mock import MagicMock, patch
from app.services.hashing import calculate_sha256

TEST_CASE_ID = "11111111-1111-4111-8111-111111111111"
TEST_DOC_ID = "22222222-2222-4222-8222-222222222222"


def test_unauthenticated_document_endpoints_reject(client):
    pdf_content = b"%PDF-1.4 Unauthenticated upload test"
    pdf_file = io.BytesIO(pdf_content)

    # 1. Unauthenticated upload -> 401/403
    upload_resp = client.post(
        "/api/v1/documents/upload",
        data={
            "case_id": TEST_CASE_ID,
            "title": "Unauth Report",
            "document_type": "FIR",
            "sensitivity_level": "HIGH",
        },
        files={"file": ("unauth.pdf", pdf_file, "application/pdf")},
    )
    assert upload_resp.status_code in (401, 403)

    # 2. Unauthenticated metadata access -> 401/403
    get_resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}")
    assert get_resp.status_code in (401, 403)

    # 3. Unauthenticated download -> 401/403
    dl_resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}/download")
    assert dl_resp.status_code in (401, 403)

    # 4. Unauthenticated verify -> 401/403
    verify_resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}/verify")
    assert verify_resp.status_code in (401, 403)


def test_authenticated_document_workflow(client):
    # 1. Login to get token for POL-IO-001
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Authenticated Upload Document
    pdf_content = b"%PDF-1.4 Mock document bytes for integration test"
    pdf_file = io.BytesIO(pdf_content)

    with patch("app.services.storage.storage_service.get_client") as mock_get_client:
        mock_minio = MagicMock()
        mock_get_client.return_value = mock_minio
        mock_minio.bucket_exists.return_value = True

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "FIR Investigation Report",
                "document_type": "FIR",
                "sensitivity_level": "HIGH",
            },
            files={"file": ("report.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        doc_id = doc_data["id"]

        # Ensure uploaded_by matches authenticated user's ID
        assert str(doc_data["uploaded_by"]) == str(user_id)

    # 3. Authenticated Get Document Metadata
    get_resp = client.get(
        f"/api/v1/documents/{doc_id}",
        headers=headers,
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == "FIR Investigation Report"
    assert str(get_resp.json()["uploaded_by"]) == str(user_id)

    # 4. SHA-256 Digest Calculation & Authenticated Verification
    expected_hash = calculate_sha256(pdf_content)

    with patch("app.services.storage.storage_service.get_file") as mock_get_file:
        mock_response = MagicMock()
        mock_response.read.return_value = pdf_content
        mock_get_file.return_value = mock_response

        verify_resp = client.get(
            f"/api/v1/documents/{doc_id}/verify",
            headers=headers,
        )
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["integrity_verified"] is True
        assert verify_data["status"] == "INTEGRITY_VERIFIED"
        assert verify_data["calculated_hash"] == expected_hash

    # 5. Authenticated Download Document
    with patch("app.services.storage.storage_service.get_file") as mock_get_file:
        mock_response = MagicMock()
        mock_response.stream.return_value = [pdf_content]
        mock_get_file.return_value = mock_response

        dl_resp = client.get(
            f"/api/v1/documents/{doc_id}/download",
            headers=headers,
        )
        assert dl_resp.status_code == 200
        assert dl_resp.content == pdf_content


def test_anti_impersonation_on_upload(client):
    """
    Verifies that a user logged in as POL-IO-001 cannot impersonate another user
    even if the client sends an 'uploaded_by' form field. The system must strictly record current_user.id.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    pdf_content = b"%PDF-1.4 Anti-impersonation test"
    pdf_file = io.BytesIO(pdf_content)
    fake_user_id = str(uuid.uuid4())

    with patch("app.services.storage.storage_service.get_client") as mock_get_client:
        mock_minio = MagicMock()
        mock_get_client.return_value = mock_minio
        mock_minio.bucket_exists.return_value = True

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "FIR Anti-Impersonation Test",
                "document_type": "FIR",
                "uploaded_by": fake_user_id,  # Attempted impersonation
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("anti_imp.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()

        # Must record actual authenticated user ID, ignoring the fake uploaded_by
        assert str(doc_data["uploaded_by"]) == str(user_id)
        assert str(doc_data["uploaded_by"]) != fake_user_id
