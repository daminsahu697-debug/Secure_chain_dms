import io
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

from app.models.document import Document
from app.models.document_version import DocumentVersion

TEST_CASE_ID = "11111111-1111-4111-8111-111111111111"
TEST_DOC_ID = "22222222-2222-4222-8222-222222222222"


def get_auth_headers(client, employee_id="POL-IO-001", password="demo-password"):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": employee_id, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# 1. Unauthenticated document list -> 401
def test_unauthenticated_document_list_returns_401(client):
    resp = client.get("/api/v1/documents")
    assert resp.status_code in (401, 403)


# 2. Authenticated document list -> 200
def test_authenticated_document_list_returns_200(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents", headers=headers)
    assert resp.status_code == 200


# 3. Document list response shape
def test_document_list_response_shape(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "skip" in data
    assert "limit" in data
    assert isinstance(data["items"], list)
    assert isinstance(data["total"], int)
    assert data["skip"] == 0
    assert data["limit"] == 50


# 4. case_id filtering
def test_document_list_case_id_filtering(client):
    headers = get_auth_headers(client)

    # Invalid case_id format -> 400
    bad_resp = client.get("/api/v1/documents?case_id=invalid-uuid", headers=headers)
    assert bad_resp.status_code == 400

    # Valid case_id filter
    resp = client.get(f"/api/v1/documents?case_id={TEST_CASE_ID}", headers=headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["case_id"] == TEST_CASE_ID


# 5. document_type filtering
def test_document_list_type_filtering(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents?document_type=FIR", headers=headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["document_type"] == "FIR"


# 6. sensitivity_level filtering
def test_document_list_sensitivity_filtering(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents?sensitivity_level=MEDIUM", headers=headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["sensitivity_level"] == "MEDIUM"


# 7. status filtering
def test_document_list_status_filtering(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents?status=LOCKED", headers=headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["status"] == "LOCKED"


# 8. Pagination skip/limit
def test_document_list_pagination(client):
    headers = get_auth_headers(client)

    # Invalid skip/limit validation -> 400
    bad_skip = client.get("/api/v1/documents?skip=-1", headers=headers)
    assert bad_skip.status_code == 400

    bad_limit = client.get("/api/v1/documents?limit=0", headers=headers)
    assert bad_limit.status_code == 400

    bad_limit_large = client.get("/api/v1/documents?limit=150", headers=headers)
    assert bad_limit_large.status_code == 400

    # Valid pagination
    resp = client.get("/api/v1/documents?skip=0&limit=2", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["skip"] == 0
    assert data["limit"] == 2
    assert len(data["items"]) <= 2


# 9. Documents ordered newest first
def test_documents_ordered_newest_first(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    if len(items) >= 2:
        dt1 = datetime.fromisoformat(items[0]["created_at"].replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(items[1]["created_at"].replace("Z", "+00:00"))
        assert dt1 >= dt2


# 10. No document-list secrets exposed
def test_no_document_list_secrets_exposed(client):
    headers = get_auth_headers(client)
    resp = client.get("/api/v1/documents", headers=headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert "wrapped_dek" not in item
        assert "iv" not in item
        assert "aad" not in item
        assert "key_id" not in item
        assert "kek_version" not in item
        assert "storage_key" not in item
        assert "storage_path" not in item


# 11. Unauthenticated version history -> 401
def test_unauthenticated_version_history_returns_401(client):
    resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}/versions")
    assert resp.status_code in (401, 403)


# 12. Authenticated version history -> 200
def test_authenticated_version_history_returns_200(client):
    headers = get_auth_headers(client)
    resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}/versions", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# 13. Non-existent document -> 404
def test_version_history_nonexistent_doc_returns_404(client):
    headers = get_auth_headers(client)
    random_id = str(uuid.uuid4())
    resp = client.get(f"/api/v1/documents/{random_id}/versions", headers=headers)
    assert resp.status_code == 404


# 14. Versions ordered ascending by version_number
# 15. Version number mapping (1 -> 1.0, 2 -> 1.1, 3 -> 1.2)
# 16. Version response does NOT expose sensitive fields
# 17. Version chain fields returned unchanged
def test_version_history_ordering_mapping_secrets_and_chain(client):
    headers = get_auth_headers(client)

    # Upload document to create initial version (v1 -> 1.0)
    pdf_content = b"%PDF-1.4 Multi-version test document bytes"
    pdf_file = io.BytesIO(pdf_content)

    with patch("app.services.storage.storage_service.get_client") as mock_get_client:
        mock_minio = MagicMock()
        mock_get_client.return_value = mock_minio
        mock_minio.bucket_exists.return_value = True

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": TEST_CASE_ID,
                "title": "Version History Audit Test Document",
                "document_type": "FIR",
                "sensitivity_level": "MEDIUM",
            },
            files={"file": ("history_test.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )
        assert upload_resp.status_code == 201
        doc_id = upload_resp.json()["id"]

    # Fetch version history
    resp = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers)
    assert resp.status_code == 200
    versions = resp.json()
    assert len(versions) >= 1

    # Verify ascending ordering & mapping
    for i in range(len(versions)):
        v = versions[i]
        assert v["version_number"] == i + 1
        expected_ver_str = "1.0" if v["version_number"] == 1 else f"1.{v['version_number'] - 1}"
        assert v["version"] == expected_ver_str

        # Verify chain linkage fields exist
        assert "doc_hash" in v
        assert "chain_hash" in v
        assert "prev_chain_hash" in v

        # Verify NO secrets exposed
        assert "wrapped_dek" not in v
        assert "iv" not in v
        assert "aad" not in v
        assert "key_id" not in v
        assert "kek_version" not in v
        assert "algorithm" not in v
        assert "storage_key" not in v
        assert "storage_path" not in v


# 18. Empty version history behavior for a valid document without versions
def test_version_history_empty_behavior(client, db_session):
    headers = get_auth_headers(client)

    # Create a document without any versions in DB
    new_doc_id = uuid.uuid4()
    doc_no_ver = Document(
        id=new_doc_id,
        case_id=uuid.UUID(TEST_CASE_ID),
        title="Document Without Versions",
        document_type="EVIDENCE",
        sensitivity_level="LOW",
        status="LOCKED",
        created_by=uuid.UUID("a85fb498-d932-4d3e-9086-723421f52bdb"),
        current_version_id=None,
    )
    db_session.add(doc_no_ver)
    db_session.commit()

    resp = client.get(f"/api/v1/documents/{new_doc_id}/versions", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []
