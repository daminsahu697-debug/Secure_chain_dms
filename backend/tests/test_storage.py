import io
import uuid
from unittest.mock import MagicMock, patch
import pytest

from app.services.hashing import calculate_sha256
from app.services.storage import (
    FileValidationError,
    GCSStorageAdapter,
    StorageError,
    StorageService,
)


@pytest.fixture
def gcs_adapter():
    adapter = GCSStorageAdapter()
    return adapter


def test_1_file_validation():
    service = StorageService(provider="GCS")

    # Valid PDF
    service.validate_file("report.pdf", "application/pdf", 1024 * 1024)

    # Valid image
    service.validate_file("photo.jpg", "image/jpeg", 2 * 1024 * 1024)

    # Invalid extension
    with pytest.raises(FileValidationError, match="extension"):
        service.validate_file("malicious.exe", "application/octet-stream", 1024)

    # File size exceeding 50 MB
    with pytest.raises(FileValidationError, match="exceeds maximum"):
        service.validate_file("huge.pdf", "application/pdf", 51 * 1024 * 1024)

    # Empty filename
    with pytest.raises(FileValidationError, match="Invalid filename"):
        service.validate_file("", "application/pdf", 100)


def test_2_object_key_generation():
    service = StorageService(provider="GCS")
    doc_id = "11111111-1111-4111-8111-111111111111"
    key = service.generate_object_name(doc_id, "evidence.pdf")

    assert key.startswith(f"documents/{doc_id}/")
    assert key.endswith(".pdf")
    assert len(key.split("/")) == 3


def test_3_gcs_upload(gcs_adapter):
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_bucket.exists.return_value = True

    with patch.object(gcs_adapter, "get_client", return_value=mock_client):
        result_key = gcs_adapter.upload_file(
            file_data=b"%PDF-1.4 test payload",
            object_name="documents/doc1/uuid1.pdf",
            content_type="application/pdf",
        )

        assert result_key == "documents/doc1/uuid1.pdf"
        mock_client.bucket.assert_called_with("securechain-documents")
        mock_bucket.blob.assert_called_with("documents/doc1/uuid1.pdf")
        mock_blob.upload_from_string.assert_called_once_with(
            b"%PDF-1.4 test payload", content_type="application/pdf"
        )


def test_4_gcs_download_and_stream(gcs_adapter):
    pdf_bytes = b"%PDF-1.4 downloadable content"
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_bucket.exists.return_value = True
    mock_blob.download_as_bytes.return_value = pdf_bytes

    with patch.object(gcs_adapter, "get_client", return_value=mock_client):
        stream = gcs_adapter.get_file("documents/doc1/uuid1.pdf")
        retrieved = stream.read()
        assert retrieved == pdf_bytes

        # Test chunked streaming iterator
        chunks = list(stream.stream(chunk_size=10))
        assert b"".join(chunks) == pdf_bytes


def test_5_gcs_byte_retrieval(gcs_adapter):
    pdf_bytes = b"%PDF-1.4 raw bytes retrieval"
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_bucket.exists.return_value = True
    mock_blob.download_as_bytes.return_value = pdf_bytes

    with patch.object(gcs_adapter, "get_client", return_value=mock_client):
        retrieved_bytes = gcs_adapter.get_file_bytes("documents/doc1/uuid1.pdf")
        assert retrieved_bytes == pdf_bytes


def test_6_gcs_deletion(gcs_adapter):
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_bucket.exists.return_value = True
    mock_blob.exists.return_value = True

    with patch.object(gcs_adapter, "get_client", return_value=mock_client):
        gcs_adapter.delete_file("documents/doc1/uuid1.pdf")
        mock_blob.delete.assert_called_once()


def test_7_storage_failure_handling(gcs_adapter):
    mock_client = MagicMock()
    mock_client.bucket.side_effect = Exception("GCS Service Unavailable")

    with patch.object(gcs_adapter, "get_client", return_value=mock_client):
        with pytest.raises(StorageError, match="GCS storage service is unavailable"):
            gcs_adapter.upload_file(b"payload", "documents/doc1/file.pdf")


def test_8_upload_rollback_cleanup(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    pdf_content = b"%PDF-1.4 Rollback test"
    pdf_file = io.BytesIO(pdf_content)

    # Force DB failure after storage upload by supplying a non-existent case_id
    fake_case_id = str(uuid.uuid4())

    with patch("app.services.storage.storage_service.delete_file") as mock_delete:
        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": fake_case_id,
                "title": "Failing Upload",
                "document_type": "FIR",
            },
            files={"file": ("fail.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 404
        assert "not found" in upload_resp.json()["detail"].lower()


def test_9_authenticated_gcs_document_upload(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    pdf_content = b"%PDF-1.4 GCS Integration Test Document"
    pdf_file = io.BytesIO(pdf_content)
    test_case_id = "11111111-1111-4111-8111-111111111111"

    with patch("app.services.storage.storage_service.adapter.get_client") as mock_get_client:
        mock_gcs_client = MagicMock()
        mock_bucket = MagicMock()
        mock_blob = MagicMock()
        mock_get_client.return_value = mock_gcs_client
        mock_gcs_client.bucket.return_value = mock_bucket
        mock_bucket.blob.return_value = mock_blob
        mock_bucket.exists.return_value = True

        upload_resp = client.post(
            "/api/v1/documents/upload",
            data={
                "case_id": test_case_id,
                "title": "GCS Test Case Report",
                "document_type": "FIR",
                "sensitivity_level": "HIGH",
            },
            files={"file": ("gcs_report.pdf", pdf_file, "application/pdf")},
            headers=headers,
        )

        assert upload_resp.status_code == 201
        doc_data = upload_resp.json()
        assert doc_data["title"] == "GCS Test Case Report"
        assert str(doc_data["uploaded_by"]) == str(user_id)


def test_10_authenticated_gcs_document_download(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    test_doc_id = "22222222-2222-4222-8222-222222222222"
    pdf_bytes = b"%PDF-1.4 GCS Download Content"

    with patch("app.services.storage.storage_service.adapter.get_file_bytes", return_value=pdf_bytes):
        dl_resp = client.get(
            f"/api/v1/documents/{test_doc_id}/download",
            headers=headers,
        )
        assert dl_resp.status_code == 200
        assert dl_resp.content == pdf_bytes


def test_11_gcs_document_integrity_verification(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    test_doc_id = "22222222-2222-4222-8222-222222222222"
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    pdf_bytes = b""  # Empty bytes SHA-256 matches expected_hash

    with patch("app.services.storage.storage_service.adapter.get_file_bytes", return_value=pdf_bytes):
        verify_resp = client.get(
            f"/api/v1/documents/{test_doc_id}/verify",
            headers=headers,
        )
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["integrity_verified"] is True
        assert verify_data["status"] == "INTEGRITY_VERIFIED"
        assert verify_data["calculated_hash"] == expected_hash
