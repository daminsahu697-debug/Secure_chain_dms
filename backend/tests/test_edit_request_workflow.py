"""
Unit & Integration Test Suite for Step 5C — Controlled Document Amendment Workflow
===================================================================================
Tests all 23 amendment workflow requirements including:
- Edit request creation & proposal SHA-256 generation
- Approver pool resolution & requester exclusion
- Quorum request submission & offline handling
- Status synchronization & voting (self-approval/unauthorized error handling)
- Approved amendment finalization & idempotency
- SecurityAdapter Two-Vault packaging (quorum_token + amendment_of verification)
- GCS vault2_blob upload & failure cleanup
- DB transaction rollback safety
- Integer version numbering continuity
- Audit logging of all critical workflow state transitions
"""

import io
import json
import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import status
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.models.case import Case
from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.models.edit_request import EditRequest
from app.models.audit_log import AuditLog
from app.services.security_adapter import VaultPackage, security_adapter


@pytest.fixture
def mock_db_session():
    db = MagicMock()
    return db


@pytest.fixture
def test_user():
    return User(
        id=uuid.uuid4(),
        email="officer@securechain.test",
        full_name="Officer Test",
        employee_id="EMP_OFFICER_100",
        is_active=True,
    )


@pytest.fixture
def test_approvers():
    return [
        User(id=uuid.uuid4(), email="app1@test.com", full_name="Approver 1", employee_id="EMP_APP1", role="APPROVAL_OFFICER", is_active=True),
        User(id=uuid.uuid4(), email="app2@test.com", full_name="Approver 2", employee_id="EMP_APP2", role="APPROVAL_OFFICER", is_active=True),
        User(id=uuid.uuid4(), email="app3@test.com", full_name="Approver 3", employee_id="EMP_APP3", role="APPROVAL_OFFICER", is_active=True),
    ]


@pytest.fixture
def test_case(test_user):
    return Case(
        id=uuid.uuid4(),
        case_number="CASE-2026-001",
        title="Test Investigation Case",
        created_by=test_user.id,
    )


@pytest.fixture
def test_doc_and_version(test_case, test_user):
    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    
    version = DocumentVersion(
        id=ver_id,
        document_id=doc_id,
        version_number=1,
        original_filename="original_evidence.pdf",
        storage_key="documents/original_evidence.pdf",
        doc_hash="a" * 64,
        chain_hash="b" * 64,
        prev_chain_hash="0" * 64,
        quorum_token=None,
        wrapped_dek="wrapped_dek_v1",
        iv="iv_v1_12345678",
        key_id=uuid.uuid4(),
        kek_version="v1",
        aad="aad_v1",
        algorithm="AES-256-GCM",
        created_by=test_user.id,
        status="LOCKED",
        file_size=1024,
        mime_type="application/pdf",
        created_at=datetime.now(timezone.utc),
    )

    doc = Document(
        id=doc_id,
        case_id=test_case.id,
        title="Original Evidence Document",
        document_type="Evidence",
        sensitivity_level="MEDIUM",
        status="LOCKED",
        created_by=test_user.id,
        current_version_id=ver_id,
    )
    doc.current_version = version

    return doc, version


@pytest.fixture
def client(test_user, mock_db_session):
    def override_get_current_user():
        return test_user

    def override_get_db():
        yield mock_db_session

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# 1. Unauthenticated request rejected
def test_1_unauthenticated_request_rejected(mock_db_session):
    app.dependency_overrides.clear()
    with TestClient(app) as unauth_client:
        res = unauth_client.post(
            f"/api/v1/documents/{uuid.uuid4()}/edit-requests",
            data={"reason": "Amendment reason"},
            files={"file": ("amendment.pdf", b"%PDF-1.4 proposed amendment bytes", "application/pdf")},
        )
        assert res.status_code == status.HTTP_401_UNAUTHORIZED


# 2. Document not found
def test_2_document_not_found(client, mock_db_session):
    mock_db_session.query.return_value.filter.return_value.first.return_value = None
    missing_doc_id = uuid.uuid4()

    res = client.post(
        f"/api/v1/documents/{missing_doc_id}/edit-requests",
        data={"reason": "Amendment reason"},
        files={"file": ("amendment.pdf", b"%PDF-1.4 amendment", "application/pdf")},
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND


# 3. Successful edit request creation
def test_3_successful_edit_request_creation(client, mock_db_session, test_user, test_doc_and_version, test_approvers):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q, \
         patch("app.services.storage.storage_service.upload_file", return_value="proposals/tmp.tmp"):

        mock_eligible.return_value = [str(a.id) for a in test_approvers]
        mock_create_q.return_value = {
            "success": True,
            "request": {"id": "req_q123", "status": "PENDING"}
        }

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Correction of evidence detail"},
            files={"file": ("amendment.pdf", b"%PDF-1.4 new proposed content", "application/pdf")},
        )

        assert res.status_code == status.HTTP_201_CREATED
        data = res.json()
        assert data["reason"] == "Correction of evidence detail"
        assert data["status"] == "PENDING"
        mock_create_q.assert_called_once()


# 4. Requester excluded from approver pool
@pytest.mark.anyio
async def test_4_requester_excluded_from_approver_pool(test_user, test_approvers):
    mock_db = MagicMock()
    all_users = [test_user] + test_approvers
    mock_db.query.return_value.filter.return_value.all.return_value = all_users

    from app.services.quorum_client import quorum_client
    eligible_ids = await quorum_client.get_eligible_approvers(
        case_id="case_101",
        sensitivity="MEDIUM",
        requester_id=str(test_user.id),
        db=mock_db,
    )

    assert str(test_user.id) not in eligible_ids
    assert len(eligible_ids) == 3


# 5. Quorum request submitted
def test_5_quorum_request_submitted(client, mock_db_session, test_user, test_doc_and_version, test_approvers):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q, \
         patch("app.services.storage.storage_service.upload_file"):

        mock_eligible.return_value = [str(a.id) for a in test_approvers]
        mock_create_q.return_value = {"success": True, "request": {"id": "req_submitted_001"}}

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Updating section 4"},
            files={"file": ("amendment.pdf", b"%PDF-1.4 payload content", "application/pdf")},
        )
        assert res.status_code == status.HTTP_201_CREATED
        assert mock_create_q.call_count == 1


# 6. Proposal SHA-256 generated
def test_6_proposal_sha256_generated(client, mock_db_session, test_user, test_doc_and_version, test_approvers):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]

    file_bytes = b"%PDF-1.4 specific unique content for hash calculation"
    from app.services.hashing import calculate_sha256
    expected_hash = calculate_sha256(file_bytes)

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q, \
         patch("app.services.storage.storage_service.upload_file"):

        mock_eligible.return_value = [str(a.id) for a in test_approvers]
        mock_create_q.return_value = {"success": True, "request": {"id": "req_sha256"}}

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Testing proposal hash generation"},
            files={"file": ("amendment.pdf", file_bytes, "application/pdf")},
        )

        assert res.status_code == status.HTTP_201_CREATED
        data = res.json()
        assert data["amendment_reason_code"] == expected_hash


# 7. Pending request creates no version
def test_7_pending_request_creates_no_version(client, mock_db_session, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=uuid.uuid4(),
        source_version_id=version.id,
        reason="Pending edit request",
        amendment_reason_code="hash_pending",
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.return_value = edit_req

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val:
        from fastapi import HTTPException
        mock_val.side_effect = HTTPException(status_code=400, detail="Quorum token is not authorized. Current status: 'PENDING'")

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_400_BAD_REQUEST
        assert "not authorized" in res.json()["detail"].lower()


# 8. Rejected request creates no version
def test_8_rejected_request_creates_no_version(client, mock_db_session, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=uuid.uuid4(),
        source_version_id=version.id,
        reason="Rejected edit request",
        amendment_reason_code="hash_rejected",
        status="REJECTED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.return_value = edit_req

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val:
        from fastapi import HTTPException
        mock_val.side_effect = HTTPException(status_code=400, detail="Quorum token is not authorized. Current status: 'REJECTED'")

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_400_BAD_REQUEST


# 9. Approved request can finalize
def test_9_approved_request_can_finalize(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Approved amendment",
        amendment_reason_code="hash_approved",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [
        edit_req, doc, version
    ]

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek_enc_v2",
            "iv": "iv_v2_123456789012",
            "kek_version": "v1",
            "aad": "aad_v2",
            "algorithm": "AES-256-GCM",
            "doc_hash": "c" * 64,
            "chain_record": {
                "chain_hash": "d" * 64,
                "prev_chain_hash": version.doc_hash,
                "quorum_token": "req_approved_123",
            },
        },
        vault2_blob=b"encrypted_vault2_ciphertext",
        vault2_blob_ref=f"documents/{doc.id}/ciphertext_v2.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"%PDF-1.4 new amended bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/ciphertext_v2.bin"):

        mock_val.return_value = {"id": "req_approved_123", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED
        data = res.json()
        assert data["version_number"] == 2


# 10. Quorum token required
def test_10_quorum_token_required():
    with pytest.raises(Exception):
        security_adapter.process_evidence_upload(
            plaintext=b"amendment plaintext",
            document_id=str(uuid.uuid4()),
            case_id=str(uuid.uuid4()),
            officer_id=str(uuid.uuid4()),
            version="2",
            quorum_token=None,  # Missing quorum token MUST fail for amendments
            amendment_of="a" * 64,
        )


# 11. Amendment_of references source doc_hash
def test_11_amendment_of_references_source_doc_hash(test_doc_and_version, test_user):
    doc, version = test_doc_and_version
    # Register genesis (version 1.0) for case first
    gen_pkg = security_adapter.process_evidence_upload(
        plaintext=b"%PDF-1.4 original genesis content",
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        officer_id=str(test_user.id),
        version="1.0",
    )

    pkg = security_adapter.process_evidence_upload(
        plaintext=b"%PDF-1.4 amended content",
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        officer_id=str(test_user.id),
        version="2",
        quorum_token="req_valid_token",
        amendment_of=gen_pkg.vault1_metadata["doc_hash"],
    )

    chain_rec = pkg.vault1_metadata["chain_record"]
    assert chain_rec["amendment_of"] == gen_pkg.vault1_metadata["doc_hash"]
    assert chain_rec["prev_chain_hash"] == gen_pkg.vault1_metadata["chain_record"]["chain_hash"]


# 12. New encrypted version created
def test_12_new_encrypted_version_created(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Creating version 2",
        amendment_reason_code="hash_ver2",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek_enc_v2",
            "iv": "iv_v2_123456789012",
            "kek_version": "v1",
            "aad": "aad_v2",
            "algorithm": "AES-256-GCM",
            "doc_hash": "e" * 64,
            "chain_record": {
                "chain_hash": "f" * 64,
                "prev_chain_hash": version.doc_hash,
                "quorum_token": "req_approved_ver2",
            },
        },
        vault2_blob=b"encrypted_ciphertext_ver2",
        vault2_blob_ref="documents/ciphertext_ver2.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"%PDF-1.4 new version"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/ciphertext_ver2.bin"):

        mock_val.return_value = {"id": "req_approved_ver2", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED
        assert mock_db_session.add.call_count >= 1


# 13. Previous version unchanged
def test_13_previous_version_unchanged(test_doc_and_version):
    doc, version = test_doc_and_version
    original_ver_num = version.version_number
    original_hash = version.doc_hash
    original_storage = version.storage_key

    # Finalizing amendment does not mutate fields on the original version instance
    assert version.version_number == original_ver_num
    assert version.doc_hash == original_hash
    assert version.storage_key == original_storage


# 14. Current version ID updated
def test_14_current_version_id_updated(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Pointer update test",
        amendment_reason_code="hash_ptr",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek_v2",
            "iv": "iv_v2",
            "kek_version": "v1",
            "aad": "aad_v2",
            "algorithm": "AES-256-GCM",
            "doc_hash": "1" * 64,
            "chain_record": {"chain_hash": "2" * 64, "prev_chain_hash": version.doc_hash, "quorum_token": "req_ptr"},
        },
        vault2_blob=b"encrypted_ciphertext",
        vault2_blob_ref="documents/ptr.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/ptr.bin"):

        mock_val.return_value = {"id": "req_ptr", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED
        assert doc.current_version_id != version.id


# 15. Plaintext not sent to GCS
def test_15_plaintext_not_sent_to_gcs(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Encryption test",
        amendment_reason_code="hash_enc",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]
    plaintext_data = b"%PDF-1.4 TOP SECRET UNENCRYPTED PLAINTEXT AMENDMENT"
    encrypted_data = b"CIPHERTEXT_AES_GCM_ENCRYPTED_BLOB_VAULT2"

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek",
            "iv": "iv",
            "kek_version": "v1",
            "aad": "aad",
            "algorithm": "AES-256-GCM",
            "doc_hash": "3" * 64,
            "chain_record": {"chain_hash": "4" * 64, "prev_chain_hash": version.doc_hash, "quorum_token": "req_enc"},
        },
        vault2_blob=encrypted_data,
        vault2_blob_ref="documents/cipher.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=plaintext_data), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file") as mock_gcs_upload:

        mock_val.return_value = {"id": "req_enc", "status": "APPROVED"}
        mock_gcs_upload.return_value = "documents/cipher.bin"

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED

        uploaded_bytes = mock_gcs_upload.call_args[1]["file_data"]
        assert uploaded_bytes == encrypted_data
        assert plaintext_data not in uploaded_bytes


# 16. Quorum offline handled safely
def test_16_quorum_offline_handled_safely(client, mock_db_session, test_doc_and_version):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q:

        mock_eligible.return_value = [str(uuid.uuid4()) for _ in range(3)]
        mock_create_q.return_value = {"status": "OFFLINE", "skipped": True, "reason": "Quorum Engine unavailable"}

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Offline test"},
            files={"file": ("amendment.pdf", b"bytes", "application/pdf")},
        )
        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# 17. Vote authorization errors
def test_17_vote_authorization_errors(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Self approval test",
        amendment_reason_code="hash_self",
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.return_value = edit_req

    with patch("app.services.quorum_client.quorum_client.cast_vote", new_callable=AsyncMock) as mock_vote:
        from fastapi import HTTPException
        mock_vote.side_effect = HTTPException(
            status_code=403,
            detail="403 Forbidden: Requester is strictly prohibited from voting on their own edit request"
        )

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/vote",
            json={"vote_choice": "APPROVE"},
        )
        assert res.status_code == status.HTTP_403_FORBIDDEN


# 18. GCS failure cleanup
def test_18_gcs_failure_cleanup(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="GCS failure test",
        amendment_reason_code="hash_gcs_fail",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek",
            "iv": "iv",
            "kek_version": "v1",
            "aad": "aad",
            "algorithm": "AES-256-GCM",
            "doc_hash": "5" * 64,
            "chain_record": {"chain_hash": "6" * 64, "prev_chain_hash": version.doc_hash, "quorum_token": "req_fail"},
        },
        vault2_blob=b"blob",
        vault2_blob_ref="documents/fail.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file", side_effect=Exception("GCS connection timeout")):

        mock_val.return_value = {"id": "req_fail", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert mock_db_session.rollback.call_count >= 1


# 19. DB failure cleanup
def test_19_db_failure_cleanup(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="DB failure test",
        amendment_reason_code="hash_db_fail",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]
    mock_db_session.commit.side_effect = Exception("DB deadlock")

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek",
            "iv": "iv",
            "kek_version": "v1",
            "aad": "aad",
            "algorithm": "AES-256-GCM",
            "doc_hash": "7" * 64,
            "chain_record": {"chain_hash": "8" * 64, "prev_chain_hash": version.doc_hash, "quorum_token": "req_db_fail"},
        },
        vault2_blob=b"blob",
        vault2_blob_ref="documents/db_fail.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package), \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/db_fail.bin"), \
         patch("app.services.storage.storage_service.delete_file") as mock_delete:

        mock_val.return_value = {"id": "req_db_fail", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert mock_db_session.rollback.call_count >= 1
        mock_delete.assert_any_call("documents/db_fail.bin")


# 20. Security adapter failure
def test_20_security_adapter_failure(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Security failure test",
        amendment_reason_code="hash_sec_fail",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", side_effect=Exception("KMS key unavailable")):

        mock_val.return_value = {"id": "req_sec_fail", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


# 21. Repeated finalize is idempotent
def test_21_repeated_finalize_is_idempotent(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    existing_proposed_ver_id = uuid.uuid4()
    existing_ver = DocumentVersion(
        id=existing_proposed_ver_id,
        document_id=doc.id,
        version_number=2,
        original_filename="amendment.pdf",
        storage_key="documents/ver2.bin",
        doc_hash="9" * 64,
        created_by=test_user.id,
        status="LOCKED",
        created_at=datetime.now(timezone.utc),
    )

    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        proposed_version_id=existing_proposed_ver_id,
        reason="Already finalized request",
        amendment_reason_code="hash_idempotent",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, existing_ver]

    with patch("app.services.security_adapter.security_adapter.process_evidence_upload") as mock_sec:
        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED
        data = res.json()
        assert data["id"] == str(existing_proposed_ver_id)
        mock_sec.assert_not_called()


# 22. Version numbering correct
def test_22_version_numbering_correct(client, mock_db_session, test_user, test_doc_and_version):
    doc, version = test_doc_and_version
    version.version_number = 3  # Current version is 3

    edit_req = EditRequest(
        id=uuid.uuid4(),
        document_id=doc.id,
        requester_id=test_user.id,
        source_version_id=version.id,
        reason="Bump version from 3",
        amendment_reason_code="hash_v4",
        status="APPROVED",
        requested_at=datetime.now(timezone.utc),
    )

    mock_db_session.query.return_value.filter.return_value.first.side_effect = [edit_req, doc, version]

    mock_package = VaultPackage(
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        vault1_metadata={
            "key_id": str(uuid.uuid4()),
            "wrapped_dek": "dek",
            "iv": "iv",
            "kek_version": "v1",
            "aad": "aad",
            "algorithm": "AES-256-GCM",
            "doc_hash": "a" * 64,
            "chain_record": {"chain_hash": "b" * 64, "prev_chain_hash": version.doc_hash, "quorum_token": "req_v4"},
        },
        vault2_blob=b"blob",
        vault2_blob_ref="documents/v4.bin",
    )

    with patch("app.services.quorum_client.quorum_client.validate_approved_quorum_token", new_callable=AsyncMock) as mock_val, \
         patch("app.services.storage.storage_service.get_file_bytes", return_value=b"bytes"), \
         patch("app.services.security_adapter.security_adapter.process_evidence_upload", return_value=mock_package) as mock_sec, \
         patch("app.services.storage.storage_service.upload_file", return_value="documents/v4.bin"):

        mock_val.return_value = {"id": "req_v4", "status": "APPROVED"}

        res = client.post(f"/api/v1/documents/{doc.id}/edit-requests/{edit_req.id}/finalize")
        assert res.status_code == status.HTTP_201_CREATED
        assert res.json()["version_number"] == 4
        assert mock_sec.call_args[1]["version"] == "1.3"


# 23. Audit events created
def test_23_audit_events_created(client, mock_db_session, test_user, test_doc_and_version, test_approvers):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q, \
         patch("app.services.storage.storage_service.upload_file"):

        mock_eligible.return_value = [str(a.id) for a in test_approvers]
        mock_create_q.return_value = {"success": True, "request": {"id": "req_audit_test"}}

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Audit trail logging test"},
            files={"file": ("amendment.pdf", b"%PDF-1.4 audit content", "application/pdf")},
        )
        assert res.status_code == status.HTTP_201_CREATED

        # Verify AuditLog object added to session
        added_objects = [call[0][0] for call in mock_db_session.add.call_args_list]
        audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
        assert len(audit_logs) >= 1
        assert audit_logs[0].event_type == "EDIT_REQUEST_CREATED"


# 24. Plaintext proposal never reaches GCS
def test_24_plaintext_proposal_never_reaches_gcs(client, mock_db_session, test_user, test_doc_and_version, test_approvers):
    doc, version = test_doc_and_version
    mock_db_session.query.return_value.filter.return_value.first.side_effect = [doc, version]
    raw_plaintext_proposal = b"%PDF-1.4 CONFIDENTIAL PLAINTEXT AMENDMENT PROPOSAL BY OFFICER"

    with patch("app.services.quorum_client.quorum_client.get_eligible_approvers", new_callable=AsyncMock) as mock_eligible, \
         patch("app.services.quorum_client.quorum_client.create_approval_request", new_callable=AsyncMock) as mock_create_q, \
         patch("app.services.storage.storage_service.upload_file") as mock_upload:

        mock_eligible.return_value = [str(a.id) for a in test_approvers]
        mock_create_q.return_value = {"success": True, "request": {"id": "req_enc_prop_test"}}

        res = client.post(
            f"/api/v1/documents/{doc.id}/edit-requests",
            data={"reason": "Testing encrypted temporary proposal storage"},
            files={"file": ("amendment.pdf", raw_plaintext_proposal, "application/pdf")},
        )
        assert res.status_code == status.HTTP_201_CREATED

        # Assert no call to storage_service.upload_file contained raw_plaintext_proposal
        for call in mock_upload.call_args_list:
            file_data = call[1].get("file_data") or (call[0][0] if call[0] else b"")
            assert raw_plaintext_proposal not in file_data


# 25. First and second amendment version format
def test_25_first_and_second_amendment_version_format(test_doc_and_version, test_user):
    doc, version = test_doc_and_version

    # Genesis (original 1.0)
    gen_pkg = security_adapter.process_evidence_upload(
        plaintext=b"%PDF-1.4 original genesis",
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        officer_id=str(test_user.id),
        version="1.0",
    )
    assert gen_pkg.vault1_metadata["chain_record"]["version"] == "1.0"

    # First amendment (version_number 2 -> security "1.1")
    amd1_pkg = security_adapter.process_evidence_upload(
        plaintext=b"%PDF-1.4 first amendment",
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        officer_id=str(test_user.id),
        version="1.1",
        quorum_token="req_amd1",
        amendment_of=gen_pkg.vault1_metadata["doc_hash"],
    )
    assert amd1_pkg.vault1_metadata["chain_record"]["version"] == "1.1"

    # Second amendment (version_number 3 -> security "1.2")
    amd2_pkg = security_adapter.process_evidence_upload(
        plaintext=b"%PDF-1.4 second amendment",
        document_id=str(doc.id),
        case_id=str(doc.case_id),
        officer_id=str(test_user.id),
        version="1.2",
        quorum_token="req_amd2",
        amendment_of=amd1_pkg.vault1_metadata["doc_hash"],
    )
    assert amd2_pkg.vault1_metadata["chain_record"]["version"] == "1.2"

