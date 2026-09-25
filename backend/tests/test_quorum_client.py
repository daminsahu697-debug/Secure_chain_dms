"""
Unit & Integration Test Suite for FastAPI QuorumClient
======================================================
Tests all 13 quorum service client requirements using mocked httpx responses and DB session mocks.
Asserts exact endpoint paths (/api/approval/requests, /api/approval/audit-logs) and payload schemas.
No external live Node.js or PostgreSQL services required.
"""

import uuid
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from app.services.quorum_client import QuorumClient, quorum_client
from app.models.user import User


@pytest.fixture
def quorum_client_instance():
    return QuorumClient(base_url="http://localhost:3000", timeout=5.0)


# 1. Successful Create Request
@pytest.mark.anyio
async def test_1_successful_create_request(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "success": True,
        "request": {
            "id": "req_12345",
            "status": "PENDING",
            "threshold_m": 2,
            "pool_size_n": 3,
        },
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        res = await quorum_client_instance.create_approval_request(
            document_id="doc_101",
            requester_id="user_officer",
            sensitivity="MEDIUM",
            proposed_content="Proposed content",
            pool_member_ids=["user_app1", "user_app2", "user_app3"],
        )

        assert res["success"] is True
        assert res["request"]["id"] == "req_12345"
        mock_post.assert_called_once_with(
            "http://localhost:3000/api/approval/requests",
            json={
                "documentId": "doc_101",
                "requesterId": "user_officer",
                "proposedContent": "Proposed content",
                "sensitivityTier": "MEDIUM",
                "poolMemberIds": ["user_app1", "user_app2", "user_app3"],
            },
        )


# 2. Successful Vote
@pytest.mark.anyio
async def test_2_successful_vote(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "message": "Vote 'APPROVE' recorded successfully",
        "data": {
            "request": {"id": "req_12345", "status": "APPROVED"},
            "new_version": {"version_number": "1.1"},
        },
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        res = await quorum_client_instance.cast_vote(
            request_id="req_12345",
            voter_id="user_app1",
            vote_choice="APPROVE",
        )

        assert res["success"] is True
        assert res["data"]["request"]["status"] == "APPROVED"
        mock_post.assert_called_once_with(
            "http://localhost:3000/api/approval/requests/req_12345/vote",
            json={
                "voterId": "user_app1",
                "voteChoice": "APPROVE",
            },
        )


# 3. Successful Request Lookup
@pytest.mark.anyio
async def test_3_successful_request_lookup(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "request": {
            "id": "req_12345",
            "document_id": "doc_101",
            "status": "PENDING",
            "sensitivity_tier": "HIGH",
        },
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        res = await quorum_client_instance.get_request_details("req_12345")

        assert res["success"] is True
        assert res["request"]["id"] == "req_12345"
        mock_get.assert_called_once_with("http://localhost:3000/api/approval/requests/req_12345")


# 4. Successful Audit Lookup
@pytest.mark.anyio
async def test_4_successful_audit_lookup(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "logs": [
            {"event_type": "EDIT_REQUEST_CREATED", "request_id": "req_12345"},
            {"event_type": "VOTE_CAST", "request_id": "req_12345"},
        ],
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        res = await quorum_client_instance.get_audit_logs("req_12345")

        assert res["success"] is True
        assert len(res["logs"]) == 2
        mock_get.assert_called_once_with(
            "http://localhost:3000/api/approval/audit-logs",
            params={"requestId": "req_12345"},
        )


# 5. Connection Failure
@pytest.mark.anyio
async def test_5_connection_failure(quorum_client_instance):
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        res = await quorum_client_instance.create_approval_request(
            document_id="doc_101",
            requester_id="user_officer",
            sensitivity="MEDIUM",
            proposed_content="Content",
            pool_member_ids=["user_app1"],
        )

        assert res["status"] == "OFFLINE"
        assert res["skipped"] is True
        assert "unavailable" in res["reason"].lower()


# 6. Timeout
@pytest.mark.anyio
async def test_6_timeout(quorum_client_instance):
    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Request timed out")):
        res = await quorum_client_instance.get_request_details("req_12345")

        assert res["status"] == "OFFLINE"
        assert res["skipped"] is True


# 7. HTTP 400 Bad Request
@pytest.mark.anyio
async def test_7_http_400(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {
        "error": True,
        "code": "POOL_SIZE_MISMATCH",
        "message": "Sensitivity tier requires 3 pool members",
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.create_approval_request(
                document_id="doc_101",
                requester_id="user_officer",
                sensitivity="MEDIUM",
                proposed_content="Content",
                pool_member_ids=["user_app1"],
            )

        assert exc_info.value.status_code == 400
        assert "Sensitivity tier requires 3 pool members" in exc_info.value.detail


# 8. Self-Approval 403
@pytest.mark.anyio
async def test_8_self_approval_403(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {
        "error": True,
        "code": "SELF_APPROVAL_FORBIDDEN",
        "message": "Requester is strictly prohibited from voting on their own edit request",
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.cast_vote("req_12345", "user_officer", "APPROVE")

        assert exc_info.value.status_code == 403
        assert "prohibited" in exc_info.value.detail.lower()


# 9. Unauthorized Approver 403
@pytest.mark.anyio
async def test_9_unauthorized_approver_403(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {
        "error": True,
        "code": "UNAUTHORIZED_APPROVER",
        "message": "User is not an authorized approver for request",
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.cast_vote("req_12345", "user_intruder", "APPROVE")

        assert exc_info.value.status_code == 403


# 10. Duplicate Vote 409
@pytest.mark.anyio
async def test_10_duplicate_vote_409(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 409
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {
        "error": True,
        "code": "DUPLICATE_VOTE",
        "message": "User has already cast a vote on request",
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.cast_vote("req_12345", "user_app1", "APPROVE")

        assert exc_info.value.status_code == 409
        assert "already cast" in exc_info.value.detail.lower()


# 11. Request Not Found 404
@pytest.mark.anyio
async def test_11_request_not_found_404(quorum_client_instance):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {
        "error": True,
        "code": "REQUEST_NOT_FOUND",
        "message": "Edit request 'req_nonexistent' not found",
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.get_request_details("req_nonexistent")

        assert exc_info.value.status_code == 404


# 12. Approved State Validation
@pytest.mark.anyio
async def test_12_approved_state_validation(quorum_client_instance):
    # Case A: Status is APPROVED -> succeeds
    mock_resp_approved = MagicMock()
    mock_resp_approved.status_code = 200
    mock_resp_approved.json.return_value = {
        "success": True,
        "request": {"id": "req_approved", "status": "APPROVED", "document_id": "doc_101"},
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_approved
        approved_req = await quorum_client_instance.validate_approved_quorum_token("req_approved")
        assert approved_req["status"] == "APPROVED"

    # Case B: Status is PENDING -> raises HTTP 400
    mock_resp_pending = MagicMock()
    mock_resp_pending.status_code = 200
    mock_resp_pending.json.return_value = {
        "success": True,
        "request": {"id": "req_pending", "status": "PENDING"},
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_pending
        with pytest.raises(HTTPException) as exc_info:
            await quorum_client_instance.validate_approved_quorum_token("req_pending")

        assert exc_info.value.status_code == 400
        assert "not authorized" in exc_info.value.detail.lower()


# 13. Requester Excluded From Eligible Approvers
@pytest.mark.anyio
async def test_13_requester_excluded_from_eligible_approvers(quorum_client_instance):
    requester_uuid = uuid.uuid4()
    user1 = User(id=requester_uuid, employee_id="EMP_REQ", full_name="Requester User", is_active=True)
    user2 = User(id=uuid.uuid4(), employee_id="EMP_APP1", full_name="Approver 1", role="APPROVAL_OFFICER", is_active=True)
    user3 = User(id=uuid.uuid4(), employee_id="EMP_APP2", full_name="Approver 2", role="APPROVAL_OFFICER", is_active=True)
    user4 = User(id=uuid.uuid4(), employee_id="EMP_APP3", full_name="Approver 3", role="APPROVAL_OFFICER", is_active=True)

    mock_db = MagicMock()
    mock_query = MagicMock()
    mock_filter = MagicMock()
    mock_filter.all.return_value = [user1, user2, user3, user4]
    mock_query.filter.return_value = mock_filter
    mock_db.query.return_value = mock_query

    eligible_ids = await quorum_client_instance.get_eligible_approvers(
        case_id="case_001",
        sensitivity="MEDIUM",
        requester_id=str(requester_uuid),
        db=mock_db,
    )

    # Requester MUST NOT be in eligible_ids
    assert str(requester_uuid) not in eligible_ids
    assert len(eligible_ids) == 3
    assert str(user2.id) in eligible_ids
    assert str(user3.id) in eligible_ids
    assert str(user4.id) in eligible_ids
