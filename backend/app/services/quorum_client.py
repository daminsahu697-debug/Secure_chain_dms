"""
SecureChain DMS — FastAPI Quorum Service Client
================================================
Communicates with the Node.js M-of-N Quorum Approval Engine microservice (default port 3000).
Provides methods to create edit approval requests, cast votes, fetch request details/audit logs,
resolve eligible pool approvers from PostgreSQL, and validate approved quorum tokens.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User

logger = logging.getLogger(__name__)


class QuorumClient:
    """
    HTTP client interface for interacting with the Quorum Approval Engine microservice.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.base_url = (base_url or getattr(settings, "QUORUM_SERVICE_URL", "http://localhost:3000")).rstrip("/")
        self.timeout = timeout or getattr(settings, "QUORUM_SERVICE_TIMEOUT", 15.0)

    def _handle_service_error(self, err: Exception) -> Dict[str, Any]:
        """Format connection/timeout errors consistently for graceful degradation."""
        logger.warning(f"Quorum Engine service connection failure: {err}")
        return {
            "status": "OFFLINE",
            "skipped": True,
            "reason": "Quorum Engine unavailable",
        }

    async def create_approval_request(
        self,
        document_id: str,
        requester_id: str,
        sensitivity: str,
        proposed_content: str,
        pool_member_ids: List[str],
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        POST /api/approval/requests
        Submit a new edit request to the Quorum Approval Engine.
        """
        payload = {
            "documentId": str(document_id),
            "requesterId": str(requester_id),
            "proposedContent": proposed_content,
            "sensitivityTier": sensitivity.upper(),
            "poolMemberIds": [str(m) for m in pool_member_ids],
        }
        if request_id:
            payload["id"] = str(request_id)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(f"{self.base_url}/api/approval/requests", json=payload)

            if res.status_code == 400:
                err_data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                detail = err_data.get("message", "Invalid approval request payload")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

            res.raise_for_status()
            return res.json()
        except HTTPException:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as err:
            return self._handle_service_error(err)

    async def cast_vote(
        self,
        request_id: str,
        voter_id: str,
        vote_choice: str,
    ) -> Dict[str, Any]:
        """
        POST /api/approval/requests/{request_id}/vote
        Cast an APPROVE or REJECT vote on a pending edit request.
        """
        payload = {
            "voterId": str(voter_id),
            "voteChoice": vote_choice.upper(),
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(f"{self.base_url}/api/approval/requests/{request_id}/vote", json=payload)

            if res.status_code != 200:
                err_data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                code = err_data.get("code")
                msg = err_data.get("message", "Vote failed")

                if res.status_code == 403 or code in ("SELF_APPROVAL_FORBIDDEN", "UNAUTHORIZED_APPROVER"):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)
                elif res.status_code == 409 or code == "DUPLICATE_VOTE":
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
                elif res.status_code == 404 or code == "REQUEST_NOT_FOUND":
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
                elif res.status_code == 400:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

            res.raise_for_status()
            return res.json()
        except HTTPException:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as err:
            return self._handle_service_error(err)

    async def get_request_details(self, request_id: str) -> Dict[str, Any]:
        """
        GET /api/approval/requests/{request_id}
        Fetch sanitized request details and vote status.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(f"{self.base_url}/api/approval/requests/{request_id}")

            if res.status_code == 404:
                err_data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                msg = err_data.get("message", f"Request '{request_id}' not found")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)

            res.raise_for_status()
            return res.json()
        except HTTPException:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as err:
            return self._handle_service_error(err)

    async def get_audit_logs(self, request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        GET /api/approval/audit-logs?requestId={request_id}
        Retrieve immutable WORM audit logs.
        """
        try:
            params = {}
            if request_id:
                params["requestId"] = request_id
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(f"{self.base_url}/api/approval/audit-logs", params=params)

            res.raise_for_status()
            return res.json()
        except HTTPException:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as err:
            return self._handle_service_error(err)

    async def get_eligible_approvers(
        self,
        case_id: str,
        sensitivity: str,
        requester_id: str,
        db: Session,
    ) -> List[str]:
        """
        Resolve eligible pool approver user IDs from PostgreSQL via SQLAlchemy Session.
        Enforces that requester_id is STRICTLY EXCLUDED from the returned pool.
        """
        req_str = str(requester_id)
        users = db.query(User).filter(User.is_active.is_(True)).all()

        eligible_ids = []
        for u in users:
            u_id_str = str(u.id)
            if u_id_str == req_str:
                continue
            eligible_ids.append(u_id_str)

        # Pool size N based on sensitivity: LOW=1, MEDIUM=3, HIGH=5
        sens_upper = (sensitivity or "MEDIUM").upper()
        pool_n = 1 if sens_upper == "LOW" else (3 if sens_upper == "MEDIUM" else 5)
        effective_n = min(pool_n, len(eligible_ids))

        return eligible_ids[:effective_n]

    async def validate_approved_quorum_token(self, request_id: str) -> Dict[str, Any]:
        """
        CRITICAL SECURITY RULE:
        Verifies that a given edit request ID is a valid, fully APPROVED quorum authorization token.
        Raises HTTPException 400 if the request is pending, rejected, or missing.
        """
        details = await self.get_request_details(request_id)
        if details.get("skipped"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Quorum Engine is offline. Cannot validate quorum authorization token.",
            )

        req_data = details.get("request", {})
        request_status = req_data.get("status")

        if request_status != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Quorum token '{request_id}' is not authorized. Current status: '{request_status}' (must be 'APPROVED').",
            )

        return req_data


quorum_client = QuorumClient()

__all__ = ["QuorumClient", "quorum_client"]
