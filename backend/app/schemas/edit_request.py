import uuid
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict


class EditRequestBase(BaseModel):
    reason: str
    amendment_reason_code: Optional[str] = None
    status: str = "PENDING"


class EditRequestCreate(EditRequestBase):
    document_id: Union[uuid.UUID, str, int]


class VoteRequest(BaseModel):
    vote_choice: str  # APPROVE or REJECT


class EditRequestResponse(EditRequestBase):
    id: Union[uuid.UUID, str, int]
    document_id: Union[uuid.UUID, str, int]
    requester_id: Union[uuid.UUID, str, int]
    source_version_id: Union[uuid.UUID, str, int]
    proposed_version_id: Optional[Union[uuid.UUID, str, int]] = None
    quorum_policy_id: Optional[Union[uuid.UUID, str, int]] = None
    requested_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    quorum_data: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)
