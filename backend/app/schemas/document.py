import uuid
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict


class DocumentBase(BaseModel):
    document_type: str
    title: str
    sensitivity_level: str = "MEDIUM"
    status: str = "LOCKED"


class DocumentCreate(DocumentBase):
    case_id: Union[uuid.UUID, str, int]
    uploaded_by: Optional[Union[uuid.UUID, str, int]] = None


class DocumentUpdate(BaseModel):
    title: Optional[str] = None
    document_type: Optional[str] = None
    sensitivity_level: Optional[str] = None
    status: Optional[str] = None
    current_version_id: Optional[Union[uuid.UUID, str, int]] = None


class DocumentResponse(DocumentBase):
    id: Union[uuid.UUID, str, int]
    case_id: Union[uuid.UUID, str, int]
    case_number: Optional[str] = None
    uploaded_by: Union[uuid.UUID, str, int]
    current_version_id: Optional[Union[uuid.UUID, str, int]] = None
    created_at: datetime
    updated_at: datetime
    edit_request_id: Optional[Union[uuid.UUID, str]] = None
    active_edit_request: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class DocumentListResponse(BaseModel):
    items: list[DocumentResponse]
    total: int
    skip: int
    limit: int

    model_config = ConfigDict(from_attributes=True)
