import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
from app.db.guid import GUID

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.case import Case
    from app.models.document_version import DocumentVersion
    from app.models.edit_request import EditRequest


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    document_type: Mapped[str] = mapped_column(String(100), nullable=False)
    sensitivity_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="MEDIUM"
    )
    status: Mapped[str] = mapped_column(
        String(30), index=True, nullable=False, default="LOCKED"
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    current_version_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey(
            "document_versions.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_documents_current_version_id",
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Property alias for compatibility
    @property
    def uploaded_by(self) -> uuid.UUID:
        return self.created_by

    @uploaded_by.setter
    def uploaded_by(self, value: uuid.UUID) -> None:
        self.created_by = value

    @property
    def case_number(self) -> Optional[str]:
        return self.case.case_number if self.case else None

    @property
    def edit_request_id(self) -> Optional[uuid.UUID]:
        for req in (self.edit_requests or []):
            if req.status in ("PENDING", "PENDING_QUORUM", "APPROVED"):
                return req.id
        return None

    @property
    def active_edit_request(self) -> Optional[dict]:
        for req in (self.edit_requests or []):
            if req.status in ("PENDING", "PENDING_QUORUM", "APPROVED"):
                return {
                    "id": str(req.id),
                    "requester_id": str(req.requester_id),
                    "reason": req.reason,
                    "status": req.status,
                    "requested_at": req.requested_at.isoformat() if req.requested_at else None,
                }
        return None

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="documents")
    uploader: Mapped["User"] = relationship(
        "User", back_populates="uploaded_documents", foreign_keys=[created_by]
    )
    versions: Mapped[List["DocumentVersion"]] = relationship(
        "DocumentVersion",
        back_populates="document",
        foreign_keys="DocumentVersion.document_id",
        cascade="all, delete-orphan",
    )
    current_version: Mapped[Optional["DocumentVersion"]] = relationship(
        "DocumentVersion",
        foreign_keys=[current_version_id],
        post_update=True,
    )
    edit_requests: Mapped[List["EditRequest"]] = relationship(
        "EditRequest", back_populates="document", cascade="all, delete-orphan"
    )
