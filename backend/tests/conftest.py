import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.security import hash_password
from app.db.base import Base
from app.db.seed_demo_users import seed_demo_users
from app.main import app
from app.models.case import Case
from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.models.user import User

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Seed demo users
    seed_demo_users(db, password="demo-password")

    emp001 = db.query(User).filter(User.employee_id == "EMP001").first()

    # Inactive user
    inactive = User(
        employee_id="INACTIVE001",
        full_name="Inactive User",
        email="inactive@securechain.gov.in",
        role="OFFICER",
        hashed_password=hash_password("demo-password"),
        is_active=False,
    )
    db.add(inactive)

    # Seed dummy case & document using UUIDs
    test_case_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    test_doc_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    test_ver_id = uuid.UUID("33333333-3333-4333-8333-333333333333")

    test_case = db.query(Case).filter(Case.id == test_case_id).first()
    if not test_case:
        test_case = Case(
            id=test_case_id,
            case_number="CASE-2026-001",
            title="Test Case",
            description="Test Case Description",
            status="ACTIVE",
            created_by=emp001.id,
        )
        db.add(test_case)
        db.flush()


    test_doc = Document(
        id=test_doc_id,
        case_id=test_case.id,
        document_type="EVIDENCE",
        title="Test Evidence Doc",
        sensitivity_level="HIGH",
        status="LOCKED",
        created_by=emp001.id,
    )
    db.add(test_doc)
    db.flush()

    test_ver = DocumentVersion(
        id=test_ver_id,
        document_id=test_doc.id,
        version_number=1,
        original_filename="test_evidence.pdf",
        storage_key="documents/1/test_evidence.pdf",
        doc_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        prev_chain_hash="0"*64,
        chain_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        created_by=emp001.id,
        status="LOCKED",
    )
    db.add(test_ver)
    db.flush()

    test_doc.current_version_id = test_ver.id
    db.commit()

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    yield db

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    with TestClient(app) as test_client:
        yield test_client
