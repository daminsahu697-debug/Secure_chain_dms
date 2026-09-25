import logging
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.models.user import User

logger = logging.getLogger(__name__)

DEMO_USERS_SPEC = [
    {
        "employee_id": "POL-IO-001",
        "name": "Officer (Investigation)",
        "email": "officer@securechain.gov.in",
        "role": "POLICE",
    },
    {
        "employee_id": "JUD-JDG-001",
        "name": "Hon. Presiding Judge",
        "email": "judge@securechain.gov.in",
        "role": "JUDICIAL",
    },
    {
        "employee_id": "FOR-EXP-001",
        "name": "Forensic Officer",
        "email": "forensic@securechain.gov.in",
        "role": "FORENSIC",
    },
    {
        "employee_id": "APP001",
        "name": "Approval Officer 1",
        "email": "app001@securechain.gov.in",
        "role": "APPROVAL_OFFICER",
    },
    {
        "employee_id": "APP002",
        "name": "Approval Officer 2",
        "email": "app002@securechain.gov.in",
        "role": "APPROVAL_OFFICER",
    },
    {
        "employee_id": "APP003",
        "name": "Approval Officer 3",
        "email": "app003@securechain.gov.in",
        "role": "APPROVAL_OFFICER",
    },
    {
        "employee_id": "ADMIN001",
        "name": "System Administrator",
        "email": "admin001@securechain.gov.in",
        "role": "SYSTEM_ADMIN",
    },
]


def seed_demo_users(db: Session, password: str = None) -> list[User]:
    """
    Creates demo users if they do not already exist in the database.
    Password is derived from configuration (settings.DEMO_USER_PASSWORD) or function param.
    Never hard-coded into source.
    """
    demo_password = password or settings.DEMO_USER_PASSWORD
    hashed_pwd = hash_password(demo_password)
    created_or_updated = []

    for spec in DEMO_USERS_SPEC:
        user = db.query(User).filter(User.employee_id == spec["employee_id"]).first()
        if not user:
            user = User(
                employee_id=spec["employee_id"],
                name=spec["name"],
                email=spec["email"],
                role=spec["role"],
                hashed_password=hashed_pwd,
                is_active=True,
            )
            db.add(user)
            logger.info(f"Created demo user '{user.employee_id}' with role '{user.role}'.")
        else:
            # Ensure password and role match demo requirements
            user.hashed_password = hashed_pwd
            user.role = spec["role"]
            user.is_active = True
            logger.info(f"Updated existing user '{user.employee_id}' password/role.")
        created_or_updated.append(user)

    db.commit()
    for u in created_or_updated:
        db.refresh(u)

    # Seed demo case if not present
    from app.models.case import Case
    import uuid

    demo_case_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    demo_case = db.query(Case).filter(Case.id == demo_case_id).first()
    if not demo_case and created_or_updated:
        emp001 = next((u for u in created_or_updated if u.employee_id == "EMP001"), created_or_updated[0])
        demo_case = Case(
            id=demo_case_id,
            case_number="CASE-2026-001",
            title="Inter-State Financial Embezzlement Syndicate Investigation",
            description="Primary demo case docket for financial crimes investigation",
            status="ACTIVE",
            created_by=emp001.id,
        )
        db.add(demo_case)
        db.commit()
        logger.info(f"Created demo case '{demo_case.case_number}' ({demo_case.id}).")
    return created_or_updated
