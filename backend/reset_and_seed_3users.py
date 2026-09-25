"""
SecureChain DMS — Database Reset and 3-User Seeding Script
===========================================================
1. Truncates all data from application tables (preserving schema).
2. Preserves 'roles' and 'alembic_version'.
3. Creates exactly 3 authorized users:
   - Officer: POL-IO-001
   - Judge: JUD-JDG-001
   - Forensic Officer: FOR-EXP-001
4. Seeds starter case CASE-2026-001 with all 3 users as case participants.
"""

import uuid
from sqlalchemy import text
from app.db.session import SessionLocal, engine
from app.core.security import hash_password
from app.models.user import User
from app.models.role import Role
from app.models.case import Case, CaseParticipant


def reset_and_seed():
    print("=" * 60)
    print("Starting SecureChain DMS Database Reset & Seeding")
    print("=" * 60)

    # Tables to truncate in order
    tables_to_truncate = [
        "tamper_alerts",
        "approval_assignments",
        "approvals",
        "edit_requests",
        "merkle_checkpoints",
        "audit_logs",
        "storage_objects",
        "document_versions",
        "documents",
        "case_participants",
        "cases",
        "quorum_policies",
        "users",
    ]

    with engine.connect() as conn:
        print("\n1. Truncating data from application tables...")
        for table in tables_to_truncate:
            try:
                conn.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
                conn.commit()
                print(f"  [OK] Truncated {table}")
            except Exception as e:
                print(f"  [WARN] Could not truncate {table}: {e}")
                conn.rollback()

    db = SessionLocal()
    try:
        print("\n2. Verifying roles...")
        # Check / ensure roles exist
        required_roles = {
            "INVESTIGATING_OFFICER": "Investigating Officer for law enforcement cases",
            "JUDGE": "Honorable Judge for judicial adjudication",
            "FORENSIC_EXPERT": "Forensic Expert / Examiner for scientific analysis",
        }
        roles_map = {}
        for role_name, desc in required_roles.items():
            r = db.query(Role).filter(Role.name == role_name).first()
            if not r:
                r = Role(id=uuid.uuid4(), name=role_name, description=desc)
                db.add(r)
                db.commit()
                db.refresh(r)
                print(f"  + Created missing role: {role_name}")
            roles_map[role_name] = r
            print(f"  [OK] Role ready: {role_name} ({r.id})")

        print("\n3. Seeding exactly 3 authorized users...")
        pwd_hash = hash_password("123456")

        users_spec = [
            {
                "employee_id": "POL-IO-001",
                "name": "Officer (Investigation)",
                "email": "officer@securechain.gov.in",
                "department": "Special Investigation Division",
                "jurisdiction": "Central District PS, New Delhi",
                "role_str": "POLICE",
                "role_id": roles_map["INVESTIGATING_OFFICER"].id,
            },
            {
                "employee_id": "JUD-JDG-001",
                "name": "Hon. Presiding Judge",
                "email": "judge@securechain.gov.in",
                "department": "District & Sessions Court",
                "jurisdiction": "Patiala House Courts, New Delhi",
                "role_str": "JUDICIAL",
                "role_id": roles_map["JUDGE"].id,
            },
            {
                "employee_id": "FOR-EXP-001",
                "name": "Forensic Officer",
                "email": "forensic@securechain.gov.in",
                "department": "Cyber Forensics & Ballistics Division",
                "jurisdiction": "Central Forensic Science Laboratory (CFSL)",
                "role_str": "FORENSIC",
                "role_id": roles_map["FORENSIC_EXPERT"].id,
            },
        ]

        created_users = {}
        for spec in users_spec:
            u = User(
                id=uuid.uuid4(),
                employee_id=spec["employee_id"],
                full_name=spec["name"],
                email=spec["email"],
                department=spec["department"],
                jurisdiction=spec["jurisdiction"],
                _role_str=spec["role_str"],
                role_id=spec["role_id"],
                password_hash=pwd_hash,
                is_active=True,
            )
            db.add(u)
            db.commit()
            db.refresh(u)
            created_users[spec["employee_id"]] = u
            print(f"  [OK] Created user: {u.full_name} | ID: {u.employee_id} | Role: {u.role}")

        print("\n4. Seeding clean starter Case...")
        officer = created_users["POL-IO-001"]
        judge = created_users["JUD-JDG-001"]
        forensic = created_users["FOR-EXP-001"]

        starter_case = Case(
            id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
            case_number="CASE-2026-001",
            title="State vs. Primary Accused (FIR No. 2026/001)",
            description="Initial registered case docket for inter-agency criminal investigation and evidentiary chain.",
            case_type="CRIMINAL",
            department="Special Investigation Division",
            jurisdiction="Patiala House Courts, New Delhi",
            status="ACTIVE",
            created_by=officer.id,
        )
        db.add(starter_case)
        db.commit()
        db.refresh(starter_case)
        print(f"  [OK] Created starter case: {starter_case.case_number} ({starter_case.title})")

        print("\n5. Linking all 3 users as Case Participants...")
        participants = [
            CaseParticipant(
                id=uuid.uuid4(),
                case_id=starter_case.id,
                participant_id=officer.id,
                access_level="ADMIN",
                added_by=officer.id,
            ),
            CaseParticipant(
                id=uuid.uuid4(),
                case_id=starter_case.id,
                participant_id=judge.id,
                access_level="WRITE",
                added_by=officer.id,
            ),
            CaseParticipant(
                id=uuid.uuid4(),
                case_id=starter_case.id,
                participant_id=forensic.id,
                access_level="WRITE",
                added_by=officer.id,
            ),
        ]
        for p in participants:
            db.add(p)
        db.commit()
        print("  [OK] Added Officer, Judge, and Forensic Officer as case participants.")

        print("\n" + "=" * 60)
        print("Database Reset & 3-User Seeding Completed Successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"Error during seeding: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    reset_and_seed()
