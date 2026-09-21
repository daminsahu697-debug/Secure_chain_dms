from fastapi import APIRouter

from app.db.seed_demo_users import DEMO_USERS_SPEC

router = APIRouter()


def _portal_role(role: str) -> str:
    role = role.upper()
    if role in {"JUDICIAL", "REVIEWER"}:
        return "JUDICIAL"
    if role in {"FORENSIC", "FSL"}:
        return "FORENSIC"
    if role in {"AUDITOR", "AUDIT"}:
        return "AUDITOR"
    return "POLICE"


@router.get("/personas", tags=["Authentication"])
def list_personas() -> dict[str, list[dict[str, str]]]:
    """Return public demo persona metadata used by the login screen."""
    return {
        "personas": [
            {
                "id": user["employee_id"],
                "employee_id": user["employee_id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "portalRole": _portal_role(user["role"]),
            }
            for user in DEMO_USERS_SPEC
        ]
    }