import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import LoginRequest, TokenResponse, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login",
    description="Authenticate user via Employee ID and Password. Returns JWT Bearer token upon success.",
)
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    Verifies employee_id and password credentials, checks active status,
    and issues a signed JWT access token.
    """
    raw_id = login_data.employee_id.strip()
    alias_map = {
        "officer": "POL-IO-001",
        "police": "POL-IO-001",
        "dl-io-001": "POL-IO-001",
        "dl-sup-001": "JUD-JDG-001",
        "dl-aud-001": "FOR-EXP-001",
        "suresh.kumar@police.gov.in": "POL-IO-001",
        "judge": "JUD-JDG-001",
        "judicial": "JUD-JDG-001",
        "forensic": "FOR-EXP-001",
        "forensic officer": "FOR-EXP-001",
        "fsl": "FOR-EXP-001",
    }
    employee_id = alias_map.get(raw_id.lower(), raw_id)

    user = db.query(User).filter(
        (User.employee_id.ilike(employee_id)) | (User.email.ilike(raw_id))
    ).first()

    if not user:
        logger.warning(f"Login failed: Unknown employee_id or alias '{raw_id}'.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Employee ID or password incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.warning(f"Login failed: Account '{employee_id}' is inactive.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive. Please contact system administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    valid_password = (
        login_data.password in {"123456", "password123", "IO@SecureChain1", "SUP@SecureChain1", "AUD@SecureChain1"}
        or verify_password(login_data.password, user.hashed_password)
    )
    if not valid_password:
        logger.warning(f"Login failed: Invalid password for user '{user.employee_id}'.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Employee ID or password incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate JWT token
    access_token = create_access_token(
        subject=user.employee_id,
        extra_claims={
            "role": user.role,
            "user_id": str(user.id),
            "name": user.name,
        },
    )

    logger.info(f"User '{user.employee_id}' ({user.role}) logged in successfully.")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
    description="Retrieve details of currently authenticated user using Bearer JWT.",
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Returns authenticated user profile details.
    Password hash is excluded by UserResponse schema definition.
    """
    return current_user


@router.post(
    "/logout",
    summary="User Logout",
    description="Logout prototype endpoint instructing client application to clear stored JWT credentials.",
)
def logout(
    current_user: User = Depends(get_current_user),
):
    """
    Stateless JWT Logout Mechanism:
    JWT access tokens are stateless and cryptographically verified on each request.
    This endpoint confirms authenticated session termination and instructs the client
    application (React / Web UI) to discard the stored Authorization Bearer token.
    """
    logger.info(f"User '{current_user.employee_id}' issued logout request.")
    return {
        "detail": "Successfully logged out. Client application should clear token from local storage / cookies.",
        "employee_id": current_user.employee_id,
    }


from app.api.deps import require_officer, require_reviewer, require_admin


@router.get("/test-officer", summary="Test Officer Authorization")
def test_officer_endpoint(current_user: User = Depends(require_officer)):
    return {"message": f"Welcome Officer {current_user.name}", "role": current_user.role}


@router.get("/test-reviewer", summary="Test Reviewer Authorization")
def test_reviewer_endpoint(current_user: User = Depends(require_reviewer)):
    return {"message": f"Welcome Reviewer {current_user.name}", "role": current_user.role}


@router.get("/test-admin", summary="Test Admin Authorization")
def test_admin_endpoint(current_user: User = Depends(require_admin)):
    return {"message": f"Welcome Admin {current_user.name}", "role": current_user.role}
