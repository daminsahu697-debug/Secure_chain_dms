import logging
from typing import Callable, List, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency that:
    1. Reads Bearer token from Authorization header.
    2. Decodes & validates JWT signature and expiration.
    3. Extracts employee_id identity.
    4. Fetches user record from PostgreSQL.
    5. Checks if user account is active.
    6. Returns authenticated User model instance.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or invalid/expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise credentials_exception

    token = credentials.credentials

    try:
        payload = decode_access_token(token)
        employee_id: Optional[str] = payload.get("sub")
        if not employee_id:
            logger.warning("JWT payload missing 'sub' subject claim.")
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        logger.warning("Authentication failed: Expired JWT token signature.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as err:
        logger.warning(f"Authentication failed: Invalid JWT token ({err}).")
        raise credentials_exception

    user = db.query(User).filter(User.employee_id == employee_id).first()
    if not user:
        logger.warning(f"Authentication failed: User employee_id '{employee_id}' not found.")
        raise credentials_exception

    if not user.is_active:
        logger.warning(f"Authentication rejected: User '{employee_id}' is inactive.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive. Access denied.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(*allowed_roles: str) -> Callable:
    """
    Reusable dependency factory enforcing Role-Based Access Control (RBAC).
    Normalizes roles to uppercase strings.
    Raises HTTP 403 Forbidden if current user's role is not authorized.
    """
    normalized_allowed = [r.upper() for r in allowed_roles]

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = (current_user.role or "").upper()
        if user_role not in normalized_allowed:
            logger.warning(
                f"Access denied: User '{current_user.employee_id}' with role '{user_role}' "
                f"attempted to access endpoint requiring roles {normalized_allowed}."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Role '{current_user.role}' is not authorized to perform this operation.",
            )
        return current_user

    return role_checker


# Convenient pre-defined role dependencies
require_officer = require_roles("OFFICER", "ADMIN")
require_reviewer = require_roles("REVIEWER", "ADMIN")
require_admin = require_roles("ADMIN")
