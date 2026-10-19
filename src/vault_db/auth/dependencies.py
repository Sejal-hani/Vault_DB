"""
VaultDB Authentication Dependencies for FastAPI
Extracts and validates identity from Bearer JWT tokens, API keys, or session cookies.
"""

from dataclasses import dataclass
from typing import Optional, List
from fastapi import Request, Header, Cookie, HTTPException, status, Depends

from src.vault_db.auth.jwt_handler import decode_access_token
from src.vault_db.storage.postgres import PostgresStorage


@dataclass
class AuthenticatedUser:
    email: str
    role: str
    full_name: str
    api_key: Optional[str] = None
    department: str = "General"


_pg_storage: Optional[PostgresStorage] = None


def get_postgres_storage() -> PostgresStorage:
    global _pg_storage
    if _pg_storage is None:
        _pg_storage = PostgresStorage()
    return _pg_storage


async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    vault_session: Optional[str] = Cookie(None),
) -> AuthenticatedUser:
    """
    Server-side identity derivation.
    Checks:
    1. Authorization: Bearer <JWT>
    2. X-API-Key: <key>
    3. Cookie: vault_session=<JWT>
    4. Fallback for backwards compatibility / local dev: if header 'X-Demo-User' is sent.
    """
    storage = get_postgres_storage()

    # 1. API Key Authentication
    api_key = x_api_key
    if not api_key and authorization and authorization.startswith("ApiKey "):
        api_key = authorization.split(" ", 1)[1].strip()

    if api_key:
        user_record = storage.get_user_by_api_key(api_key)
        if user_record and user_record.get("status") == "active":
            return AuthenticatedUser(
                email=user_record["email"],
                role=user_record["role"].lower(),
                full_name=user_record.get("full_name", user_record["email"]),
                api_key=api_key,
                department=user_record.get("department", "General"),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API Key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. JWT Token Authentication (Bearer Header or Cookie)
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif vault_session:
        token = vault_session

    if token:
        try:
            payload = decode_access_token(token)
            email = payload.get("sub")
            if not email:
                raise ValueError("Token missing subject claim.")

            user_record = storage.get_user_by_email(email)
            if not user_record or user_record.get("status") != "active":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is deactivated or no longer exists.",
                )

            return AuthenticatedUser(
                email=user_record["email"],
                role=user_record["role"].lower(),
                full_name=user_record.get("full_name", user_record["email"]),
                api_key=user_record.get("api_key"),
                department=user_record.get("department", "General"),
            )
        except ValueError as ve:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(ve),
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. Fallback for unauthenticated requests:
    # If client sends no credentials, default to guest or deny
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token in Authorization header, X-API-Key, or vault_session cookie.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(allowed_roles: List[str]):
    """Enforces that the authenticated user belongs to one of the specified roles."""
    async def role_checker(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        clean_allowed = [r.lower() for r in allowed_roles]
        if current_user.role not in clean_allowed and "*" not in clean_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Role '{current_user.role}' lacks permissions for this endpoint.",
            )
        return current_user
    return role_checker
