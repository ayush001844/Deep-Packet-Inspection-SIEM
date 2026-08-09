"""
Authentication & Authorization (Upgraded – Upgrade 8)
======================================================
Real JWT-based auth with bcrypt password hashing, role-based access control,
refresh token rotation, and API key authentication.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, status, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.db.database import get_session, User, RefreshToken, APIKey

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "packet-analyzer-pro-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ---------------------------------------------------------------------------
# Password hashing (bcrypt)
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# ---------------------------------------------------------------------------
# JWT Token
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> tuple[str, str]:
    """Create a refresh token and return (raw_token, token_hash)."""
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    session = get_session()
    try:
        refresh = RefreshToken(
            token_hash=token_hash,
            username=username,
            expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
        session.add(refresh)
        session.commit()
    finally:
        session.close()

    return raw_token, token_hash

# ---------------------------------------------------------------------------
# API Key helpers
# ---------------------------------------------------------------------------

def generate_api_key() -> tuple[str, str, str]:
    """Generate an API key. Returns (full_key, key_hash, key_prefix)."""
    full_key = f"dg_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = full_key[:10]
    return full_key, key_hash, key_prefix

# ---------------------------------------------------------------------------
# OAuth2 + API Key schemes
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ---------------------------------------------------------------------------
# Dependency: get current user from JWT or API key
# ---------------------------------------------------------------------------

def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> User:
    """Authenticate via JWT token or API key."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Try API key first
    if api_key:
        return _authenticate_api_key(api_key)

    # Fall back to JWT
    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type", "access")
        if username is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    session = get_session()
    try:
        user = session.query(User).filter(User.username == username).first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user
    finally:
        session.close()


def _authenticate_api_key(raw_key: str) -> User:
    """Validate an API key and return the associated user."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    session = get_session()
    try:
        api_key_record = session.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True,
        ).first()

        if not api_key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        # Check expiry
        if api_key_record.expires_at and api_key_record.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key expired",
            )

        # Update last used
        api_key_record.last_used = datetime.utcnow()
        session.commit()

        # Get user
        user = session.query(User).filter(User.username == api_key_record.username).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with API key is inactive",
            )

        return user
    finally:
        session.close()


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Dependency that enforces admin role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user

# ---------------------------------------------------------------------------
# Seed default admin user
# ---------------------------------------------------------------------------

def seed_default_users() -> None:
    """Create default admin user if no users exist."""
    session = get_session()
    try:
        if session.query(User).count() == 0:
            admin = User(
                username="admin",
                hashed_password=hash_password("admin"),
                role="admin",
                is_active=True,
            )
            session.add(admin)

            analyst = User(
                username="analyst",
                hashed_password=hash_password("analyst"),
                role="analyst",
                is_active=True,
            )
            session.add(analyst)
            session.commit()
            print("[Auth] Seeded default users: admin (admin/admin), analyst (analyst/analyst)")
    except Exception as e:
        print(f"[Auth] Error seeding users: {e}")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class APIKeyCreateRequest(BaseModel):
    label: str
    scopes: list[str] = ["read"]
    expires_in_days: Optional[int] = None


@router.post("/login")
def login(req: LoginRequest):
    """Authenticate user and return JWT access token + refresh token."""
    session = get_session()
    try:
        user = session.query(User).filter(User.username == req.username).first()

        if not user or not verify_password(req.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled",
            )

        access_token = create_access_token(
            data={"sub": user.username, "role": user.role}
        )

        refresh_raw, _ = create_refresh_token(user.username)

        return {
            "access_token": access_token,
            "refresh_token": refresh_raw,
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    finally:
        session.close()


@router.post("/refresh")
def refresh_token(req: RefreshRequest):
    """Exchange a refresh token for a new access token + refresh token (rotation)."""
    token_hash = hashlib.sha256(req.refresh_token.encode()).hexdigest()

    session = get_session()
    try:
        token_record = session.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
        ).first()

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        if token_record.is_revoked:
            # Possible token reuse attack – revoke all tokens for this user
            session.query(RefreshToken).filter(
                RefreshToken.username == token_record.username
            ).update({"is_revoked": True})
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected. All sessions revoked.",
            )

        if token_record.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired",
            )

        # Revoke old token
        token_record.is_revoked = True
        session.commit()

        # Get user
        user = session.query(User).filter(User.username == token_record.username).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        # Issue new tokens
        new_access = create_access_token(
            data={"sub": user.username, "role": user.role}
        )
        new_refresh_raw, _ = create_refresh_token(user.username)

        return {
            "access_token": new_access,
            "refresh_token": new_refresh_raw,
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    finally:
        session.close()


@router.post("/api-keys")
def create_api_key(req: APIKeyCreateRequest, user: User = Depends(require_admin)):
    """Create a new API key (admin only)."""
    full_key, key_hash, key_prefix = generate_api_key()

    session = get_session()
    try:
        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            label=req.label,
            username=user.username,
            scopes=req.scopes,
            expires_at=(
                datetime.utcnow() + timedelta(days=req.expires_in_days)
                if req.expires_in_days
                else None
            ),
        )
        session.add(api_key)
        session.commit()

        return {
            "api_key": full_key,  # Only returned once!
            "key_prefix": key_prefix,
            "label": req.label,
            "scopes": req.scopes,
            "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
            "warning": "Save this key now. It will NOT be shown again.",
        }
    finally:
        session.close()


@router.get("/api-keys")
def list_api_keys(user: User = Depends(require_admin)):
    """List all API keys (masked)."""
    session = get_session()
    try:
        keys = session.query(APIKey).filter(APIKey.username == user.username).all()
        return [
            {
                "id": k.id,
                "key_prefix": k.key_prefix + "...",
                "label": k.label,
                "scopes": k.scopes,
                "is_active": k.is_active,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "created_at": k.created_at.isoformat() if k.created_at else "",
            }
            for k in keys
        ]
    finally:
        session.close()


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int, user: User = Depends(require_admin)):
    """Revoke an API key."""
    session = get_session()
    try:
        key = session.query(APIKey).filter(
            APIKey.id == key_id,
            APIKey.username == user.username,
        ).first()

        if not key:
            raise HTTPException(status_code=404, detail="API key not found")

        key.is_active = False
        session.commit()
        return {"status": "revoked", "key_id": key_id}
    finally:
        session.close()


@router.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    """Logout (revoke all refresh tokens for the user)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    session = get_session()
    try:
        session.query(RefreshToken).filter(
            RefreshToken.username == username,
        ).update({"is_revoked": True})
        session.commit()
        return {"status": "logged_out", "username": username}
    finally:
        session.close()
