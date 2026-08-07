"""
Authentication & Authorization
===============================
Real JWT-based auth with bcrypt password hashing and role-based access control.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.db.database import get_session, User

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "packet-analyzer-pro-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------------------------------------------------------------------------
# OAuth2 scheme
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ---------------------------------------------------------------------------
# Dependency: get current user from JWT
# ---------------------------------------------------------------------------

def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Decode JWT and return the authenticated User object."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
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


@router.post("/login")
def login(req: LoginRequest):
    """Authenticate user and return JWT."""
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

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
        }
    finally:
        session.close()
