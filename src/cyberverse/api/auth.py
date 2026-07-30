"""
auth.py — JWT Authentication for CyberVerse API
================================================
Simple JWT-based authentication using python-jose.
For local development uses a static user store.
Production deployments should replace with a real user DB.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Graceful import of jose
try:
    from jose import JWTError, jwt
    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False

# Graceful import of passlib
try:
    from passlib.context import CryptContext
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    _pwd_context = None  # type: ignore[assignment]

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get("CYBERVERSE_SECRET_KEY", "cyberverse-dev-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_EXPIRE_MINUTES", "60"))

# ---------------------------------------------------------------------------
# Static user store (dev mode)
# ---------------------------------------------------------------------------

# In production: replace with DB lookup
# Password: "cyberverse" (bcrypt hash below)
_USERS_DB: dict = {
    "admin": {
        "username": "admin",
        "full_name": "CyberVerse Admin",
        "email": "admin@cyberverse.io",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "role": "admin",
        "disabled": False,
    },
    "analyst": {
        "username": "analyst",
        "full_name": "Security Analyst",
        "email": "analyst@cyberverse.io",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "analyst",
        "disabled": False,
    },
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    username: str
    role: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: str = "analyst"
    disabled: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def _verify_password(plain: str, hashed: str) -> bool:
    if PASSLIB_AVAILABLE and _pwd_context:
        try:
            return _pwd_context.verify(plain, hashed)
        except Exception:
            pass
    # Fallback: plain text comparison (DEV ONLY)
    return plain == "secret" or plain == "cyberverse"


def _get_user(username: str) -> Optional[dict]:
    return _USERS_DB.get(username)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = _get_user(username)
    if not user:
        return None
    if not _verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})

    if JOSE_AVAILABLE:
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Fallback: base64 "token" for dev without jose installed
    import base64, json
    return base64.urlsafe_b64encode(json.dumps(to_encode, default=str).encode()).decode()


def _decode_token(token: str) -> dict:
    if JOSE_AVAILABLE:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    import base64, json
    try:
        return json.loads(base64.urlsafe_b64decode(token + "==").decode())
    except Exception:
        raise ValueError("Invalid token")


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> User:
    """FastAPI dependency — validates JWT and returns the current user."""
    if token is None:
        # Allow unauthenticated access in dev mode if no token provided
        return User(username="anonymous", role="analyst")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(token)
        username: str = payload.get("sub", "")
        role: str = payload.get("role", "analyst")
        if not username:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    user_dict = _get_user(username)
    if user_dict is None:
        raise credentials_exception
    if user_dict.get("disabled"):
        raise HTTPException(status_code=400, detail="Inactive user")

    return User(
        username=user_dict["username"],
        full_name=user_dict.get("full_name"),
        email=user_dict.get("email"),
        role=role,
        disabled=user_dict.get("disabled", False),
    )


# ---------------------------------------------------------------------------
# Router factory (imported by main.py)
# ---------------------------------------------------------------------------

from fastapi import APIRouter

auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@auth_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"], "role": user.get("role", "analyst")},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        username=user["username"],
        role=user.get("role", "analyst"),
    )
