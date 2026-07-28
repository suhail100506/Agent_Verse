import os
import json
import uuid
import datetime
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path

USER_DB_PATH = Path(__file__).parent / "users_db.json"


def load_users() -> list:
    if USER_DB_PATH.exists():
        try:
            with open(USER_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_users(users: list) -> None:
    with open(USER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def register_user(username: str, email: str, password: str, role: str = "SOC Analyst") -> Dict[str, Any]:
    users = load_users()
    for u in users:
        if u.get("username").lower() == username.lower():
            return {"error": "Username already exists"}

    user_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
    hashed = hash_password(password)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    new_user = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "hashed_password": hashed,
        "role": role,
        "created_at": timestamp
    }
    users.append(new_user)
    save_users(users)

    # Generate pseudo-JWT token
    token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{user_id}.{uuid.uuid4().hex}"
    return {
        "status": "success",
        "message": "User registered successfully",
        "user": {"user_id": user_id, "username": username, "email": email, "role": role},
        "access_token": token
    }


def login_user(username: str, password: str) -> Dict[str, Any]:
    users = load_users()
    hashed = hash_password(password)

    for u in users:
        if u.get("username").lower() == username.lower() and u.get("hashed_password") == hashed:
            token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{u['user_id']}.{uuid.uuid4().hex}"
            return {
                "status": "success",
                "message": "Authentication successful",
                "user": {"user_id": u["user_id"], "username": u["username"], "email": u["email"], "role": u.get("role", "SOC Analyst")},
                "access_token": token
            }

    return {"error": "Invalid username or password"}
