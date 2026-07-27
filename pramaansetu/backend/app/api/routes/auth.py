from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
from app.db.mongo import get_database
from app.db.models import UserRegister, UserLogin, Token, UserOut
from app.core.security import (
    get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
)

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/register", response_model=Token)
async def register(user_in: UserRegister, db=Depends(get_database)):
    existing = await db.users.find_one({"email": user_in.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    hashed_pw = get_password_hash(user_in.password)
    user_doc = {
        "email": user_in.email.lower(),
        "password_hash": hashed_pw,
        "role": user_in.role if user_in.role in ["applicant", "verifier", "admin"] else "applicant",
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)

    access_token = create_access_token(user_id, user_doc["role"])
    refresh_token = create_refresh_token(user_id, user_doc["role"])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": user_doc["email"],
            "role": user_doc["role"]
        }
    }

@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db=Depends(get_database)):
    user = await db.users.find_one({"email": credentials.email.lower()})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    user_id = str(user["_id"])
    access_token = create_access_token(user_id, user["role"])
    refresh_token = create_refresh_token(user_id, user["role"])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": user["email"],
            "role": user["role"]
        }
    }

@router.post("/refresh")
async def refresh_token_endpoint(body: dict, db=Depends(get_database)):
    refresh_token = body.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")

    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid token type")

    user_id = payload.get("sub")
    role = payload.get("role")

    new_access_token = create_access_token(user_id, role)
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user), db=Depends(get_database)):
    from app.db.mongo import to_object_id
    user = await db.users.find_one({"_id": to_object_id(current_user["id"])})
    if not user:
        # Return fallback demo user object for unauthenticated testing
        return {
            "id": current_user["id"],
            "email": "verifier@pramaansetu.ac.in",
            "role": current_user["role"] or "verifier",
            "created_at": datetime.utcnow()
        }
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"]
    }
