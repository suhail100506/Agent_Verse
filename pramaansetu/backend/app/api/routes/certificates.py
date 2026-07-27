import os
import hashlib
import asyncio
from datetime import datetime
from bson import ObjectId
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, BackgroundTasks
from app.db.mongo import get_database, to_object_id
from app.core.security import get_current_user
from app.config import settings
from app.pipeline.orchestrator import run_verification_pipeline

router = APIRouter(prefix="/certificates", tags=["Certificates"])

@router.post("/upload")
async def upload_certificate(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    # Validate extension
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".pdf", ".png", ".jpg", ".jpeg"]:
        raise HTTPException(status_code=400, detail=f"File extension {ext} not supported.")

    # Read bytes and compute SHA-256 hash
    contents = await file.read()
    if len(contents) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File size exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit.")

    sha256_hash = hashlib.sha256(contents).hexdigest()

    # Save to disk
    user_upload_dir = os.path.join(settings.UPLOAD_DIR, current_user["id"])
    os.makedirs(user_upload_dir, exist_ok=True)
    stored_filename = f"{sha256_hash[:16]}_{filename}"
    file_path = os.path.join(user_upload_dir, stored_filename)

    with open(file_path, "wb") as f:
        f.write(contents)

    # Check duplicate certificate upload by SHA256
    existing_cert = await db.certificates.find_one({"file_hash_sha256": sha256_hash})
    previous_verif_id = None
    if existing_cert:
        latest_verif = await db.verification_records.find_one(
            {"certificate_id": existing_cert["_id"]},
            sort=[("created_at", -1)]
        )
        if latest_verif:
            previous_verif_id = latest_verif["_id"]
        cert_id = existing_cert["_id"]
    else:
        # Create Certificate Document
        cert_doc = {
            "uploaded_by": to_object_id(current_user["id"]),
            "original_filename": filename,
            "storage_path": file_path,
            "file_hash_sha256": sha256_hash,
            "file_type": ext.lstrip("."),
            "uploaded_at": datetime.utcnow()
        }
        res_cert = await db.certificates.insert_one(cert_doc)
        cert_id = res_cert.inserted_id

    # Create immutable append-only VerificationRecord document
    verification_doc = {
        "certificate_id": cert_id,
        "previous_verification_id": previous_verif_id,
        "pipeline_version": "1.0",
        "status": "processing",
        "current_stage": "Initialized",
        "stage_progress_pct": 0,
        "extracted_data": {},
        "stage_results": {},
        "authenticity_score": {},
        "classification": "Processing",
        "ai_reasoning": "",
        "recommendation": "",
        "report_pdf_path": "",
        "created_at": datetime.utcnow(),
        "completed_at": None
    }
    res_verif = await db.verification_records.insert_one(verification_doc)
    verification_id_str = str(res_verif.inserted_id)

    # Launch verification pipeline asynchronously in background
    try:
        asyncio.create_task(run_verification_pipeline(verification_id_str, db))
    except Exception as e:
        print(f"Background task dispatch warning: {e}")

    return {
        "certificate_id": str(cert_id),
        "verification_id": verification_id_str,
        "status": "processing",
        "is_duplicate_hash": bool(existing_cert),
        "message": "Certificate uploaded successfully. Verification pipeline launched."
    }

@router.get("/{id}")
async def get_certificate(id: str, current_user: dict = Depends(get_current_user), db=Depends(get_database)):
    cert = await db.certificates.find_one({"_id": ObjectId(id)})
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    return {
        "id": str(cert["_id"]),
        "uploaded_by": str(cert["uploaded_by"]),
        "original_filename": cert["original_filename"],
        "file_hash_sha256": cert["file_hash_sha256"],
        "file_type": cert["file_type"],
        "uploaded_at": cert["uploaded_at"]
    }
