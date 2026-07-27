from fastapi import APIRouter, Depends, HTTPException
from app.db.mongo import get_database, to_object_id
from app.core.security import get_current_user

router = APIRouter(prefix="/verification", tags=["Verification"])

@router.get("/{id}/status")
async def get_verification_status(id: str, db=Depends(get_database)):
    try:
        verif = await db.verification_records.find_one({"_id": to_object_id(id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verification ID format")

    if not verif:
        raise HTTPException(status_code=404, detail="Verification record not found")

    return {
        "id": str(verif["_id"]),
        "status": verif.get("status", "processing"),
        "current_stage": verif.get("current_stage", "Initialized"),
        "stage_progress_pct": verif.get("stage_progress_pct", 0),
        "classification": verif.get("classification", "Processing"),
        "stage_results": verif.get("stage_results", {}),
        "completed_at": verif.get("completed_at")
    }

@router.get("/{id}/result")
async def get_verification_result(id: str, db=Depends(get_database)):
    try:
        verif = await db.verification_records.find_one({"_id": to_object_id(id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verification ID format")

    if not verif:
        raise HTTPException(status_code=404, detail="Verification record not found")

    # Fraud Pattern Check: Check if certificate number has appeared across other user accounts
    duplicate_alert = None
    cert_no = verif.get("extracted_data", {}).get("certificate_number")
    inst = verif.get("extracted_data", {}).get("institution")

    if cert_no:
        query = {"extracted_data.certificate_number": cert_no}
        if inst:
            query["extracted_data.institution"] = inst

        matching_records = await db.verification_records.find(query).to_list(length=10)
        if len(matching_records) > 1:
            duplicate_alert = {
                "flagged": True,
                "occurrences_count": len(matching_records),
                "message": f"Fraud Warning: Certificate Number '{cert_no}' has been submitted {len(matching_records)} times across different uploads."
            }

    verif_out = {
        "id": str(verif["_id"]),
        "certificate_id": str(verif["certificate_id"]),
        "previous_verification_id": str(verif["previous_verification_id"]) if verif.get("previous_verification_id") else None,
        "pipeline_version": verif.get("pipeline_version", "1.0"),
        "status": verif.get("status"),
        "current_stage": verif.get("current_stage"),
        "stage_progress_pct": verif.get("stage_progress_pct", 100),
        "extracted_data": verif.get("extracted_data", {}),
        "stage_results": verif.get("stage_results", {}),
        "authenticity_score": verif.get("authenticity_score", {}),
        "classification": verif.get("classification", "Processing"),
        "ai_reasoning": verif.get("ai_reasoning", ""),
        "recommendation": verif.get("recommendation", ""),
        "report_pdf_path": verif.get("report_pdf_path", ""),
        "created_at": verif.get("created_at"),
        "completed_at": verif.get("completed_at"),
        "duplicate_alert": duplicate_alert
    }

    return verif_out
