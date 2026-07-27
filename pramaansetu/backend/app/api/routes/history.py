from fastapi import APIRouter, Depends, Query, HTTPException
from bson import ObjectId
from app.db.mongo import get_database, to_object_id
from app.core.security import get_current_user

router = APIRouter(prefix="/history", tags=["History"])

@router.get("")
async def get_verification_history(
    page: int = Query(1, ge=1),
    limit: int = Query(15, ge=1, le=100),
    institution: str = Query(None),
    status: str = Query(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    query = {}
    
    # Applicant role only views own uploads
    if current_user["role"] == "applicant":
        user_certs = await db.certificates.find({"uploaded_by": to_object_id(current_user["id"])}).to_list(length=1000)
        cert_ids = [c["_id"] for c in user_certs]
        query["certificate_id"] = {"$in": cert_ids}

    if status:
        query["classification"] = status
    if institution:
        query["extracted_data.institution"] = {"$regex": institution, "$options": "i"}

    skip = (page - 1) * limit
    total_count = await db.verification_records.count_documents(query)
    
    cursor = db.verification_records.find(query).sort("created_at", -1).skip(skip).limit(limit)
    records = await cursor.to_list(length=limit)

    results = []
    for r in records:
        cert_info = await db.certificates.find_one({"_id": r["certificate_id"]})
        results.append({
            "id": str(r["_id"]),
            "certificate_id": str(r["certificate_id"]),
            "filename": cert_info.get("original_filename") if cert_info else "Certificate Document",
            "extracted_name": r.get("extracted_data", {}).get("name"),
            "certificate_number": r.get("extracted_data", {}).get("certificate_number"),
            "institution": r.get("extracted_data", {}).get("institution"),
            "overall_score": r.get("authenticity_score", {}).get("overall_score", 0),
            "classification": r.get("classification", "Processing"),
            "created_at": r.get("created_at"),
            "completed_at": r.get("completed_at")
        })

    return {
        "page": page,
        "limit": limit,
        "total_records": total_count,
        "records": results
    }

@router.get("/duplicates/{cert_number}")
async def check_duplicate_certificate_number(
    cert_number: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    query = {"extracted_data.certificate_number": cert_number}
    records = await db.verification_records.find(query).to_list(length=50)

    findings = []
    for r in records:
        cert_info = await db.certificates.find_one({"_id": r["certificate_id"]})
        user_info = await db.users.find_one({"_id": cert_info["uploaded_by"]}) if cert_info else None
        findings.append({
            "verification_id": str(r["_id"]),
            "uploaded_by_email": user_info["email"] if user_info else "Unknown",
            "institution": r.get("extracted_data", {}).get("institution"),
            "classification": r.get("classification"),
            "created_at": r.get("created_at")
        })

    return {
        "certificate_number": cert_number,
        "total_occurrences": len(findings),
        "is_fraud_risk": len(findings) > 1,
        "occurrences": findings
    }
