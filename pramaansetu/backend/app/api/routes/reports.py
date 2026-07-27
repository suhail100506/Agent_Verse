import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from app.db.mongo import get_database, to_object_id

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/{id}/download")
async def download_pdf_report(id: str, db=Depends(get_database)):
    try:
        verif = await db.verification_records.find_one({"_id": to_object_id(id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verification ID format")

    if not verif:
        raise HTTPException(status_code=404, detail="Verification record not found")

    pdf_path = verif.get("report_pdf_path")
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not yet generated or available.")

    filename = f"PramaanSetu_Audit_Report_{id}.pdf"
    return FileResponse(
        path=pdf_path,
        filename=filename,
        media_type="application/pdf"
    )
