import os
import logging
from datetime import datetime
from bson import ObjectId

from app.config import settings

# Stage Modules
from app.modules import (
    upload_validation,
    preprocessing,
    ocr,
    info_extraction,
    qr_verification,
    cert_number_verification,
    template_matching,
    logo_verification,
    seal_verification,
    signature_verification,
    metadata_analysis,
    tampering_detection,
    authority_verification,
    llm_reasoning,
    scoring,
    classification,
    recommendation,
    report_generation
)

logger = logging.getLogger(__name__)

from app.db.mongo import to_object_id

async def run_verification_pipeline(verification_id: str, db=None) -> dict:
    """Orchestrates all 18 verification stages with failure isolation & live database updates."""
    
    if db is None:
        from app.db.mongo import get_database
        db = get_database()

    # 1. Fetch Verification Record & Certificate
    rec_obj_id = to_object_id(verification_id)
    verification_doc = await db.verification_records.find_one({"_id": rec_obj_id})
    if not verification_doc:
        raise ValueError(f"Verification record {verification_id} not found.")

    cert_doc = await db.certificates.find_one({"_id": to_object_id(verification_doc["certificate_id"])})
    if not cert_doc:
        raise ValueError(f"Certificate {verification_doc['certificate_id']} not found.")

    file_path = cert_doc["storage_path"]
    temp_dir = os.path.join(settings.UPLOAD_DIR, "temp", str(verification_id))
    os.makedirs(temp_dir, exist_ok=True)

    stage_results = {}

    async def update_progress(stage_name: str, pct: int):
        await db.verification_records.update_one(
            {"_id": rec_obj_id},
            {"$set": {"current_stage": stage_name, "stage_progress_pct": pct}}
        )

    # --- STAGE 1: File Validation ---
    await update_progress("File Validation", 5)
    try:
        stage_results["file_validation"] = upload_validation.validate_file(file_path, settings.MAX_UPLOAD_SIZE_MB)
    except Exception as e:
        logger.error(f"Stage 1 error: {e}")
        stage_results["file_validation"] = {"passed": False, "error": str(e)}

    # --- STAGE 2: Image Preprocessing ---
    await update_progress("Image Preprocessing", 10)
    preprocessed_path = file_path
    try:
        res2 = preprocessing.preprocess_image(file_path, temp_dir)
        stage_results["preprocessing"] = res2
        preprocessed_path = res2.get("preprocessed_path", file_path)
    except Exception as e:
        logger.error(f"Stage 2 error: {e}")
        stage_results["preprocessing"] = {"passed": False, "error": str(e)}

    # --- STAGE 3: OCR ---
    await update_progress("OCR Text Extraction", 18)
    ocr_raw_text = ""
    try:
        res3 = ocr.run_ocr(preprocessed_path, file_path if file_path.lower().endswith(".pdf") else None)
        stage_results["ocr"] = res3
        ocr_raw_text = res3.get("raw_text", "")
    except Exception as e:
        logger.error(f"Stage 3 error: {e}")
        stage_results["ocr"] = {"passed": False, "error": str(e), "accuracy": 0, "raw_text": ""}

    # --- STAGE 4: Information Parsing ---
    await update_progress("Information Parsing", 25)
    extracted_data = {}
    try:
        res4 = info_extraction.parse_information(ocr_raw_text)
        stage_results["info_parsing"] = res4
        extracted_data = res4.get("extracted_data", {})
    except Exception as e:
        logger.error(f"Stage 4 error: {e}")
        stage_results["info_parsing"] = {"passed": False, "error": str(e)}

    # Save initial parsed data to MongoDB
    await db.verification_records.update_one(
        {"_id": rec_obj_id},
        {"$set": {"extracted_data": extracted_data}}
    )

    # --- STAGE 5: QR Code Verification ---
    await update_progress("QR Code Verification", 32)
    try:
        stage_results["qr_verification"] = qr_verification.verify_qr_code(preprocessed_path, extracted_data)
    except Exception as e:
        logger.error(f"Stage 5 error: {e}")
        stage_results["qr_verification"] = {"status": "absent", "error": str(e), "match": False}

    # --- STAGE 6: Certificate Number Verification ---
    await update_progress("Certificate Number Verification", 38)
    try:
        cert_no = extracted_data.get("certificate_number")
        inst = extracted_data.get("institution")
        stage_results["certificate_number_verification"] = cert_number_verification.verify_certificate_number(cert_no, inst)
    except Exception as e:
        logger.error(f"Stage 6 error: {e}")
        stage_results["certificate_number_verification"] = {"valid_format": False, "checksum_passed": False, "error": str(e)}

    # --- STAGE 7: Template Matching ---
    await update_progress("Template Matching", 45)
    try:
        tpl_cursor = db.template_library.find({})
        template_list = await tpl_cursor.to_list(length=50)
        stage_results["template_matching"] = template_matching.match_template(
            preprocessed_path,
            template_list,
            extracted_data.get("institution")
        )
    except Exception as e:
        logger.error(f"Stage 7 error: {e}")
        stage_results["template_matching"] = {"institution_matched": None, "similarity_pct": 0, "error": str(e)}

    # --- STAGE 8: Logo Verification ---
    await update_progress("Logo Verification", 52)
    try:
        stage_results["logo_verification"] = logo_verification.verify_logo(preprocessed_path)
    except Exception as e:
        logger.error(f"Stage 8 error: {e}")
        stage_results["logo_verification"] = {"match_pct": 0, "error": str(e)}

    # --- STAGE 9: Seal Verification ---
    await update_progress("Seal Verification", 58)
    try:
        stage_results["seal_verification"] = seal_verification.verify_seal(preprocessed_path)
    except Exception as e:
        logger.error(f"Stage 9 error: {e}")
        stage_results["seal_verification"] = {"confidence_pct": 0, "error": str(e)}

    # --- STAGE 10: Signature Verification ---
    await update_progress("Signature Verification", 64)
    try:
        stage_results["signature_verification"] = signature_verification.verify_signature(
            preprocessed_path,
            file_path if file_path.lower().endswith(".pdf") else None
        )
    except Exception as e:
        logger.error(f"Stage 10 error: {e}")
        stage_results["signature_verification"] = {"present": False, "error": str(e)}

    # --- STAGE 11: Metadata Analysis ---
    await update_progress("Metadata Analysis", 70)
    try:
        stage_results["metadata_analysis"] = metadata_analysis.analyze_metadata(file_path)
    except Exception as e:
        logger.error(f"Stage 11 error: {e}")
        stage_results["metadata_analysis"] = {"risk_flag": False, "error": str(e)}

    # --- STAGE 12: Tampering Detection ---
    await update_progress("Tampering Detection", 76)
    try:
        stage_results["tampering_detection"] = tampering_detection.detect_tampering(preprocessed_path, temp_dir)
    except Exception as e:
        logger.error(f"Stage 12 error: {e}")
        stage_results["tampering_detection"] = {"score": 0, "indicators_found": [], "error": str(e)}

    # --- STAGE 13: Authority Verification ---
    await update_progress("Issuing Authority Verification", 82)
    try:
        stage_results["authority_verification"] = await authority_verification.verify_issuing_authority(extracted_data, db)
    except Exception as e:
        logger.error(f"Stage 13 error: {e}")
        stage_results["authority_verification"] = {"method": "unavailable", "verified": None, "error": str(e)}

    # --- STAGE 15: Scoring Calculation (Computed before LLM reasoning for context) ---
    score_obj = scoring.calculate_authenticity_score(stage_results)
    overall_score = score_obj["overall_score"]

    # --- STAGE 14: AI Reasoning ---
    await update_progress("AI Reasoning Analysis", 88)
    ai_reasoning_text = ""
    try:
        ai_reasoning_text = await llm_reasoning.generate_ai_reasoning(stage_results, extracted_data, overall_score)
    except Exception as e:
        logger.error(f"Stage 14 error: {e}")
        ai_reasoning_text = f"Forensic reasoning generator encountered an issue: {str(e)}."

    # --- STAGE 16: Classification ---
    await update_progress("Classification Assignment", 92)
    final_classification = classification.classify_certificate(overall_score, stage_results)

    # --- STAGE 17: Recommendation ---
    await update_progress("Recommendation Generation", 95)
    final_recommendation = recommendation.generate_recommendation(final_classification, stage_results)

    # --- STAGE 18: Final Report PDF Generation ---
    await update_progress("Generating PDF Report", 98)
    part_doc = {
        "_id": str(rec_obj_id),
        "classification": final_classification,
        "authenticity_score": score_obj,
        "extracted_data": extracted_data,
        "ai_reasoning": ai_reasoning_text,
        "recommendation": final_recommendation,
        "stage_results": stage_results
    }
    
    report_pdf_path = ""
    try:
        report_pdf_path = report_generation.generate_pdf_report(part_doc, settings.REPORT_DIR)
    except Exception as e:
        logger.error(f"Stage 18 report generation error: {e}")

    # Final DB Update
    completion_time = datetime.utcnow()
    await db.verification_records.update_one(
        {"_id": rec_obj_id},
        {
            "$set": {
                "status": "completed",
                "current_stage": "Completed",
                "stage_progress_pct": 100,
                "stage_results": stage_results,
                "authenticity_score": score_obj,
                "classification": final_classification,
                "ai_reasoning": ai_reasoning_text,
                "recommendation": final_recommendation,
                "report_pdf_path": report_pdf_path,
                "completed_at": completion_time
            }
        }
    )

    # Cleanup temporary preprocessing files
    try:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

    return await db.verification_records.find_one({"_id": rec_obj_id})
