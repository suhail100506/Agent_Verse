import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.modules import (
    upload_validation, preprocessing, ocr, info_extraction,
    qr_verification, cert_number_verification, template_matching,
    logo_verification, seal_verification, signature_verification,
    metadata_analysis, tampering_detection, authority_verification,
    llm_reasoning, scoring, classification, recommendation, report_generation
)
from app.config import settings

async def run_e2e_test():
    sample_img_path = os.path.abspath("backend/uploads/sample_anna_univ_cert.png")
    temp_dir = os.path.abspath("backend/uploads/temp/e2e_test")
    os.makedirs(temp_dir, exist_ok=True)

    print("--- Executing 18-Stage Forensic Pipeline E2E Test ---")

    # 1. Validation
    res1 = upload_validation.validate_file(sample_img_path)
    print(f"Stage 1 (File Validation): {res1['passed']} (SHA256: {res1['file_hash'][:12]}...)")

    # 2. Preprocessing
    res2 = preprocessing.preprocess_image(sample_img_path, temp_dir)
    print(f"Stage 2 (Preprocessing): {res2['passed']} (Deskew Angle: {res2.get('deskew_angle')}°)")

    # 3. OCR
    preprocessed_path = res2["preprocessed_path"]
    res3 = ocr.run_ocr(preprocessed_path)
    print(f"Stage 3 (OCR): Accuracy {res3['accuracy']}%")

    # 4. Info Parsing
    res4 = info_extraction.parse_information(res3["raw_text"])
    ext_data = res4["extracted_data"]
    print(f"Stage 4 (Parsed Info): Name='{ext_data['name']}', CertNo='{ext_data['certificate_number']}', Inst='{ext_data['institution']}'")

    # 5. QR Code
    res5 = qr_verification.verify_qr_code(preprocessed_path, ext_data)
    print(f"Stage 5 (QR Code): Status={res5['status']}")

    # 6. Cert No Verification
    res6 = cert_number_verification.verify_certificate_number(ext_data["certificate_number"], ext_data["institution"])
    print(f"Stage 6 (Cert No Format): Valid={res6['valid_format']}, Checksum={res6['checksum_passed']}")

    # 7. Template Matching
    dummy_templates = [
        {"institution_name": "Anna University", "reference_logo_path": "", "reference_seal_path": "", "layout_coordinates": {}}
    ]
    res7 = template_matching.match_template(preprocessed_path, dummy_templates, ext_data["institution"])
    print(f"Stage 7 (Template Match): Inst={res7['institution_matched']}, Similarity={res7['similarity_pct']}%")

    # 8. Logo Verification
    res8 = logo_verification.verify_logo(preprocessed_path)
    print(f"Stage 8 (Logo Verification): Match={res8['match_pct']}%")

    # 9. Seal Verification
    res9 = seal_verification.verify_seal(preprocessed_path)
    print(f"Stage 9 (Seal Verification): Confidence={res9['confidence_pct']}%")

    # 10. Signature Verification
    res10 = signature_verification.verify_signature(preprocessed_path)
    print(f"Stage 10 (Signature Verification): Present={res10['present']} ({res10['type']})")

    # 11. Metadata Analysis
    res11 = metadata_analysis.analyze_metadata(sample_img_path)
    print(f"Stage 11 (Metadata Analysis): Risk Flag={res11['risk_flag']}")

    # 12. Tampering Detection
    res12 = tampering_detection.detect_tampering(preprocessed_path, temp_dir)
    print(f"Stage 12 (Tampering Detection): Score={res12['score']}")

    # 13. Authority Verification
    res13 = await authority_verification.verify_issuing_authority(ext_data, None)
    print(f"Stage 13 (Authority Verification): Verified={res13['verified']} ({res13['method']})")

    stage_results = {
        "file_validation": res1,
        "preprocessing": res2,
        "ocr": res3,
        "info_parsing": res4,
        "qr_verification": res5,
        "certificate_number_verification": res6,
        "template_matching": res7,
        "logo_verification": res8,
        "seal_verification": res9,
        "signature_verification": res10,
        "metadata_analysis": res11,
        "tampering_detection": res12,
        "authority_verification": res13
    }

    # 15. Scoring
    score_obj = scoring.calculate_authenticity_score(stage_results)
    print(f"Stage 15 (Authenticity Score): Overall={score_obj['overall_score']}%")

    # 14. AI Reasoning
    reasoning_text = await llm_reasoning.generate_ai_reasoning(stage_results, ext_data, score_obj['overall_score'])
    print(f"Stage 14 (AI Reasoning): {reasoning_text[:120]}...")

    # 16. Classification
    verdict = classification.classify_certificate(score_obj['overall_score'], stage_results)
    print(f"Stage 16 (Classification): {verdict}")

    # 17. Recommendation
    rec = recommendation.generate_recommendation(verdict, stage_results)
    print(f"Stage 17 (Recommendation): {rec[:100]}...")

    # 18. Report PDF Generation
    part_doc = {
        "_id": "E2E-TEST-001",
        "classification": verdict,
        "authenticity_score": score_obj,
        "extracted_data": ext_data,
        "ai_reasoning": reasoning_text,
        "recommendation": rec,
        "stage_results": stage_results
    }
    pdf_path = report_generation.generate_pdf_report(part_doc, settings.REPORT_DIR)
    print(f"Stage 18 (PDF Report Generation): Generated at '{pdf_path}' (Exists={os.path.exists(pdf_path)})")

    print("\n--- E2E TEST COMPLETED SUCCESSFULLY! ---")

if __name__ == "__main__":
    asyncio.run(run_e2e_test())
