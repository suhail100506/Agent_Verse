def classify_certificate(overall_score: float, stage_results: dict) -> str:
    """Stage 16: Classification (Verified, Likely Genuine, Suspicious, Likely Fake, Fake, Manual Review Required)"""
    
    ocr_res = stage_results.get("ocr")
    tpl_res = stage_results.get("template_matching")

    ocr_failed = ocr_res is not None and not ocr_res.get("raw_text", "").strip()
    tpl_unmatched = tpl_res is not None and tpl_res.get("similarity_pct", 100) < 40.0

    # Rule: Any critical stage failure (OCR completely failed AND template unmatched) -> Manual Review Required
    if ocr_failed and tpl_unmatched:
        return "Manual Review Required"

    if overall_score >= 90.0:
        return "Verified"
    elif overall_score >= 75.0:
        return "Likely Genuine"
    elif overall_score >= 50.0:
        return "Suspicious"
    elif overall_score >= 25.0:
        return "Likely Fake"
    else:
        return "Fake"
