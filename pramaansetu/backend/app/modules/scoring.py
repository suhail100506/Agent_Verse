def calculate_authenticity_score(stage_results: dict) -> dict:
    """Stage 15: Authenticity Score (Weighted average with weight renormalization)"""
    
    BASE_WEIGHTS = {
        "ocr_score": 0.10,
        "qr_score": 0.15,
        "cert_number_score": 0.10,
        "template_score": 0.15,
        "logo_score": 0.10,
        "seal_score": 0.10,
        "signature_score": 0.10,
        "metadata_score": 0.10,
        "tampering_score": 0.10 # Inverted
    }

    scores = {}

    # 1. OCR Score
    ocr_res = stage_results.get("ocr", {})
    scores["ocr_score"] = float(ocr_res.get("accuracy", 0)) if ocr_res.get("passed") is not None else None

    # 2. QR Score
    qr_res = stage_results.get("qr_verification", {})
    qr_status = qr_res.get("status")
    if qr_status == "absent" or qr_res.get("error"):
        scores["qr_score"] = None # Excluded from weight calculation
    elif qr_status == "passed" or qr_res.get("match"):
        scores["qr_score"] = 100.0
    else:
        scores["qr_score"] = 0.0

    # 3. Certificate Number Validity Score
    cert_res = stage_results.get("certificate_number_verification", {})
    if cert_res.get("error"):
        scores["cert_number_score"] = None
    else:
        val_fmt = cert_res.get("valid_format", False)
        chk_pass = cert_res.get("checksum_passed", False)
        if val_fmt and chk_pass:
            scores["cert_number_score"] = 100.0
        elif val_fmt or chk_pass:
            scores["cert_number_score"] = 50.0
        else:
            scores["cert_number_score"] = 0.0

    # 4. Template Match Score
    tpl_res = stage_results.get("template_matching", {})
    scores["template_score"] = float(tpl_res.get("similarity_pct", 0)) if tpl_res.get("similarity_pct") is not None else None

    # 5. Logo Score
    logo_res = stage_results.get("logo_verification", {})
    if logo_res.get("error"):
        scores["logo_score"] = None
    else:
        scores["logo_score"] = float(logo_res.get("match_pct", 0))

    # 6. Seal Score
    seal_res = stage_results.get("seal_verification", {})
    if seal_res.get("error"):
        scores["seal_score"] = None
    else:
        scores["seal_score"] = float(seal_res.get("confidence_pct", 0))

    # 7. Signature Score
    sig_res = stage_results.get("signature_verification", {})
    if sig_res.get("error"):
        scores["signature_score"] = None
    elif sig_res.get("present"):
        scores["signature_score"] = 100.0 if sig_res.get("type") == "digital" else 85.0
    else:
        scores["signature_score"] = 0.0

    # 8. Metadata Score
    meta_res = stage_results.get("metadata_analysis", {})
    if meta_res.get("error"):
        scores["metadata_score"] = None
    elif meta_res.get("risk_flag"):
        scores["metadata_score"] = 30.0
    else:
        scores["metadata_score"] = 100.0

    # 9. Tampering Score (Inverted: score = 100 - tampering_level)
    tamp_res = stage_results.get("tampering_detection", {})
    if tamp_res.get("error"):
        scores["tampering_score"] = None
    else:
        raw_tampering = float(tamp_res.get("score", 0))
        scores["tampering_score"] = max(0.0, 100.0 - raw_tampering)

    # Renormalize active weights
    active_weight_sum = 0.0
    weighted_score_sum = 0.0

    for key, weight in BASE_WEIGHTS.items():
        val = scores.get(key)
        if val is not None:
            active_weight_sum += weight
            weighted_score_sum += val * weight

    if active_weight_sum > 0:
        overall_score = round(weighted_score_sum / active_weight_sum, 2)
    else:
        overall_score = 0.0

    return {
        "ocr_score": scores["ocr_score"],
        "qr_score": scores["qr_score"],
        "cert_number_score": scores["cert_number_score"],
        "template_score": scores["template_score"],
        "logo_score": scores["logo_score"],
        "seal_score": scores["seal_score"],
        "signature_score": scores["signature_score"],
        "metadata_score": scores["metadata_score"],
        "tampering_score": scores["tampering_score"],
        "overall_score": overall_score
    }
