import pytest
import os
from app.modules.scoring import calculate_authenticity_score
from app.modules.classification import classify_certificate
from app.modules.info_extraction import parse_information

def test_parse_information_anna_university():
    raw_text = """
    ANNA UNIVERSITY
    CHENNAI - 600 025
    This is to certify that SATHISH KUMAR R
    has qualified for the Degree of BACHELOR OF ENGINEERING
    in COMPUTER SCIENCE AND ENGINEERING
    Certificate No: AU12345678
    Date: 12-MAY-2024
    CGPA: 8.95
    """
    res = parse_information(raw_text)
    assert res["passed"] is True
    data = res["extracted_data"]
    assert data["certificate_number"] == "AU12345678"
    assert data["institution"] == "Anna University"
    assert "BACHELOR OF ENGINEERING" in data["course"].upper() or "COMPUTER SCIENCE" in data["course"].upper()

def test_score_renormalization_null_qr():
    # Test that when QR score is None (absent), weights sum up and renormalize properly
    stage_results = {
        "ocr": {"passed": True, "accuracy": 90.0},
        "qr_verification": {"status": "absent", "error": None}, # null score
        "certificate_number_verification": {"valid_format": True, "checksum_passed": True},
        "template_matching": {"similarity_pct": 85.0},
        "logo_verification": {"match_pct": 80.0},
        "seal_verification": {"confidence_pct": 90.0},
        "signature_verification": {"present": True, "type": "digital"},
        "metadata_analysis": {"risk_flag": False},
        "tampering_detection": {"score": 5.0} # inverted -> 95
    }
    
    scores = calculate_authenticity_score(stage_results)
    assert scores["qr_score"] is None
    assert scores["overall_score"] >= 85.0

def test_classification_thresholds():
    assert classify_certificate(92.5, {}) == "Verified"
    assert classify_certificate(80.0, {}) == "Likely Genuine"
    assert classify_certificate(60.0, {}) == "Suspicious"
    assert classify_certificate(35.0, {}) == "Likely Fake"
    assert classify_certificate(15.0, {}) == "Fake"

def test_critical_failure_triggers_manual_review():
    # If OCR completely fails AND template is unmatched -> Manual Review Required regardless of numeric score
    stage_results = {
        "ocr": {"raw_text": ""},
        "template_matching": {"similarity_pct": 20.0}
    }
    verdict = classify_certificate(80.0, stage_results)
    assert verdict == "Manual Review Required"
