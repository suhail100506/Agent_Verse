import sys
import os
import unittest

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.modules.scoring import calculate_authenticity_score
from app.modules.classification import classify_certificate
from app.modules.info_extraction import parse_information

class TestPramaanSetuPipeline(unittest.TestCase):

    def test_parse_information_anna_university(self):
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
        self.assertTrue(res["passed"])
        data = res["extracted_data"]
        self.assertEqual(data["certificate_number"], "AU12345678")
        self.assertEqual(data["institution"], "Anna University")

    def test_score_renormalization_null_qr(self):
        stage_results = {
            "ocr": {"passed": True, "accuracy": 90.0},
            "qr_verification": {"status": "absent", "error": None},
            "certificate_number_verification": {"valid_format": True, "checksum_passed": True},
            "template_matching": {"similarity_pct": 85.0},
            "logo_verification": {"match_pct": 80.0},
            "seal_verification": {"confidence_pct": 90.0},
            "signature_verification": {"present": True, "type": "digital"},
            "metadata_analysis": {"risk_flag": False},
            "tampering_detection": {"score": 5.0}
        }
        
        scores = calculate_authenticity_score(stage_results)
        self.assertIsNone(scores["qr_score"])
        self.assertGreaterEqual(scores["overall_score"], 85.0)

    def test_classification_thresholds(self):
        self.assertEqual(classify_certificate(92.5, {}), "Verified")
        self.assertEqual(classify_certificate(80.0, {}), "Likely Genuine")
        self.assertEqual(classify_certificate(60.0, {}), "Suspicious")
        self.assertEqual(classify_certificate(35.0, {}), "Likely Fake")
        self.assertEqual(classify_certificate(15.0, {}), "Fake")

    def test_critical_failure_triggers_manual_review(self):
        stage_results = {
            "ocr": {"raw_text": ""},
            "template_matching": {"similarity_pct": 20.0}
        }
        verdict = classify_certificate(80.0, stage_results)
        self.assertEqual(verdict, "Manual Review Required")

if __name__ == "__main__":
    unittest.main()
