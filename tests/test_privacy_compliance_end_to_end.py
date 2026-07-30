import os
import json
import unittest
from cyberverse.tools.privacy.pii_detection_tool import PIIDetectionTool
from cyberverse.tools.privacy.secret_scanner_tool import SecretScannerTool
from cyberverse.tools.privacy.compliance_tool import ComplianceTool
from cyberverse.tools.privacy.privacy_risk_tool import PrivacyRiskTool

class TestPrivacyComplianceEndToEnd(unittest.TestCase):
    def setUp(self):
        self.pii_tool = PIIDetectionTool()
        self.secret_tool = SecretScannerTool()
        self.compliance_tool = ComplianceTool()
        self.privacy_risk_tool = PrivacyRiskTool()

    def test_end_to_end_privacy_workflow(self):
        """End-to-End integration test for Privacy Compliance Analyst workflow."""
        test_payload = """
        # Enterprise User & Server Configuration Dump
        User Name: Alice Johnson
        Email Address: alice.johnson@cybercorp.com
        Contact Phone: +1 (555) 234-5678
        Indian Aadhaar Card: 3829 4810 5928
        Indian PAN Card: ABCDE1234F

        # Exposed Application API Keys & DB Strings
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        OPENAI_API_KEY=sk-proj-6_27679-xPKyZdJqVZHtAUw6bVw0NkGLy6Ymm85m_wo93AeW
        DATABASE_URL=mongodb+srv://admin:SuperSecretPass123@prod-cluster.mongodb.net/production
        """

        print("\n=== STEP 1: Executing PIIDetectionTool ===")
        pii_res_str = self.pii_tool._run(text_content=test_payload)
        pii_res = json.loads(pii_res_str)
        self.assertTrue(pii_res["success"])
        self.assertGreaterEqual(len(pii_res["entities"]), 4)
        print(f"Detected PII Count: {len(pii_res['entities'])}")

        print("\n=== STEP 2: Executing SecretScannerTool ===")
        secret_res_str = self.secret_tool._run(text=test_payload)
        secret_res = json.loads(secret_res_str)
        self.assertTrue(secret_res["success"])
        self.assertGreaterEqual(len(secret_res["findings"]), 4)
        print(f"Exposed Secrets Count: {len(secret_res['findings'])}")
        print(f"Secret Scanner Risk Score: {secret_res['risk_score']}")

        print("\n=== STEP 3: Executing ComplianceTool ===")
        compliance_res_str = self.compliance_tool._run(pii_json=pii_res_str, secret_json=secret_res_str)
        compliance_res = json.loads(compliance_res_str)
        self.assertTrue(compliance_res["success"])
        self.assertEqual(len(compliance_res["frameworks"]), 7)
        print(f"Overall Compliance Score: {compliance_res['overall_score']}")
        print(f"Overall Compliance Status: {compliance_res['overall_status']}")
        print(f"Total Framework Violations: {len(compliance_res['violations'])}")

        print("\n=== STEP 4: Executing PrivacyRiskTool Synthesis ===")
        risk_res_str = self.privacy_risk_tool._run(
            pii_json=pii_res_str,
            secret_json=secret_res_str,
            compliance_json=compliance_res_str
        )
        risk_res = json.loads(risk_res_str)
        self.assertTrue(risk_res["success"])
        self.assertIn(risk_res["overall_risk"], ["HIGH", "CRITICAL"])
        self.assertEqual(risk_res["compliance_readiness"], "NOT_READY")
        self.assertEqual(risk_res["dashboard"]["pii_count"], len(pii_res["entities"]))
        self.assertEqual(risk_res["dashboard"]["secret_count"], len(secret_res["findings"]))

        print("\n========================================================")
        print("FINAL PRIVACY COMPLIANCE ANALYST REPORT JSON")
        print("========================================================")
        final_report = {
            "specialist": "Privacy Compliance Analyst",
            "assessment_status": risk_res["compliance_readiness"],
            "overall_risk": risk_res["overall_risk"],
            "risk_score": risk_res["risk_score"],
            "privacy_score": risk_res["privacy_score"],
            "data_exposure": risk_res["data_exposure"],
            "critical_findings": risk_res["critical_findings"],
            "dashboard": risk_res["dashboard"],
            "executive_summary": risk_res["executive_summary"],
            "recommendations": risk_res["recommendations"],
            "regulatory_frameworks": compliance_res["frameworks"],
            "violations_sample": compliance_res["violations"][:3]
        }
        print(json.dumps(final_report, indent=2))

if __name__ == "__main__":
    unittest.main()
