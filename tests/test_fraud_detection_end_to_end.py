import os
import json
import unittest
from cyberverse.tools.fraud.transaction_analysis_tool import TransactionAnalysisTool
from cyberverse.tools.fraud.behavioral_analysis_tool import BehavioralAnalysisTool
from cyberverse.tools.fraud.device_fingerprint_tool import DeviceFingerprintTool
from cyberverse.tools.fraud.account_takeover_tool import AccountTakeoverTool
from cyberverse.tools.fraud.fraud_risk_tool import FraudRiskTool

class TestFraudDetectionEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tx_tool = TransactionAnalysisTool()
        self.beh_tool = BehavioralAnalysisTool()
        self.dev_tool = DeviceFingerprintTool()
        self.ato_tool = AccountTakeoverTool()
        self.risk_tool = FraudRiskTool()

    def test_end_to_end_fraud_detection_workflow(self):
        """End-to-End integration test for Fraud Detection Specialist workflow."""
        
        print("\n=== STEP 1: Executing TransactionAnalysisTool ===")
        tx_res_str = self.tx_tool._run(
            amount=4999.99,
            currency="USD",
            merchant_category="Cryptocurrency / High-Risk",
            timestamp="2026-07-29T03:15:00Z",
            payment_method="Credit Card",
            country="US"
        )
        tx_res = json.loads(tx_res_str)
        self.assertTrue(tx_res["success"])
        print(f"Transaction Risk: {tx_res['risk']}, Score: {tx_res['transaction_score']}/100")

        print("\n=== STEP 2: Executing BehavioralAnalysisTool ===")
        sample_logins = [
            {'timestamp': '2026-07-29T21:00:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:01:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:02:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:03:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:04:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:05:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:06:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T21:07:00Z', 'status': 'failed'},
            {'timestamp': '2026-07-29T03:15:00Z', 'status': 'success'}
        ]
        sample_devices = [{'device_id': 'DEV_KNOWN'}, {'device_id': 'DEV_NEW_1'}]
        sample_locations = [
            {'country': 'US', 'timestamp': '2026-07-29T20:00:00Z'},
            {'country': 'RU', 'timestamp': '2026-07-29T21:30:00Z'}
        ]

        beh_res_str = self.beh_tool._run(
            user_id="USR_99182",
            login_history=sample_logins,
            device_history=sample_devices,
            location_history=sample_locations
        )
        beh_res = json.loads(beh_res_str)
        self.assertTrue(beh_res["success"])
        print(f"Behavioral Risk: {beh_res['risk']}, Score: {beh_res['behavior_score']}/100")

        print("\n=== STEP 3: Executing DeviceFingerprintTool ===")
        dev_res_str = self.dev_tool._run(
            browser="HeadlessChrome",
            operating_system="Linux",
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/114.0.5735.198 Safari/537.36",
            screen_resolution="800x600",
            timezone="UTC",
            language="en-US",
            ip_address="198.51.100.45",
            webdriver=True
        )
        dev_res = json.loads(dev_res_str)
        self.assertTrue(dev_res["success"])
        print(f"Device Trust Score: {dev_res['device_trust_score']}/100, Fingerprint: {dev_res['fingerprint'][:16]}...")

        print("\n=== STEP 4: Executing AccountTakeoverTool ===")
        ato_res_str = self.ato_tool._run(
            account_id="ACC_9921",
            password_changed=True,
            mfa_disabled=True,
            email_changed=True,
            failed_logins=8,
            credential_stuffing=True,
            impossible_travel=True
        )
        ato_res = json.loads(ato_res_str)
        self.assertTrue(ato_res["success"])
        print(f"Account Takeover Probability: {ato_res['takeover_probability']}%, Risk: {ato_res['risk']}")

        print("\n=== STEP 5: Executing FraudRiskTool Synthesis ===")
        risk_res_str = self.risk_tool._run(
            transaction_json=tx_res_str,
            behavioral_json=beh_res_str,
            device_json=dev_res_str,
            takeover_json=ato_res_str
        )
        risk_res = json.loads(risk_res_str)
        self.assertTrue(risk_res["success"])
        print(f"Overall Fraud Risk: {risk_res['overall_risk']}")
        print(f"Fraud Score: {risk_res['fraud_score']}/100")
        print(f"Fraud Detected: {risk_res['fraud_detected']}")

        print("\n========================================================")
        print("FINAL ENTERPRISE FRAUD ASSESSMENT REPORT JSON")
        print("========================================================")
        final_report = {
            "specialist": "Fraud Detection Specialist",
            "overall_risk": risk_res["overall_risk"],
            "fraud_score": risk_res["fraud_score"],
            "confidence": risk_res["confidence"],
            "fraud_detected": risk_res["fraud_detected"],
            "dashboard": risk_res["dashboard"],
            "evidence": risk_res["evidence"],
            "recommendations": risk_res["recommendations"],
            "executive_summary": risk_res["executive_summary"]
        }
        print(json.dumps(final_report, indent=2))

if __name__ == "__main__":
    unittest.main()
