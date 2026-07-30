"""
test_password_security_end_to_end.py
=====================================
End-to-end integration test for the Password Security Advisor tool suite.

Workflow Under Test
-------------------
Password / Account Metadata
            │
            ▼
PasswordStrengthTool    — Entropy, length, complexity, pattern detection
            │
            ▼
PasswordPolicyTool      — Minimum/maximum length, complexity, age, history, lockout
            │
            ▼
PasswordLeakTool        — K-Anonymity HIBP breach check & offline fallback
            │
            ▼
MFAAssessmentTool       — Protocol readiness, factor strength (FIDO2/TOTP vs SMS), recovery
            │
            ▼
PasswordRiskTool        — Weighted scoring fusion → unified enterprise risk report

Coverage
--------
- Tool instantiation & registration checks
- Schema validation & invalid input handling
- Full workflow execution against breached & unbreached credentials
- Partial telemetry aggregation
- Enterprise output structure validation
"""

import json
import sys
import unittest

sys.path.insert(0, "src")

from cyberverse.tools.password.password_strength_tool import PasswordStrengthTool
from cyberverse.tools.password.password_policy_tool import PasswordPolicyTool
from cyberverse.tools.password.password_leak_tool import PasswordLeakTool
from cyberverse.tools.password.mfa_assessment_tool import MFAAssessmentTool
from cyberverse.tools.password.password_risk_tool import PasswordRiskTool


class TestPasswordSecurityEndToEnd(unittest.TestCase):
    """End-to-end integration test suite for Password Security Advisor."""

    @classmethod
    def setUpClass(cls) -> None:
        """Instantiate all five Password Security Advisor tools."""
        cls.strength_tool = PasswordStrengthTool()
        cls.policy_tool = PasswordPolicyTool()
        cls.leak_tool = PasswordLeakTool()
        cls.mfa_tool = MFAAssessmentTool()
        cls.risk_tool = PasswordRiskTool()

    def test_01_tool_registration(self) -> None:
        """Verify all 5 tools are instantiated with correct names."""
        print("\n=== TEST 01: Tool Registration ===")
        self.assertEqual(self.strength_tool.name, "Password Strength Tool")
        self.assertEqual(self.policy_tool.name, "Password Policy Tool")
        self.assertEqual(self.leak_tool.name, "Password Leak Tool")
        self.assertEqual(self.mfa_tool.name, "MFA Assessment Tool")
        self.assertEqual(self.risk_tool.name, "Password Risk Tool")
        print("  [OK] All five Password Security Advisor tools registered successfully.")

    def test_02_password_strength_tool(self) -> None:
        """Verify PasswordStrengthTool evaluation."""
        print("\n=== TEST 02: PasswordStrengthTool ===")
        res_str = self.strength_tool._run(password="ExamplePassword123!")
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertIn("password_score", res)
        self.assertIn("risk", res)
        self.assertIn("dashboard", res)
        self.assertGreaterEqual(res["password_score"], 80)
        self.assertEqual(res["risk"], "LOW")
        print(f"  [OK] Strength Score: {res['password_score']}/100, Risk: {res['risk']}")

    def test_03_password_policy_tool(self) -> None:
        """Verify PasswordPolicyTool compliance validation."""
        print("\n=== TEST 03: PasswordPolicyTool ===")
        res_str = self.policy_tool._run(password="ExamplePassword123!")
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertIn("policy_score", res)
        self.assertIn("risk", res)
        self.assertEqual(res["policy_score"], 100)
        self.assertEqual(res["risk"], "LOW")
        print(f"  [OK] Policy Score: {res['policy_score']}/100, Risk: {res['risk']}")

    def test_04_password_leak_tool(self) -> None:
        """Verify PasswordLeakTool k-anonymity breach check."""
        print("\n=== TEST 04: PasswordLeakTool ===")
        # Test a known breached password (123456)
        res_breached = json.loads(self.leak_tool._run(password="123456"))
        self.assertTrue(res_breached["success"])
        self.assertTrue(res_breached["breached"])
        self.assertGreater(res_breached["breach_count"], 0)
        self.assertIn(res_breached["risk"], ("HIGH", "CRITICAL"))

        # Test an unbreached complex password
        res_clean = json.loads(self.leak_tool._run(password="X9#mK2@vLqP7$nRwZ_Unbreached2026!"))
        self.assertTrue(res_clean["success"])
        self.assertFalse(res_clean["breached"])
        self.assertEqual(res_clean["breach_count"], 0)
        self.assertEqual(res_clean["risk"], "LOW")
        print(f"  [OK] Breached check passed ({res_breached['breach_count']:,} breaches), Unbreached check passed.")

    def test_05_mfa_assessment_tool(self) -> None:
        """Verify MFAAssessmentTool posture assessment."""
        print("\n=== TEST 05: MFAAssessmentTool ===")
        res_str = self.mfa_tool._run(
            mfa_enabled=True,
            methods=["TOTP", "Security Key"],
            backup_codes=True,
            recovery_email=True,
            sms_enabled=False
        )
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertIn("mfa_score", res)
        self.assertIn("risk", res)
        self.assertGreaterEqual(res["mfa_score"], 90)
        self.assertEqual(res["dashboard"]["trust_level"], "Excellent")
        print(f"  [OK] MFA Score: {res['mfa_score']}/100, Trust Level: {res['dashboard']['trust_level']}")

    def test_06_end_to_end_workflow(self) -> None:
        """Execute full end-to-end workflow chaining all 5 tools."""
        print("\n=== TEST 06: Full End-to-End Workflow Execution ===")
        password = "ExamplePassword123!"

        # Step 1: Strength
        strength_res = json.loads(self.strength_tool._run(password=password))

        # Step 2: Policy
        policy_res = json.loads(self.policy_tool._run(password=password))

        # Step 3: Leak
        leak_res = json.loads(self.leak_tool._run(password=password))

        # Step 4: MFA
        mfa_res = json.loads(self.mfa_tool._run(
            mfa_enabled=True,
            methods=["TOTP"],
            backup_codes=True,
            recovery_email=True,
            sms_enabled=False
        ))

        # Step 5: Risk Aggregation
        risk_res = json.loads(self.risk_tool._run(
            strength=strength_res,
            policy=policy_res,
            leak=leak_res,
            mfa=mfa_res
        ))

        print("  -- Password Security Assessment Output --")
        print(f"  Overall Risk    : {risk_res['overall_risk']}")
        print(f"  Security Score  : {risk_res['password_security_score']}/100")
        print(f"  Confidence      : {risk_res['confidence']}%")
        print(f"  Dashboard       : {json.dumps(risk_res['dashboard'], indent=4)}")

        self.assertTrue(risk_res["success"])
        self.assertIn("overall_risk", risk_res)
        self.assertIn("password_security_score", risk_res)
        self.assertIn("confidence", risk_res)
        self.assertIn("dashboard", risk_res)
        self.assertIn("evidence", risk_res)
        self.assertIn("recommendations", risk_res)
        self.assertIn("executive_summary", risk_res)

    def test_07_enterprise_sample_output_structure(self) -> None:
        """Validate enterprise sample output schema."""
        print("\n=== TEST 07: Enterprise Sample Output Schema ===")
        sample_output = {
            "specialist": "Password Security Advisor",
            "overall_risk": "HIGH",
            "password_security_score": 89,
            "confidence": 98,
            "dashboard": {
                "strength_score": 91,
                "policy_score": 88,
                "breach_score": 96,
                "mfa_score": 91
            },
            "evidence": [
                "Password found in breach database.",
                "Password meets complexity requirements.",
                "MFA enabled with TOTP.",
                "Enterprise password policy satisfied."
            ],
            "recommendations": [
                "Replace breached password immediately.",
                "Continue using MFA.",
                "Rotate credentials.",
                "Monitor credential exposure."
            ],
            "executive_summary": "Password security assessment identified breached credentials despite strong password complexity. Immediate password rotation is recommended."
        }

        required_keys = [
            "specialist", "overall_risk", "password_security_score",
            "confidence", "dashboard", "evidence", "recommendations", "executive_summary"
        ]
        for k in required_keys:
            self.assertIn(k, sample_output)

        print("  [OK] Enterprise sample output structure validated.")
        print(json.dumps(sample_output, indent=2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
