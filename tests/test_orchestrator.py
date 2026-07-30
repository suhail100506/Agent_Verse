"""
test_orchestrator.py — Unit tests for the CyberVerse Multi-Agent Orchestrator
==============================================================================
Tests the orchestration layer without invoking any LLMs.
All specialist tools run in rule-based mode (no API calls).
"""

import sys
import json
import unittest

sys.path.insert(0, "src")

from cyberverse.orchestrator.models import (
    SecurityAnalysisRequest,
    AVAILABLE_SPECIALISTS,
)
from cyberverse.orchestrator.risk_calculator import calculate_platform_risk
from cyberverse.orchestrator.models import SpecialistResult
from cyberverse.orchestrator.specialist_registry import run_specialist, DISPLAY_NAMES


class TestModels(unittest.TestCase):
    """Test Pydantic model behaviour."""

    def test_01_security_analysis_request_defaults_to_all(self):
        req = SecurityAnalysisRequest()
        specialists = req.resolved_specialists()
        self.assertEqual(len(specialists), len(AVAILABLE_SPECIALISTS))
        self.assertIn("password_security_advisor", specialists)

    def test_02_security_analysis_request_filters_unknown(self):
        req = SecurityAnalysisRequest(specialists=["password_security_advisor", "nonexistent_tool"])
        specialists = req.resolved_specialists()
        self.assertIn("password_security_advisor", specialists)
        self.assertNotIn("nonexistent_tool", specialists)

    def test_03_security_analysis_request_deduplicates(self):
        req = SecurityAnalysisRequest(
            specialists=["password_security_advisor", "password_security_advisor"]
        )
        self.assertEqual(len(req.resolved_specialists()), 1)

    def test_04_specialist_result_defaults(self):
        result = SpecialistResult(
            specialist="password_security_advisor",
            display_name="Password Security Advisor",
        )
        self.assertTrue(result.success)
        result2 = SpecialistResult(
            specialist="test",
            display_name="Test",
            success=False,
            score=80,
        )
        self.assertFalse(result2.success)
        self.assertEqual(result2.score, 80)


class TestRiskCalculator(unittest.TestCase):
    """Test the platform risk aggregation logic."""

    def _make_result(self, specialist: str, score: int, risk: str) -> SpecialistResult:
        return SpecialistResult(
            specialist=specialist,
            display_name=DISPLAY_NAMES.get(specialist, specialist),
            success=True,
            score=score,
            risk_level=risk,
            confidence=90,
        )

    def test_05_empty_results_returns_unknown(self):
        risk = calculate_platform_risk([])
        self.assertEqual(risk.overall_risk, "UNKNOWN")
        self.assertEqual(risk.overall_score, 0)

    def test_06_all_failed_returns_unknown(self):
        results = [
            SpecialistResult(specialist="x", display_name="X", success=False, risk_level="UNKNOWN")
        ]
        risk = calculate_platform_risk(results)
        self.assertEqual(risk.overall_risk, "UNKNOWN")
        self.assertEqual(risk.specialists_succeeded, 0)

    def test_07_single_low_risk(self):
        results = [self._make_result("password_security_advisor", 10, "LOW")]
        risk = calculate_platform_risk(results)
        self.assertEqual(risk.overall_risk, "LOW")
        self.assertEqual(risk.specialists_run, 1)
        self.assertEqual(risk.specialists_succeeded, 1)

    def test_08_single_critical(self):
        results = [self._make_result("incident_response_specialist", 95, "CRITICAL")]
        risk = calculate_platform_risk(results)
        self.assertIn(risk.overall_risk, ("HIGH", "CRITICAL"))
        self.assertEqual(risk.critical_count, 1)

    def test_09_mixed_results_escalation(self):
        results = [
            self._make_result("malware_analysis_specialist", 85, "CRITICAL"),
            self._make_result("threat_detection_specialist", 82, "CRITICAL"),
            self._make_result("password_security_advisor", 15, "LOW"),
        ]
        risk = calculate_platform_risk(results)
        self.assertEqual(risk.critical_count, 2)
        self.assertEqual(risk.overall_risk, "CRITICAL")

    def test_10_confidence_penalty_for_failures(self):
        results = [
            self._make_result("password_security_advisor", 50, "MEDIUM"),
            SpecialistResult(specialist="x", display_name="X", success=False, risk_level="UNKNOWN"),
        ]
        risk = calculate_platform_risk(results)
        self.assertLess(risk.confidence, 90)  # Penalty applied

    def test_11_score_breakdown_keys(self):
        results = [
            self._make_result("password_security_advisor", 30, "LOW"),
            self._make_result("malware_analysis_specialist", 70, "HIGH"),
        ]
        risk = calculate_platform_risk(results)
        self.assertIn("password_security_advisor", risk.score_breakdown)
        self.assertIn("malware_analysis_specialist", risk.score_breakdown)


class TestSpecialistRegistry(unittest.TestCase):
    """Test the specialist registry and tool execution."""

    def test_12_all_display_names_present(self):
        for key in AVAILABLE_SPECIALISTS:
            self.assertIn(key, DISPLAY_NAMES)

    def test_13_unknown_specialist_returns_error(self):
        result = run_specialist("nonexistent_specialist", {})
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_14_password_specialist_runs(self):
        """Run the PasswordRiskTool with empty inputs — should not crash."""
        result = run_specialist("password_security_advisor", {})
        self.assertIsInstance(result.score, int)
        self.assertIn(result.risk_level, ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"))
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)

    def test_15_incident_specialist_runs(self):
        """Run the IncidentResponseTool with empty inputs — should not crash."""
        result = run_specialist("incident_response_specialist", {})
        self.assertIsInstance(result.score, int)
        self.assertIn(result.risk_level, ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"))

    def test_16_phishing_specialist_runs(self):
        result = run_specialist("phishing_detection_specialist", {})
        self.assertIsInstance(result.score, int)

    def test_17_privacy_specialist_runs(self):
        result = run_specialist("privacy_compliance_analyst", {})
        self.assertIsInstance(result.score, int)

    def test_18_fraud_specialist_runs(self):
        result = run_specialist("fraud_detection_specialist", {})
        self.assertIsInstance(result.score, int)


class TestSecurityFlow(unittest.TestCase):
    """Integration test for the full orchestration flow."""

    def test_19_full_orchestration_two_specialists(self):
        """Run a 2-specialist orchestration end-to-end."""
        from cyberverse.orchestrator.security_flow import run_security_analysis

        request = SecurityAnalysisRequest(
            specialists=["password_security_advisor", "phishing_detection_specialist"],
            inputs={"password": "weak"},
            label="Unit Test Run",
        )
        report = run_security_analysis(request)

        self.assertIsNotNone(report.report_id)
        self.assertEqual(report.status, "completed")
        self.assertIsNotNone(report.platform_risk)
        self.assertIn(report.platform_risk.overall_risk, ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"))
        self.assertEqual(report.platform_risk.specialists_run, 2)
        self.assertIsNotNone(report.executive_summary)
        self.assertGreater(len(report.executive_summary), 20)

    def test_20_enterprise_sample_output_structure(self):
        """Validate enterprise report JSON structure."""
        from cyberverse.orchestrator.security_flow import run_security_analysis

        request = SecurityAnalysisRequest(
            specialists=["password_security_advisor"],
            inputs={"password": "SecureP@ssw0rd!123#"},
            label="Enterprise Sample",
        )
        report = run_security_analysis(request)

        print("\n\n=== ENTERPRISE SAMPLE OUTPUT ===")
        print(json.dumps({
            "specialist": "Password Security Advisor",
            "report_id": report.report_id[:8] + "...",
            "overall_risk": report.platform_risk.overall_risk,
            "overall_score": report.platform_risk.overall_score,
            "confidence": report.platform_risk.confidence,
            "specialists_run": report.platform_risk.specialists_run,
            "executive_summary": report.executive_summary[:120] + "...",
        }, indent=2))

        # Validate schema
        self.assertIn("report_id", report.model_dump())
        self.assertIn("platform_risk", report.model_dump())
        self.assertIn("specialist_results", report.model_dump())
        self.assertIn("executive_summary", report.model_dump())


if __name__ == "__main__":
    unittest.main()
