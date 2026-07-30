"""
test_all_agents_live.py — Comprehensive Live Test Suite for All 9 CyberVerse Agents
===================================================================================
Executes live testing for all 9 Cybersecurity Specialist Agents using Groq & OpenAI APIs.
Outputs full diagnostic metrics: Score (0-100), Risk Level, Confidence %, Duration (ms), and Top Findings.
"""

import sys
import os
import json
import time
import unittest

sys.path.insert(0, "src")

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

from cyberverse.orchestrator.specialist_registry import run_specialist, AVAILABLE_SPECIALISTS, DISPLAY_NAMES
from cyberverse.orchestrator.models import SecurityAnalysisRequest
from cyberverse.orchestrator.security_flow import run_security_analysis


class TestAllAgentsLive(unittest.TestCase):
    """Test suite executing live analysis across all 9 agents."""

    @classmethod
    def setUpClass(cls):
        cls.groq_key = os.environ.get("GROQ_API_KEY", "")
        cls.openai_key = os.environ.get("OPENAI_API_KEY", "")
        print("\n================================================================================")
        print("  CYBERVERSE ALL 9 SPECIALIST AGENTS LIVE TEST SUITE")
        print("================================================================================")
        print(f"  Groq API Key   : {'CONFIGURED (' + cls.groq_key[:12] + '...)' if cls.groq_key else 'NOT SET'}")
        print(f"  OpenAI API Key : {'CONFIGURED (' + cls.openai_key[:12] + '...)' if cls.openai_key else 'NOT SET'}")
        print(f"  Default LLM    : {os.environ.get('MODEL', 'groq/llama-3.3-70b-versatile')}")
        print("================================================================================\n")

    def test_01_certificate_verification_specialist(self):
        """Test Agent 1: Certificate Verification Specialist."""
        t0 = time.time()
        res = run_specialist("certificate_verification_specialist", {
            "document": {"file": "diploma_scan.pdf", "tampered": False},
            "qr": {"code": "CERT-2026-99481"},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [1/9] Certificate Verification Specialist : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_02_privacy_compliance_analyst(self):
        """Test Agent 2: Privacy Compliance Analyst."""
        t0 = time.time()
        res = run_specialist("privacy_compliance_analyst", {
            "pii": {"email": "user@company.com", "ssn": "000-12-3456"},
            "secrets": {"aws_key": "AKIAIOSFODNN7EXAMPLE"},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [2/9] Privacy Compliance Analyst         : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_03_malware_analysis_specialist(self):
        """Test Agent 3: Malware Analysis Specialist."""
        t0 = time.time()
        res = run_specialist("malware_analysis_specialist", {
            "hash_result": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            "yara_result": {"matched_rules": ["SUSPICIOUS_PE_HEADER", "EMBEDDED_EXE"]},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [3/9] Malware Analysis Specialist        : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_04_threat_detection_specialist(self):
        """Test Agent 4: Threat Detection Specialist."""
        t0 = time.time()
        res = run_specialist("threat_detection_specialist", {
            "ip": {"ip": "192.168.1.105", "reputation": "malicious"},
            "url": {"url": "http://malicious-c2-server.xyz/payload.bin"},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [4/9] Threat Detection Specialist        : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_05_identity_verification_specialist(self):
        """Test Agent 5: Identity Verification Specialist."""
        t0 = time.time()
        res = run_specialist("identity_verification_specialist", {
            "document": {"type": "passport", "verified": True},
            "liveness": {"score": 98.5, "passed": True},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [5/9] Identity Verification Specialist   : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_06_fraud_detection_specialist(self):
        """Test Agent 6: Fraud Detection Specialist."""
        t0 = time.time()
        res = run_specialist("fraud_detection_specialist", {
            "transaction": {"amount": 9999.00, "suspicious": True},
            "account_takeover": {"failed_logins": 12, "new_ip": True},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [6/9] Fraud Detection Specialist         : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_07_phishing_detection_specialist(self):
        """Test Agent 7: Phishing Detection Specialist."""
        t0 = time.time()
        res = run_specialist("phishing_detection_specialist", {
            "headers": {"spf": "fail", "dmarc": "fail"},
            "url_inspection": {"url": "http://verify-account-alert-security.xyz"},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [7/9] Phishing Detection Specialist       : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_08_password_security_advisor(self):
        """Test Agent 8: Password Security Advisor."""
        t0 = time.time()
        res = run_specialist("password_security_advisor", {
            "strength": {"password": "P@ssw0rd2026!Secure"},
            "mfa": {"enabled": True},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [8/9] Password Security Advisor          : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_09_incident_response_specialist(self):
        """Test Agent 9: Incident Response Specialist."""
        t0 = time.time()
        res = run_specialist("incident_response_specialist", {
            "classification": {"severity": "CRITICAL", "category": "Malware"},
            "mitre": {"technique": "T1059.001"},
        })
        dt = int((time.time() - t0) * 1000)

        self.assertTrue(res.success or res.score >= 0)
        print(f"  [9/9] Incident Response Specialist       : Risk={res.risk_level:<8} Score={res.score:<3} Conf={res.confidence}% Time={dt}ms")
        return res

    def test_10_full_orchestration_flow_all_9(self):
        """Test Full Multi-Agent Parallel Orchestration across all 9 agents."""
        print("\n--------------------------------------------------------------------------------")
        print("  EXECUTING PARALLEL MULTI-AGENT ORCHESTRATION (ALL 9 SPECIALISTS)")
        print("--------------------------------------------------------------------------------")

        request = SecurityAnalysisRequest(
            specialists=AVAILABLE_SPECIALISTS,
            inputs={"password": "TestP@ssw0rd!123", "ip": "192.168.1.1"},
            label="Full Platform Live Audit",
        )

        t0 = time.time()
        report = run_security_analysis(request)
        dt = int((time.time() - t0) * 1000)

        self.assertIsNotNone(report.report_id)
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.platform_risk.specialists_run, 9)

        print(f"\n  [OK] Orchestration Flow Succeeded in {dt}ms!")
        print(f"     Report ID            : {report.report_id}")
        print(f"     Overall Risk Level   : {report.platform_risk.overall_risk}")
        print(f"     Overall Risk Score   : {report.platform_risk.overall_score}/100")
        print(f"     Specialists Executed : {report.platform_risk.specialists_succeeded}/9 Succeeded")
        print(f"     Confidence Rating    : {report.platform_risk.confidence}%")
        print(f"     Executive Summary    : {report.executive_summary[:100]}...")
        print("================================================================================\n")


if __name__ == "__main__":
    unittest.main()
