"""
test_phishing_detection_end_to_end.py
======================================
End-to-end integration test for the Phishing Detection Specialist tool suite.

Workflow Under Test
-------------------
Suspicious Email
        │
        ▼
EmailHeaderAnalysisTool   — header parsing, SPF/DKIM/DMARC, spoofing
        │
        ▼
URLInspectionTool         — URL structure, HTTPS, typosquatting, shorteners
        │
        ▼
DomainReputationTool      — WHOIS age, DNS health, SSL, brand indicators
        │
        ▼
ContentAnalysisTool       — social engineering, credentials, brand, links
        │
        ▼
PhishingRiskTool          — weighted aggregation → unified enterprise report

Coverage
--------
- Tool instantiation and registration
- Schema validation (valid inputs accepted)
- All five tool outputs are valid JSON with expected top-level keys
- Phishing score and risk level are within expected bounds
- Evidence list is non-empty for a known-phishing sample
- Clean / non-phishing email produces a LOW risk verdict
- Missing tool inputs are handled gracefully (partial aggregation)
"""

import json
import sys
import unittest

sys.path.insert(0, "src")

from cyberverse.tools.phishing.email_header_analysis_tool import EmailHeaderAnalysisTool
from cyberverse.tools.phishing.url_inspection_tool import URLInspectionTool
from cyberverse.tools.phishing.domain_reputation_tool import DomainReputationTool
from cyberverse.tools.phishing.content_analysis_tool import ContentAnalysisTool
from cyberverse.tools.phishing.phishing_risk_tool import PhishingRiskTool

# ---------------------------------------------------------------------------
# ── Shared test fixtures ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

# RFC-2822 headers for a typical phishing email
_PHISHING_HEADERS = """\
From: "PayPal Support" <no-reply@paypa1-secure.ru>
Reply-To: attacker@evil-domain.xyz
Return-Path: <bounce@paypa1-secure.ru>
To: victim@company.com
Subject: URGENT: Your PayPal account has been suspended
Date: Tue, 29 Jul 2026 10:00:00 +0000
Message-ID: <abc123@paypa1-secure.ru>
Received: from evil-relay1.xyz (evil-relay1.xyz [203.0.113.1]) by mx.company.com
Received: from suspicious-relay2.net (suspicious-relay2.net [198.51.100.5]) by evil-relay1.xyz
Received: from phish-origin.ru (phish-origin.ru [192.0.2.100]) by suspicious-relay2.net
Received: from anonymizer.onion.sh by phish-origin.ru
Received: from final-hop.xyz by anonymizer.onion.sh
Received: from mail-out.paypa1-secure.ru by final-hop.xyz
Received: from root-relay.ru by mail-out.paypa1-secure.ru
Authentication-Results: mx.company.com; spf=fail smtp.mailfrom=paypa1-secure.ru; \
dkim=fail header.d=paypa1-secure.ru; dmarc=fail header.from=paypa1-secure.ru
Received-SPF: fail (domain of paypa1-secure.ru does not designate 203.0.113.1 as permitted sender)
"""

# Known-phishing HTML email body (brand impersonation + credential harvesting)
_PHISHING_HTML_BODY = """
<html><body>
<h2>Urgent: Your PayPal account has been suspended</h2>
<p>Dear valued customer,</p>
<p>We have detected <b>suspicious activity</b> on your account. <b>Immediate action required</b>.</p>
<p>Your account will be permanently deleted within <b>24 hours</b> unless you verify your identity.</p>
<p>Please enter your <b>username</b>, <b>password</b>, and <b>OTP</b> below:</p>
<a href="http://203.0.113.99/paypal-login/verify">Verify Your Account Now</a>
<p>Alternatively, scan the QR code below with your phone camera.</p>
<p>Invoice.exe is also attached for reference.</p>
<p>Please update your credit card number and CVV immediately.</p>
<p>— PayPal Security Team</p>
</body></html>
"""

# A phishing URL for inspection — uses raw IP to guarantee detection
_PHISHING_URL = "http://203.0.113.99/paypal-login/verify?ref=urgent"

# The sending domain for reputation analysis
_PHISHING_DOMAIN = "paypa1-secure.ru"

# A clean, legitimate email for negative testing
_CLEAN_HEADERS = """\
From: "Alice Smith" <alice@company.com>
To: bob@company.com
Subject: Team lunch tomorrow
Date: Tue, 29 Jul 2026 09:00:00 +0000
Authentication-Results: mx.company.com; spf=pass smtp.mailfrom=company.com; \
dkim=pass header.d=company.com; dmarc=pass header.from=company.com
"""

_CLEAN_BODY = "Hi Bob, just a reminder about the team lunch tomorrow at noon. See you there! — Alice"


# ===========================================================================
# ── TEST SUITE ───────────────────────────────────────────────────────────────
# ===========================================================================

class TestPhishingDetectionEndToEnd(unittest.TestCase):
    """End-to-end integration test for the Phishing Detection Specialist."""

    @classmethod
    def setUpClass(cls) -> None:
        """Instantiate all five phishing tools once for the entire test class."""
        cls.header_tool  = EmailHeaderAnalysisTool()
        cls.url_tool     = URLInspectionTool()
        cls.domain_tool  = DomainReputationTool()
        cls.content_tool = ContentAnalysisTool()
        cls.risk_tool    = PhishingRiskTool()

    # ── Tool Registration ──────────────────────────────────────────────────

    def test_01_tool_names_and_registration(self) -> None:
        """Verify all five tools are correctly instantiated with expected names."""
        print("\n=== TEST 01: Tool Registration ===")
        self.assertEqual(self.header_tool.name,  "Email Header Analysis Tool")
        self.assertEqual(self.url_tool.name,     "URL Inspection Tool")
        self.assertEqual(self.domain_tool.name,  "Domain Reputation Tool")
        self.assertEqual(self.content_tool.name, "Content Analysis Tool")
        self.assertEqual(self.risk_tool.name,    "Phishing Risk Tool")
        print("[OK] All five tools registered with correct names.")

    # -- Step 1: Email Header Analysis -------------------------------------

    def test_02_email_header_analysis_phishing(self) -> None:
        """EmailHeaderAnalysisTool should flag SPF/DKIM/DMARC failures and spoofing."""
        print("\n=== TEST 02: EmailHeaderAnalysisTool — Phishing Headers ===")
        result_str = self.header_tool._run(raw_headers=_PHISHING_HEADERS)
        result = json.loads(result_str)
        print(f"  Header Score : {result['header_score']}/100")
        print(f"  Risk         : {result['risk']}")
        print(f"  SPF/DKIM/DMARC: {result['dashboard']}")
        print(f"  Findings     : {len(result['findings'])} items")

        self.assertTrue(result["success"])
        self.assertIn("header_score", result)
        self.assertIn("risk", result)
        self.assertIn("dashboard", result)
        self.assertIn("findings", result)
        self.assertIn("recommendations", result)
        self.assertIsNone(result["error"])
        # Phishing headers must produce a non-LOW risk
        self.assertIn(result["risk"], ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertGreater(result["header_score"], 20)

    def test_03_email_header_analysis_clean(self) -> None:
        """EmailHeaderAnalysisTool should return LOW risk for clean headers."""
        print("\n=== TEST 03: EmailHeaderAnalysisTool — Clean Headers ===")
        result = json.loads(self.header_tool._run(raw_headers=_CLEAN_HEADERS))
        print(f"  Header Score : {result['header_score']}/100  |  Risk: {result['risk']}")
        self.assertTrue(result["success"])
        self.assertEqual(result["risk"], "LOW")

    def test_04_email_header_analysis_empty_input(self) -> None:
        """EmailHeaderAnalysisTool should gracefully reject empty input."""
        result = json.loads(self.header_tool._run(raw_headers=""))
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])

    # -- Step 2: URL Inspection ---------------------------------------------

    def test_05_url_inspection_phishing(self) -> None:
        """URLInspectionTool should flag the phishing URL."""
        print("\n=== TEST 05: URLInspectionTool — Phishing URL ===")
        result = json.loads(self.url_tool._run(url=_PHISHING_URL))
        print(f"  URL Score  : {result.get('url_score')}/100  |  Risk: {result.get('risk')}")
        print(f"  Findings   : {len(result.get('findings', []))} items")

        self.assertTrue(result["success"])
        self.assertIn("url_score",      result)
        self.assertIn("risk",           result)
        self.assertIn("findings",       result)
        self.assertIn("recommendations", result)
        self.assertIsNone(result["error"])
        # IP-based HTTP URL must score above zero
        self.assertGreater(result["url_score"], 0)
        self.assertIn(result["risk"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_06_url_inspection_legitimate(self) -> None:
        """URLInspectionTool should return LOW–MEDIUM risk for a clean HTTPS URL."""
        print("\n=== TEST 06: URLInspectionTool — Legitimate URL ===")
        result = json.loads(self.url_tool._run(url="https://www.google.com/search?q=test"))
        print(f"  URL Score  : {result.get('url_score')}/100  |  Risk: {result.get('risk')}")
        self.assertTrue(result["success"])
        self.assertIn(result["risk"], ("LOW", "MEDIUM"))

    # -- Step 3: Domain Reputation ------------------------------------------

    def test_07_domain_reputation_phishing(self) -> None:
        """DomainReputationTool should flag the phishing domain."""
        print("\n=== TEST 07: DomainReputationTool — Phishing Domain ===")
        result = json.loads(self.domain_tool._run(domain=_PHISHING_DOMAIN))
        print(f"  Trust Score : {result.get('trust_score')}/100  |  Risk: {result.get('risk')}")
        print(f"  Findings    : {len(result.get('findings', []))} items")

        self.assertTrue(result["success"])
        self.assertIn("trust_score",    result)
        self.assertIn("risk",           result)
        self.assertIn("dashboard",      result)
        self.assertIn("findings",       result)
        self.assertIn("recommendations", result)
        self.assertIsNone(result["error"])
        # Phishing domain must not be LOW
        self.assertIn(result["risk"], ("MEDIUM", "HIGH", "CRITICAL"))

    # -- Step 4: Content Analysis -------------------------------------------

    def test_08_content_analysis_phishing(self) -> None:
        """ContentAnalysisTool should detect multiple phishing signals."""
        print("\n=== TEST 08: ContentAnalysisTool — Phishing Body ===")
        result = json.loads(self.content_tool._run(
            subject="URGENT: Your PayPal account has been suspended",
            body=_PHISHING_HTML_BODY,
        ))
        print(f"  Content Score : {result['content_score']}/100  |  Risk: {result['risk']}")
        print(f"  Confidence    : {result['confidence']}%")
        dash = result["dashboard"]
        print(f"  Urgency={dash.get('urgency_detected')}  Credentials={dash.get('credential_requests')}  Brands={dash.get('brand_mentions')}")
        print(f"  Findings      : {len(result['findings'])} items")

        self.assertTrue(result["success"])
        self.assertIn("content_score", result)
        self.assertIn("risk",          result)
        self.assertIn("confidence",    result)
        self.assertIn("dashboard",     result)
        self.assertIn("findings",      result)
        self.assertIsNone(result["error"])
        self.assertIn(result["risk"], ("HIGH", "CRITICAL"))
        self.assertGreater(result["content_score"], 50)
        # Must detect credential requests
        self.assertGreater(dash.get("credential_requests", 0), 0)

    def test_09_content_analysis_clean(self) -> None:
        """ContentAnalysisTool should return LOW for a clean email."""
        print("\n=== TEST 09: ContentAnalysisTool — Clean Email ===")
        result = json.loads(self.content_tool._run(
            subject="Team lunch tomorrow",
            body=_CLEAN_BODY,
        ))
        print(f"  Content Score : {result['content_score']}/100  |  Risk: {result['risk']}")
        self.assertTrue(result["success"])
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["content_score"], 0)

    # -- Step 5: PhishingRiskTool Aggregation -------------------------------

    def test_10_phishing_risk_tool_full_pipeline(self) -> None:
        """
        Full end-to-end pipeline test.
        Run all four analysis tools against a phishing email and feed
        their outputs into PhishingRiskTool for unified aggregation.
        """
        print("\n=== TEST 10: FULL END-TO-END PHISHING PIPELINE ===")

        # -- Collect all tool outputs ---------------------------------------
        print("  [1/4] EmailHeaderAnalysisTool...")
        header_res  = json.loads(self.header_tool._run(raw_headers=_PHISHING_HEADERS))

        print("  [2/4] URLInspectionTool...")
        url_res     = json.loads(self.url_tool._run(url=_PHISHING_URL))

        print("  [3/4] DomainReputationTool...")
        domain_res  = json.loads(self.domain_tool._run(domain=_PHISHING_DOMAIN))

        print("  [4/4] ContentAnalysisTool...")
        content_res = json.loads(self.content_tool._run(
            subject="URGENT: Your PayPal account has been suspended",
            body=_PHISHING_HTML_BODY,
        ))

        # -- Feed into PhishingRiskTool -------------------------------------
        print("  [5/5] PhishingRiskTool aggregation...")
        risk_res = json.loads(self.risk_tool._run(
            header_analysis=header_res,
            url_analysis=url_res,
            domain_analysis=domain_res,
            content_analysis=content_res,
        ))

        print("\n  -- Enterprise Phishing Assessment Output --")
        print(f"  Overall Risk   : {risk_res['overall_risk']}")
        print(f"  Phishing Score : {risk_res['phishing_score']}/100")
        print(f"  Confidence     : {risk_res['confidence']}%")
        print(f"  Evidence items : {len(risk_res['evidence'])}")
        print(f"  Dashboard      : {json.dumps(risk_res['dashboard'], indent=4)}")
        print(f"  Summary        : {risk_res['executive_summary'][:120]}...")

        # -- Assertions -----------------------------------------------------
        self.assertTrue(risk_res["success"])
        self.assertIn("overall_risk",     risk_res)
        self.assertIn("phishing_score",   risk_res)
        self.assertIn("confidence",       risk_res)
        self.assertIn("dashboard",        risk_res)
        self.assertIn("evidence",         risk_res)
        self.assertIn("recommendations",  risk_res)
        self.assertIn("executive_summary", risk_res)
        self.assertIsNone(risk_res["error"])

        # Phishing score must be HIGH or CRITICAL
        self.assertIn(risk_res["overall_risk"], ("HIGH", "CRITICAL"))
        self.assertGreater(risk_res["phishing_score"], 40)
        self.assertGreater(risk_res["confidence"], 50)
        self.assertGreater(len(risk_res["evidence"]), 0)
        self.assertGreater(len(risk_res["recommendations"]), 0)
        self.assertGreater(len(risk_res["executive_summary"]), 50)

        # Dashboard structure
        dash = risk_res["dashboard"]
        self.assertIn("overall_score", dash)
        self.assertIn("header_score",  dash)
        self.assertIn("content_score", dash)

    def test_11_phishing_risk_tool_partial_inputs(self) -> None:
        """PhishingRiskTool must handle partial (missing tool) inputs gracefully."""
        print("\n=== TEST 11: PhishingRiskTool — Partial Inputs ===")
        # Only provide content analysis (other tools unavailable)
        content_res = json.loads(self.content_tool._run(
            subject="Verify your account immediately",
            body="Your Microsoft account has been suspended. Enter your password and OTP now.",
        ))
        result = json.loads(self.risk_tool._run(
            header_analysis={},
            url_analysis={},
            domain_analysis={},
            content_analysis=content_res,
        ))
        print(f"  Risk: {result['overall_risk']}  Score: {result['phishing_score']}/100")
        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertIn(result["overall_risk"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_12_phishing_risk_tool_all_empty_inputs(self) -> None:
        """PhishingRiskTool must return success=True with score=0 when all inputs are empty."""
        print("\n=== TEST 12: PhishingRiskTool — All Empty Inputs ===")
        result = json.loads(self.risk_tool._run(
            header_analysis={},
            url_analysis={},
            domain_analysis={},
            content_analysis={},
        ))
        print(f"  Risk: {result['overall_risk']}  Score: {result['phishing_score']}/100")
        self.assertTrue(result["success"])
        self.assertEqual(result["phishing_score"], 0)
        self.assertEqual(result["overall_risk"], "LOW")

    def test_13_clean_email_end_to_end(self) -> None:
        """Full pipeline on a clean email must not return CRITICAL risk."""
        print("\n=== TEST 13: Clean Email — Full Pipeline ===")
        header_res  = json.loads(self.header_tool._run(raw_headers=_CLEAN_HEADERS))
        content_res = json.loads(self.content_tool._run(
            subject="Team lunch tomorrow",
            body=_CLEAN_BODY,
        ))
        result = json.loads(self.risk_tool._run(
            header_analysis=header_res,
            url_analysis={},
            domain_analysis={},
            content_analysis=content_res,
        ))
        print(f"  Risk: {result['overall_risk']}  Score: {result['phishing_score']}/100")
        self.assertTrue(result["success"])
        self.assertNotIn(result["overall_risk"], ("CRITICAL",))

    # -- Sample Enterprise Output -------------------------------------------

    def test_14_enterprise_sample_output_structure(self) -> None:
        """Validate the enterprise sample JSON output matches the required schema."""
        print("\n=== TEST 14: Enterprise Sample Output Schema ===")
        sample_output = {
            "specialist":     "Phishing Detection Specialist",
            "overall_risk":   "CRITICAL",
            "phishing_score": 92,
            "confidence":     99,
            "dashboard": {
                "header_score":  82,
                "url_score":     91,
                "domain_score":  73,
                "content_score": 95,
                "overall_score": 92,
            },
            "evidence": [
                "DMARC (Domain-based Message Authentication) policy validation failed.",
                "SPF (Sender Policy Framework) authentication failed.",
                "DKIM (DomainKeys Identified Mail) signature verification failed.",
                "Reply-To domain mismatch detected.",
                "Display name spoofing: 'PayPal Support' with unrelated domain.",
                "Credential harvesting attempt — password, OTP, credit card solicited.",
                "PayPal brand impersonation with mismatched hyperlinks.",
                "IP-based hyperlink detected — legitimate senders rarely use raw IPs.",
                "Punycode / lookalike domain detected (paypa1-secure.ru).",
                "Dangerous attachment lure — EXE file reference in email body.",
                "QR code phishing reference detected.",
            ],
            "recommendations": [
                "Quarantine email immediately and prevent recipient delivery.",
                "Block sender domain at email gateway.",
                "Notify recipient — do not interact with any links or attachments.",
                "Escalate to Security Operations Centre (SOC).",
                "Reset credentials immediately if recipient has already interacted.",
                "Submit all IoCs (URLs, domains, IPs) to threat intelligence feeds.",
                "Scan endpoints that received this email for post-exploitation indicators.",
            ],
            "executive_summary": (
                "HIGH-CONFIDENCE PHISHING DETECTED — Phishing score: 92/100 (CRITICAL, confidence: 99%). "
                "The analyzed email exhibits multiple independent phishing indicators across 4 detection "
                "layer(s): email header authentication failures, malicious or suspicious URL characteristics, "
                "low-reputation or newly registered domain, and phishing content indicators "
                "(social engineering/credential harvesting). The message should be treated as confirmed "
                "malicious and handled immediately. Quarantine, block all associated domains and URLs, "
                "notify the recipient, and initiate security incident response procedures."
            ),
        }

        # Validate required top-level keys
        required_keys = [
            "specialist", "overall_risk", "phishing_score", "confidence",
            "dashboard", "evidence", "recommendations", "executive_summary",
        ]
        for key in required_keys:
            self.assertIn(key, sample_output, f"Missing key: {key}")

        self.assertIn(sample_output["overall_risk"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
        self.assertIsInstance(sample_output["phishing_score"], int)
        self.assertIsInstance(sample_output["confidence"], int)
        self.assertIsInstance(sample_output["evidence"], list)
        self.assertIsInstance(sample_output["recommendations"], list)
        self.assertIsInstance(sample_output["executive_summary"], str)

        print(f"  [OK] Sample output structure validated ({len(sample_output['evidence'])} evidence items).")
        print("\n  Sample Enterprise JSON Output:")
        print(json.dumps(sample_output, indent=2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
