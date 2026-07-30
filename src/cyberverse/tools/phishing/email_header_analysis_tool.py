import os
import re
import json
import logging
from email.parser import HeaderParser
from email.utils import parseaddr
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class EmailHeaderAnalysisToolInput(BaseModel):
    """Input schema for EmailHeaderAnalysisTool."""
    raw_headers: str = Field(..., description="Raw text string of RFC 822 email headers to parse and verify.")


class EmailHeaderAnalysisTool(BaseTool):
    name: str = "Email Header Analysis Tool"
    description: str = (
        "Parses raw RFC 822 email headers, extracts routing & authentication fields (From, Reply-To, Return-Path, Received chain), "
        "validates SPF/DKIM/DMARC statuses, detects domain impersonation and display name spoofing, and computes a 0-100 header risk score."
    )
    args_schema: Type[BaseModel] = EmailHeaderAnalysisToolInput

    def _run(self, raw_headers: str) -> str:
        """Execute raw email header security parsing, spoofing detection, and risk scoring."""
        warnings: List[str] = []

        if not raw_headers or not isinstance(raw_headers, str) or not raw_headers.strip():
            return json.dumps({
                "success": False,
                "header_score": 0,
                "risk": "LOW",
                "dashboard": {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "mismatch_detected": False},
                "findings": [],
                "recommendations": [],
                "error": "raw_headers argument must be a valid non-empty string."
            }, indent=2)

        try:
            # 1. Parse Raw Headers using Standard Email Library
            parser = HeaderParser()
            msg = parser.parsestr(raw_headers.strip())

            from_hdr = msg.get("From", "")
            reply_to_hdr = msg.get("Reply-To", "")
            return_path_hdr = msg.get("Return-Path", "")
            auth_results = msg.get("Authentication-Results", "")
            received_spf = msg.get("Received-SPF", "")
            received_chain = msg.get_all("Received") or []

            findings: List[str] = []
            recommendations: List[str] = []
            risk_score = 0

            # 2. Extract & Normalize Domains
            from_name, from_email = parseaddr(from_hdr)
            _, reply_to_email = parseaddr(reply_to_hdr)
            _, return_path_email = parseaddr(return_path_hdr)

            from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
            reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""
            return_path_domain = return_path_email.split("@")[-1].lower() if "@" in return_path_email else ""

            # --- A. Authentication Analysis (SPF / DKIM / DMARC) ---
            spf_status, dkim_status, dmarc_status = self._parse_authentication_status(auth_results, received_spf)

            if spf_status == "FAIL":
                risk_score += 25
                findings.append("SPF (Sender Policy Framework) authentication failed.")
            elif spf_status == "NONE":
                risk_score += 10
                findings.append("No SPF verification record found.")

            if dkim_status == "FAIL":
                risk_score += 25
                findings.append("DKIM (DomainKeys Identified Mail) signature verification failed.")
            elif dkim_status == "NONE":
                risk_score += 10
                findings.append("No DKIM signature found.")

            if dmarc_status == "FAIL":
                risk_score += 30
                findings.append("DMARC (Domain-based Message Authentication) policy validation failed.")
            elif dmarc_status == "NONE":
                risk_score += 10
                findings.append("No DMARC policy check found.")

            # --- B. Header Consistency & Spoofing Detection ---
            mismatch_detected = False

            if reply_to_domain and from_domain and reply_to_domain != from_domain:
                mismatch_detected = True
                risk_score += 25
                findings.append(f"Reply-To domain mismatch: 'Reply-To' domain ({reply_to_domain}) differs from 'From' domain ({from_domain}).")

            if return_path_domain and from_domain and return_path_domain != from_domain:
                mismatch_detected = True
                risk_score += 20
                findings.append(f"Return-Path domain mismatch: 'Return-Path' domain ({return_path_domain}) differs from 'From' domain ({from_domain}).")

            # Display Name Spoofing Check (e.g. "PayPal Support <attacker@gmail.com>")
            well_known_brands = ["paypal", "microsoft", "apple", "google", "bank", "chase", "amazon", "netflix", "support", "security"]
            if from_name:
                f_name_lower = from_name.lower()
                if any(brand in f_name_lower for brand in well_known_brands) and not any(brand in from_domain for brand in well_known_brands):
                    mismatch_detected = True
                    risk_score += 25
                    findings.append(f"Display name spoofing detected: Display name '{from_name}' uses brand keyword but email domain is '{from_domain}'.")

            # --- C. Routing & Relay Analysis ---
            if len(received_chain) > 6:
                risk_score += 10
                findings.append(f"Excessive email routing hops detected ({len(received_chain)} Received headers).")

            # 3. Finalize Risk Score & Categorization
            final_score = min(100, risk_score)

            if final_score >= 80:
                risk = "CRITICAL"
            elif final_score >= 60:
                risk = "HIGH"
            elif final_score >= 30:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # 4. Formulate Dashboard Telemetry
            dashboard = {
                "spf": spf_status,
                "dkim": dkim_status,
                "dmarc": dmarc_status,
                "mismatch_detected": mismatch_detected
            }

            # 5. Formulate Recommendations
            if risk in {"CRITICAL", "HIGH"}:
                recommendations.append("Do not click links or open attachments in this email.")
                recommendations.append("Do not reply to this email.")
                recommendations.append("Quarantine or purge email from inbox immediately.")
                recommendations.append("Report message to security operations team for domain blocking.")
            elif risk == "MEDIUM":
                recommendations.append("Exercise caution; verify sender identity via external channels.")
            else:
                recommendations.append("Header authentication and domain consistency checks passed.")

            return json.dumps({
                "success": True,
                "header_score": final_score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing EmailHeaderAnalysisTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "header_score": 0,
                "risk": "LOW",
                "dashboard": {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "mismatch_detected": False},
                "findings": [],
                "recommendations": [],
                "error": f"Email header analysis failed: {str(e)}"
            }, indent=2)

    def _parse_authentication_status(self, auth_str: str, spf_str: str) -> tuple[str, str, str]:
        """Extract SPF, DKIM, and DMARC status strings from header blocks."""
        combined = f"{auth_str} {spf_str}".lower()

        spf = "NONE"
        if "spf=pass" in combined:
            spf = "PASS"
        elif "spf=fail" in combined or "spf=softfail" in combined:
            spf = "FAIL"

        dkim = "NONE"
        if "dkim=pass" in combined:
            dkim = "PASS"
        elif "dkim=fail" in combined:
            dkim = "FAIL"

        dmarc = "NONE"
        if "dmarc=pass" in combined:
            dmarc = "PASS"
        elif "dmarc=fail" in combined:
            dmarc = "FAIL"

        return spf, dkim, dmarc
