"""
PasswordLeakTool — K-Anonymity Data Breach Checker
===================================================
Checks passwords against public data breach repositories using k-anonymity (HIBP API)
and offline SHA-1 hash lookups without exposing plaintext passwords or full hashes.

SECURITY & PRIVACY GUARANTEES:
    - Passwords and full hashes are NEVER logged or saved.
    - Uses k-anonymity: ONLY the first 5 characters of SHA-1 hash are sent over HTTP.
    - All hash matching and classification is performed locally in memory.
"""

import json
import logging
import hashlib
import requests
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── OFFLINE HIGH-RISK BREACHED HASH DATABASE (SHA-1 UPPERCASE) ────────────
# ===========================================================================
# Top common passwords pre-hashed for offline fallback checks
_OFFLINE_BREACH_HASHES: Dict[str, int] = {
    "7C4A8D09CA3762AF61E59520943DC26494F8941B": 23500000, # 123456
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8": 9800000,  # password
    "7110EDA4D09E062AA5E4A390B0A572AC0D2C0220": 4500000,  # 123456789
    "B1B3773A05C0ED0176787A4F1574FF0075F7521E": 3200000,  # qwerty
    "11F8A6B0A80509EBA98A53B0268571F10D49C7D4": 1500000,  # 12345
    "8C6976E5B5410415BDE908BD4DEE15DFB167A9C8": 2800000,  # admin
    "E5E9FA1BA31ECD1AE84F75CAAA474F3A663F05F4": 1200000,  # secret
    "F7C3BC1D808E04732ADF679965CCC34CA7AE3441": 890000,   # password123
    "7C222FB2927D828AF22F592134E8932480637C0D": 650000,   # 12345678
}

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordLeakToolInput(BaseModel):
    """Input schema for PasswordLeakTool."""

    password: str = Field(
        ...,
        description="Plaintext password string to inspect for data breach exposure.",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordLeakTool(BaseTool):
    """
    K-Anonymity Data Breach Inspector for Passwords.

    Verifies whether a password has appeared in known security breaches using
    k-Anonymity via the HIBP Passwords API range endpoint and offline SHA-1 lookup fallback.
    Never exposes or logs plaintext passwords or full SHA-1 hashes.
    """

    name: str = "Password Leak Tool"
    description: str = (
        "Checks whether a password has been compromised in public data breaches using "
        "k-Anonymity (only the first 5 SHA-1 characters are transmitted). Evaluates "
        "breach count, exposure classification (Not Found, Low, Moderate, High, Extremely Common), "
        "and computes a 0–100 leak risk score."
    )
    args_schema: Type[BaseModel] = PasswordLeakToolInput

    def _run(self, password: str = "") -> str:
        """Execute k-anonymity data breach verification."""
        if not password or not isinstance(password, str):
            return json.dumps({
                "success": False,
                "breached": False,
                "breach_count": 0,
                "password_score": 0,
                "risk": "LOW",
                "dashboard": {},
                "findings": ["No password provided for breach analysis."],
                "recommendations": ["Provide a non-empty password string for leak checking."],
                "error": "Password argument must be a non-empty string."
            }, indent=2)

        logger.info("PasswordLeakTool: inspecting breach exposure (len=%d)", len(password))

        try:
            # 1. Compute SHA-1 Hash in memory
            sha1_full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1_full[:5]
            suffix = sha1_full[5:]

            # 2. Perform k-Anonymity lookup (Online API with offline fallback)
            breach_count, lookup_method = self._lookup_pwned_count(prefix, suffix, sha1_full)
            breached = breach_count > 0

            # 3. Classify Exposure & Calculate Risk Score
            exposure_level, score, risk = self._classify_exposure(breach_count)

            # 4. Generate Telemetry Dashboard
            dashboard = {
                "breached": breached,
                "breach_count": breach_count,
                "exposure_level": exposure_level,
                "lookup_method": lookup_method,
                "score": score,
                "k_anonymity_prefix": prefix
            }

            # 5. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_report(breached, breach_count, exposure_level, lookup_method, findings, recommendations)

            return json.dumps({
                "success": True,
                "breached": breached,
                "breach_count": breach_count,
                "password_score": score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing PasswordLeakTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "breached": False,
                "breach_count": 0,
                "password_score": 0,
                "risk": "LOW",
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"Password leak lookup failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _lookup_pwned_count(self, prefix: str, suffix: str, full_hash: str) -> tuple[int, str]:
        """
        Queries HIBP API using k-Anonymity prefix.
        Falls back to local offline hash list if network is unavailable.
        """
        headers = {"User-Agent": "Cyberverse-PasswordLeakTool/1.0"}
        try:
            resp = requests.get(f"{HIBP_API_URL}{prefix}", headers=headers, timeout=4)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        res_suffix, count_str = parts[0].upper(), parts[1]
                        if res_suffix == suffix:
                            return int(count_str), "k-anonymity"
                return 0, "k-anonymity"
        except Exception as net_err:
            logger.warning("HIBP API online lookup failed/timed out (%s); using offline fallback", net_err)

        # Fallback to local offline hash table
        if full_hash in _OFFLINE_BREACH_HASHES:
            return _OFFLINE_BREACH_HASHES[full_hash], "offline-database"
        return 0, "offline-database"

    def _classify_exposure(self, count: int) -> tuple[str, int, str]:
        """
        Classifies breach exposure level and computes 0–100 leak risk score.

        Exposure Categories:
            0               -> Not Found          (Score: 0,   Risk: LOW)
            1 - 9           -> Low Exposure       (Score: 35,  Risk: MEDIUM)
            10 - 99         -> Moderate Exposure  (Score: 60,  Risk: HIGH)
            100 - 9,999     -> High Exposure      (Score: 85,  Risk: CRITICAL)
            >= 10,000       -> Extremely Common   (Score: 98,  Risk: CRITICAL)
        """
        if count == 0:
            return "Not Found", 0, "LOW"
        elif count < 10:
            return "Low Exposure", 35, "MEDIUM"
        elif count < 100:
            return "Moderate Exposure", 60, "HIGH"
        elif count < 10000:
            return "High Exposure", 85, "CRITICAL"
        else:
            return "Extremely Common", 98, "CRITICAL"

    def _generate_report(
        self,
        breached: bool,
        count: int,
        exposure: str,
        method: str,
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Formulate security findings and actionable recommendations."""
        if not breached:
            findings.append(f"Password was not found in known public data breach datasets (lookup: {method}).")
            recommendations.append("Password has no recorded breach exposure, but maintain regular rotation and unique credentials.")
            return

        findings.append(f"Data breach exposure confirmed: password has appeared in {count:,} known breach occurrences ({exposure}).")

        if count >= 10000:
            findings.append("Password is extraordinarily common and present in major credential dumps across the dark web.")

        # Recommendations
        recommendations.append("Immediately change this password across all accounts where it is used.")
        recommendations.append("Ensure passwords are unique for every online account and service.")
        recommendations.append("Enable Multi-Factor Authentication (MFA/2FA) to protect against credential stuffing.")
        recommendations.append("Use a trusted enterprise password manager to generate high-entropy passwords.")
