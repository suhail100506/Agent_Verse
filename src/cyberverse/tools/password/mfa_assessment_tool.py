"""
MFAAssessmentTool — Multi-Factor Authentication Readiness & Posture Evaluator
================================================================================
Evaluates MFA deployment posture, authentication factor types (FIDO2/WebAuthn,
TOTP, Push, SMS, Email), backup recovery mechanisms, and SIM-swapping vulnerability risks.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── METHOD WEIGHTS & PHISHING RESISTANCE MATRIX ─────────────────────────────
# ===========================================================================

# High-security FIDO2 / Hardware Security Key keywords
_HARDWARE_KEY_KEYWORDS = {"security key", "fido2", "webauthn", "yubikey", "hardware key", "u2f"}
# Time-based OTP / Authenticator keywords
_TOTP_KEYWORDS = {"totp", "authenticator", "google authenticator", "microsoft authenticator", "duo", "authy"}
# Push notification keywords
_PUSH_KEYWORDS = {"push", "push notification", "app push"}
# Insecure / Weak channels
_SMS_KEYWORDS = {"sms", "text message", "sms otp"}
_EMAIL_KEYWORDS = {"email", "email otp"}


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class MFAAssessmentToolInput(BaseModel):
    """Input schema for MFAAssessmentTool."""

    mfa_enabled: bool = Field(
        default=True,
        description="Whether Multi-Factor Authentication (MFA) is enabled for the account.",
    )
    methods: List[str] = Field(
        default_factory=list,
        description="List of configured MFA method strings (e.g. ['TOTP', 'Security Key'], ['SMS']).",
    )
    backup_codes: bool = Field(
        default=False,
        description="Whether single-use backup/recovery codes are generated and stored securely.",
    )
    recovery_email: bool = Field(
        default=False,
        description="Whether a verified secondary recovery email address is configured.",
    )
    sms_enabled: bool = Field(
        default=False,
        description="Whether SMS/text message authentication or recovery is enabled.",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class MFAAssessmentTool(BaseTool):
    """
    Multi-Factor Authentication (MFA) Security Posture Evaluator.

    Assesses MFA protocol strength, hardware security key adoption, authenticator apps,
    backup recovery readiness, and SIM-swap vulnerability risks to generate a 0–100 MFA score,
    trust level classification (Excellent, Strong, Moderate, Weak, None), and recommendations.
    """

    name: str = "MFA Assessment Tool"
    description: str = (
        "Evaluates multi-factor authentication (MFA) readiness and security posture. "
        "Assesses authentication methods (FIDO2/WebAuthn, TOTP, Push, SMS, Email), "
        "backup code availability, recovery email configurations, and SIM-swapping risks. "
        "Returns a 0–100 MFA score, trust level, telemetry dashboard, findings, and recommendations."
    )
    args_schema: Type[BaseModel] = MFAAssessmentToolInput

    def _run(
        self,
        mfa_enabled: bool = True,
        methods: Optional[List[str]] = None,
        backup_codes: bool = False,
        recovery_email: bool = False,
        sms_enabled: bool = False
    ) -> str:
        """Execute MFA readiness and security posture assessment."""
        methods = methods or []

        logger.info(
            "MFAAssessmentTool: evaluating MFA posture — enabled=%s, methods_count=%d",
            mfa_enabled, len(methods)
        )

        try:
            # 1. Handle MFA Disabled
            if not mfa_enabled or (not methods and not mfa_enabled):
                return json.dumps({
                    "success": True,
                    "mfa_score": 0,
                    "risk": "CRITICAL",
                    "dashboard": {
                        "mfa_enabled": False,
                        "trust_level": "None",
                        "methods_count": 0,
                        "phishing_resistant": False,
                        "mfa_score": 0
                    },
                    "findings": [
                        "Multi-Factor Authentication (MFA) is completely disabled. Account relies solely on single-factor password authentication."
                    ],
                    "recommendations": [
                        "Enable Multi-Factor Authentication (MFA) immediately.",
                        "Configure a time-based authenticator app (TOTP) or hardware security key (FIDO2/WebAuthn)."
                    ],
                    "error": None
                }, indent=2)

            # Normalize methods
            normalized_methods = [m.strip().lower() for m in methods if isinstance(m, str)]
            if sms_enabled and not any(k in m for m in normalized_methods for k in _SMS_KEYWORDS):
                normalized_methods.append("sms")

            # 2. Analyze Factor Characteristics
            has_hardware_key = any(any(k in m for k in _HARDWARE_KEY_KEYWORDS) for m in normalized_methods)
            has_totp = any(any(k in m for k in _TOTP_KEYWORDS) for m in normalized_methods)
            has_push = any(any(k in m for k in _PUSH_KEYWORDS) for m in normalized_methods)
            has_email = any(any(k in m for k in _EMAIL_KEYWORDS) for m in normalized_methods)
            has_sms = sms_enabled or any(any(k in m for k in _SMS_KEYWORDS) for m in normalized_methods)

            phishing_resistant = has_hardware_key

            # 3. Calculate Score & Determine Trust Level
            score, trust_level, risk = self._calculate_mfa_score(
                mfa_enabled=mfa_enabled,
                has_hardware_key=has_hardware_key,
                has_totp=has_totp,
                has_push=has_push,
                has_email=has_email,
                has_sms=has_sms,
                methods_count=len(normalized_methods),
                backup_codes=backup_codes,
                recovery_email=recovery_email
            )

            # 4. Determine Primary Method
            primary_method = "Security Key (FIDO2)" if has_hardware_key else (
                "TOTP Authenticator" if has_totp else (
                    "Push Notification" if has_push else (
                        "Email OTP" if has_email else (
                            "SMS OTP" if has_sms else "Unknown"
                        )
                    )
                )
            )

            # 5. Formulate Telemetry Dashboard
            dashboard = {
                "mfa_enabled": mfa_enabled,
                "trust_level": trust_level,
                "primary_method": primary_method,
                "methods_count": len(set(normalized_methods)),
                "configured_methods": methods,
                "phishing_resistant": phishing_resistant,
                "has_hardware_key": has_hardware_key,
                "has_totp": has_totp,
                "has_push": has_push,
                "has_sms": has_sms,
                "has_email": has_email,
                "backup_codes_configured": backup_codes,
                "recovery_email_configured": recovery_email,
                "mfa_score": score
            }

            # 6. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_findings_and_recommendations(
                mfa_enabled=mfa_enabled,
                has_hardware_key=has_hardware_key,
                has_totp=has_totp,
                has_push=has_push,
                has_sms=has_sms,
                has_email=has_email,
                backup_codes=backup_codes,
                recovery_email=recovery_email,
                trust_level=trust_level,
                score=score,
                findings=findings,
                recommendations=recommendations
            )

            return json.dumps({
                "success": True,
                "mfa_score": score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing MFAAssessmentTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "mfa_score": 0,
                "risk": "CRITICAL",
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"MFA posture assessment failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _calculate_mfa_score(
        self,
        mfa_enabled: bool,
        has_hardware_key: bool,
        has_totp: bool,
        has_push: bool,
        has_email: bool,
        has_sms: bool,
        methods_count: int,
        backup_codes: bool,
        recovery_email: bool
    ) -> tuple[int, str, str]:
        """
        Calculates 0–100 MFA score, trust level (Excellent, Strong, Moderate, Weak, None),
        and risk level (LOW, MEDIUM, HIGH, CRITICAL).
        """
        if not mfa_enabled:
            return 0, "None", "CRITICAL"

        score = 40  # Base enablement score

        # Factor weights
        if has_hardware_key:
            score += 30
        elif has_totp:
            score += 25
        elif has_push:
            score += 20
        elif has_email:
            score += 10
        elif has_sms:
            score += 5

        # Multi-factor redundancy bonus
        if methods_count >= 2:
            score += 10

        # Backup & recovery options
        if backup_codes:
            score += 10
        if recovery_email:
            score += 5

        # Insecure factor penalty if SMS is the only method
        if has_sms and not (has_hardware_key or has_totp or has_push):
            score -= 15

        final_score = max(0, min(100, score))

        # Assign Trust Level
        if has_hardware_key and final_score >= 85:
            trust_level = "Excellent"
        elif (has_totp or has_push or has_hardware_key) and final_score >= 70:
            trust_level = "Strong"
        elif final_score >= 50:
            trust_level = "Moderate"
        else:
            trust_level = "Weak"

        # Determine Risk
        if final_score >= 80:
            risk = "LOW"
        elif final_score >= 60:
            risk = "MEDIUM"
        elif final_score >= 35:
            risk = "HIGH"
        else:
            risk = "CRITICAL"

        return final_score, trust_level, risk

    def _generate_findings_and_recommendations(
        self,
        mfa_enabled: bool,
        has_hardware_key: bool,
        has_totp: bool,
        has_push: bool,
        has_sms: bool,
        has_email: bool,
        backup_codes: bool,
        recovery_email: bool,
        trust_level: str,
        score: int,
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Populate findings and recommendations."""
        findings.append(f"MFA security posture evaluated with Trust Level: {trust_level} (Score: {score}/100).")

        if has_hardware_key:
            findings.append("Hardware security key (FIDO2/WebAuthn) configured — provides robust phishing resistance.")
        elif has_totp:
            findings.append("Time-based One-Time Password (TOTP) authenticator app configured.")
        elif has_push:
            findings.append("Push notification authentication method configured.")

        if has_sms:
            findings.append("SMS text message authentication enabled — vulnerable to SIM-swapping, SS7 interception, and phishing relay attacks.")
            recommendations.append("Replace SMS authentication with a time-based authenticator app (TOTP) or FIDO2 hardware security key.")

        if has_email:
            findings.append("Email OTP authentication enabled — vulnerable if the underlying email account is compromised.")

        if not backup_codes:
            findings.append("Single-use emergency backup codes are not generated or configured.")
            recommendations.append("Generate and securely store single-use backup codes to prevent permanent account lockout.")

        if not recovery_email:
            findings.append("Secondary recovery email is not configured.")
            recommendations.append("Add a verified secondary recovery email address.")

        if not has_hardware_key:
            recommendations.append("Upgrade primary MFA factor to a hardware security key (e.g. YubiKey / FIDO2) for full phishing resistance.")

        if trust_level in ("Weak", "Moderate"):
            recommendations.append("Review and harden MFA factor configurations to eliminate insecure fallback channels.")
