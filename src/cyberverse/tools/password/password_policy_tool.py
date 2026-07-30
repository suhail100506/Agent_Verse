"""
PasswordPolicyTool — Enterprise Password Policy Compliance Validator
======================================================================
Validates passwords against configurable enterprise security policy rules,
including length, character complexity, expiration, history reuse, and lockout rules.

SECURITY NOTICE:
    - Passwords are NEVER logged, stored, or included in error messages.
    - All analysis is performed strictly in-memory.
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── DEFAULT ENTERPRISE POLICY CONFIGURATION ────────────────────────────────
# ===========================================================================

DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "min_uppercase": 1,
    "min_lowercase": 1,
    "min_digits": 1,
    "min_symbols": 1,
    "max_age_days": 90,
    "history_depth": 5,
    "lockout_threshold": 5,
}


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordPolicyToolInput(BaseModel):
    """Input schema for PasswordPolicyTool."""

    password: str = Field(
        ...,
        description="Plaintext password string to validate against enterprise policy.",
    )
    policy_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional custom policy rules: min_length, max_length, min_uppercase, "
            "min_lowercase, min_digits, min_symbols, max_age_days, password_age_days, "
            "history_depth, is_reused, lockout_threshold, failed_attempts."
        ),
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordPolicyTool(BaseTool):
    """
    Enterprise Password Policy Compliance Validator.

    Validates password compliance against configurable organizational security policies,
    evaluating length, complexity, expiration lifecycle, history reuse, and account
    lockout threshold telemetry.
    """

    name: str = "Password Policy Tool"
    description: str = (
        "Validates passwords against configurable enterprise password policies, "
        "checking minimum/maximum length, character complexity (uppercase, lowercase, "
        "digits, symbols), expiration age, history reuse flags, and lockout thresholds. "
        "Returns a 0–100 policy compliance score, risk level, telemetry dashboard, "
        "findings, and recommendations."
    )
    args_schema: Type[BaseModel] = PasswordPolicyToolInput

    def _run(self, password: str = "", policy_config: Optional[Dict[str, Any]] = None) -> str:
        """Execute password policy compliance evaluation."""
        if not password or not isinstance(password, str):
            return json.dumps({
                "success": False,
                "policy_score": 0,
                "risk": "CRITICAL",
                "dashboard": {},
                "findings": ["No password provided for policy validation."],
                "recommendations": ["Provide a non-empty password string for policy validation."],
                "error": "Password argument must be a non-empty string."
            }, indent=2)

        # Merge defaults with custom policy_config if provided
        policy = dict(DEFAULT_POLICY)
        if policy_config and isinstance(policy_config, dict):
            policy.update(policy_config)

        logger.info("PasswordPolicyTool: validating policy compliance (length=%d)", len(password))

        try:
            findings: List[str] = []
            recommendations: List[str] = []

            # 1. Length Validation
            length_pass, length_finding = self._validate_length(
                password,
                min_len=int(policy.get("min_length", 12)),
                max_len=int(policy.get("max_length", 128))
            )
            if length_finding:
                findings.append(length_finding)

            # 2. Complexity Validation
            complexity_results, comp_findings = self._validate_complexity(
                password,
                min_upper=int(policy.get("min_uppercase", 1)),
                min_lower=int(policy.get("min_lowercase", 1)),
                min_digits=int(policy.get("min_digits", 1)),
                min_symbols=int(policy.get("min_symbols", 1))
            )
            findings.extend(comp_findings)

            # 3. Expiration Validation
            pwd_age = int(policy.get("password_age_days", 0))
            max_age = int(policy.get("max_age_days", 90))
            expiration_pass, exp_finding = self._validate_expiration(pwd_age, max_age)
            if exp_finding:
                findings.append(exp_finding)

            # 4. History & Reuse Validation
            is_reused = bool(policy.get("is_reused", False))
            history_depth = int(policy.get("history_depth", 5))
            reuse_pass, reuse_finding = self._validate_history_reuse(is_reused, history_depth)
            if reuse_finding:
                findings.append(reuse_finding)

            # 5. Account Lockout Threshold Validation
            failed_attempts = int(policy.get("failed_attempts", 0))
            lockout_thresh = int(policy.get("lockout_threshold", 5))
            lockout_pass, lockout_finding = self._validate_lockout_threshold(failed_attempts, lockout_thresh)
            if lockout_finding:
                findings.append(lockout_finding)

            # 6. Calculate Compliance Score & Risk
            all_checks = [
                length_pass,
                complexity_results["upper"],
                complexity_results["lower"],
                complexity_results["digits"],
                complexity_results["symbols"],
                expiration_pass,
                reuse_pass,
                lockout_pass,
            ]
            passed_checks = sum(1 for c in all_checks if c)
            total_checks = len(all_checks)
            policy_score = int(round((passed_checks / total_checks) * 100))

            risk = self._determine_risk(policy_score, is_reused, expiration_pass)

            # Generate Recommendations
            self._generate_recommendations(policy, all_checks, findings, recommendations)

            # Construct Dashboard Telemetry
            dashboard = {
                "compliant": (policy_score == 100),
                "violations_count": len(findings),
                "length": len(password),
                "length_check": length_pass,
                "uppercase_check": complexity_results["upper"],
                "lowercase_check": complexity_results["lower"],
                "digits_check": complexity_results["digits"],
                "symbols_check": complexity_results["symbols"],
                "expiration_check": expiration_pass,
                "password_age_days": pwd_age,
                "max_allowed_age_days": max_age,
                "history_reuse_check": reuse_pass,
                "lockout_threshold_check": lockout_pass,
                "failed_login_attempts": failed_attempts,
                "lockout_threshold": lockout_thresh,
                "policy_score": policy_score
            }

            clean_findings = list(dict.fromkeys(findings))
            clean_recs = list(dict.fromkeys(recommendations))

            return json.dumps({
                "success": True,
                "policy_score": policy_score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": clean_findings,
                "recommendations": clean_recs,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing PasswordPolicyTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "policy_score": 0,
                "risk": "CRITICAL",
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"Password policy validation failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── VALIDATION HELPER METHODS ─────────────────────────────────────────────
    # =========================================================================

    def _validate_length(self, pwd: str, min_len: int, max_len: int) -> tuple[bool, Optional[str]]:
        """Validate password length against policy bounds."""
        length = len(pwd)
        if length < min_len:
            return False, f"Password length ({length} chars) is below mandatory minimum of {min_len} characters."
        if length > max_len:
            return False, f"Password length ({length} chars) exceeds maximum allowed threshold of {max_len} characters."
        return True, None

    def _validate_complexity(
        self,
        pwd: str,
        min_upper: int,
        min_lower: int,
        min_digits: int,
        min_symbols: int
    ) -> tuple[Dict[str, bool], List[str]]:
        """Validate uppercase, lowercase, numeric, and symbol complexity."""
        upper_cnt = len(re.findall(r'[A-Z]', pwd))
        lower_cnt = len(re.findall(r'[a-z]', pwd))
        digit_cnt = len(re.findall(r'[0-9]', pwd))
        symbol_cnt = len(re.findall(r'[^a-zA-Z0-9]', pwd))

        upper_pass = upper_cnt >= min_upper
        lower_pass = lower_cnt >= min_lower
        digits_pass = digit_cnt >= min_digits
        symbols_pass = symbol_cnt >= min_symbols

        findings = []
        if not upper_pass:
            findings.append(f"Insufficient uppercase letters ({upper_cnt} found, minimum {min_upper} required).")
        if not lower_pass:
            findings.append(f"Insufficient lowercase letters ({lower_cnt} found, minimum {min_lower} required).")
        if not digits_pass:
            findings.append(f"Insufficient numeric digits ({digit_cnt} found, minimum {min_digits} required).")
        if not symbols_pass:
            findings.append(f"Insufficient special symbols ({symbol_cnt} found, minimum {min_symbols} required).")

        results = {
            "upper": upper_pass,
            "lower": lower_pass,
            "digits": digits_pass,
            "symbols": symbols_pass
        }
        return results, findings

    def _validate_expiration(self, pwd_age_days: int, max_age_days: int) -> tuple[bool, Optional[str]]:
        """Check whether password exceeds expiration policy."""
        if max_age_days > 0 and pwd_age_days > max_age_days:
            return False, f"Password is expired ({pwd_age_days} days old, policy limit is {max_age_days} days)."
        return True, None

    def _validate_history_reuse(self, is_reused: bool, history_depth: int) -> tuple[bool, Optional[str]]:
        """Check whether password matches previously used password history."""
        if is_reused:
            return False, f"Password reuse detected within the last {history_depth} historical passwords."
        return True, None

    def _validate_lockout_threshold(self, failed_attempts: int, threshold: int) -> tuple[bool, Optional[str]]:
        """Evaluate account lockout risk based on failed login attempts."""
        if threshold > 0 and failed_attempts >= threshold:
            return False, f"Account threshold exceeded ({failed_attempts} failed attempts, lockout threshold is {threshold})."
        return True, None

    def _determine_risk(self, score: int, is_reused: bool, expiration_pass: bool) -> str:
        """Map score and critical policy violations to risk level."""
        if is_reused or score < 40:
            return "CRITICAL"
        if not expiration_pass or score < 60:
            return "HIGH"
        if score < 80:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(
        self,
        policy: Dict[str, Any],
        checks: List[bool],
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Generate targeted policy compliance recommendations."""
        if all(checks):
            recommendations.append("Password meets all enterprise security policy guidelines.")
            return

        if not checks[0]:
            recommendations.append(f"Ensure password length is between {policy.get('min_length', 12)} and {policy.get('max_length', 128)} characters.")
        if not checks[1]:
            recommendations.append(f"Include at least {policy.get('min_uppercase', 1)} uppercase letter(s).")
        if not checks[2]:
            recommendations.append(f"Include at least {policy.get('min_lowercase', 1)} lowercase letter(s).")
        if not checks[3]:
            recommendations.append(f"Include at least {policy.get('min_digits', 1)} numeric digit(s).")
        if not checks[4]:
            recommendations.append(f"Include at least {policy.get('min_symbols', 1)} special symbol(s) (e.g. !@#$%^&*).")
        if not checks[5]:
            recommendations.append("Rotate password immediately due to expiration policy enforcement.")
        if not checks[6]:
            recommendations.append("Select a new password that has not been used in recent password history.")
        if not checks[7]:
            recommendations.append("Reset account lockout state via administrative authorization or MFA step-up.")
