"""
PasswordRiskTool — Unified Enterprise Password Security Assessment Tool
========================================================================
Aggregates outputs from PasswordStrengthTool, PasswordPolicyTool,
PasswordLeakTool, and MFAAssessmentTool to generate a unified password
security assessment report.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Default component weights in the unified scoring model (sums to 1.0)
DEFAULT_WEIGHTS = {
    "strength": 0.25,
    "policy": 0.25,
    "leak": 0.30,
    "mfa": 0.20,
}

_SEVERITY_KEYWORDS = [
    "critical", "breached", "compromised", "leak", "expired", "reused",
    "disabled", "sms", "weak", "short", "violation", "insufficient"
]


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordRiskToolInput(BaseModel):
    """Input schema for PasswordRiskTool."""

    strength: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from PasswordStrengthTool.",
    )
    policy: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from PasswordPolicyTool.",
    )
    leak: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from PasswordLeakTool.",
    )
    mfa: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from MFAAssessmentTool.",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordRiskTool(BaseTool):
    """
    Unified Enterprise Password Security Assessment Aggregator.

    Fuses strength, policy compliance, data breach exposure, and MFA readiness telemetry
    into a single enterprise assessment report with overall security score (0–100),
    confidence rating, merged evidence, recommendations, and executive summary.
    """

    name: str = "Password Risk Tool"
    description: str = (
        "Aggregates outputs from PasswordStrengthTool, PasswordPolicyTool, "
        "PasswordLeakTool, and MFAAssessmentTool into a unified enterprise "
        "password security assessment. Computes overall password security score (0–100), "
        "confidence level, overall risk (LOW/MEDIUM/HIGH/CRITICAL), merged evidence, "
        "recommendations, and executive summary."
    )
    args_schema: Type[BaseModel] = PasswordRiskToolInput

    def _run(
        self,
        strength: Optional[Dict[str, Any]] = None,
        policy: Optional[Dict[str, Any]] = None,
        leak: Optional[Dict[str, Any]] = None,
        mfa: Optional[Dict[str, Any]] = None
    ) -> str:
        """Execute unified password security risk aggregation."""
        if isinstance(strength, str):
            try: strength = json.loads(strength)
            except Exception: strength = {"password": strength}
        if isinstance(policy, str):
            try: policy = json.loads(policy)
            except Exception: policy = {}
        if isinstance(leak, str):
            try: leak = json.loads(leak)
            except Exception: leak = {}
        if isinstance(mfa, str):
            try: mfa = json.loads(mfa)
            except Exception: mfa = {}

        strength = strength or {}
        policy = policy or {}
        leak = leak or {}
        mfa = mfa or {}

        logger.info("PasswordRiskTool: aggregating password security telemetry")

        try:
            # 1. Extract Individual Component Scores (Normalized to 0-100 Safety)
            str_score = self._extract_strength_score(strength)
            pol_score = self._extract_policy_score(policy)
            breach_safety_score, raw_leak_score = self._extract_leak_score(leak)
            mfa_score_val = self._extract_mfa_score(mfa)

            # 2. Compute Weighted Security Score
            overall_score = self._compute_weighted_score(
                str_score=str_score,
                pol_score=pol_score,
                breach_safety_score=breach_safety_score,
                mfa_score=mfa_score_val
            )

            # 3. Determine Overall Risk & Confidence
            is_breached = leak.get("breached", False)
            mfa_enabled = mfa.get("dashboard", {}).get("mfa_enabled", mfa.get("mfa_enabled", True))
            overall_risk = self._determine_overall_risk(overall_score, is_breached, mfa_enabled)
            confidence = self._compute_confidence([strength, policy, leak, mfa])

            # 4. Merge Evidence & Recommendations
            evidence = self._merge_evidence(strength, policy, leak, mfa)
            recommendations = self._merge_recommendations(
                strength, policy, leak, mfa, is_breached, mfa_enabled, overall_risk
            )

            # 5. Build Dashboard Telemetry
            dashboard = {
                "strength_score": str_score if str_score is not None else 0,
                "policy_score": pol_score if pol_score is not None else 0,
                "breach_score": breach_safety_score if breach_safety_score is not None else 100,
                "mfa_score": mfa_score_val if mfa_score_val is not None else 0,
                "overall_score": overall_score
            }

            # 6. Generate Executive Summary
            executive_summary = self._generate_executive_summary(
                overall_score=overall_score,
                overall_risk=overall_risk,
                confidence=confidence,
                is_breached=is_breached,
                mfa_enabled=mfa_enabled,
                str_score=str_score,
                pol_score=pol_score,
                mfa_score=mfa_score_val
            )

            return json.dumps({
                "success": True,
                "overall_risk": overall_risk,
                "password_security_score": overall_score,
                "confidence": confidence,
                "dashboard": dashboard,
                "evidence": evidence,
                "recommendations": recommendations,
                "executive_summary": executive_summary,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing PasswordRiskTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "overall_risk": "CRITICAL",
                "password_security_score": 0,
                "confidence": 0,
                "dashboard": {},
                "evidence": [],
                "recommendations": [],
                "executive_summary": "",
                "error": f"Password risk aggregation failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER EXTRACTION & SCORING METHODS ──────────────────────────────────
    # =========================================================================

    def _extract_strength_score(self, data: Dict[str, Any]) -> Optional[int]:
        """Extract strength score (0-100)."""
        if not data:
            return None
        val = data.get("password_score")
        if val is None:
            val = data.get("score")
        if val is not None:
            # Map zxcvbn 0-4 scale to 0-100 if necessary
            if isinstance(val, int) and val <= 4 and "entropy" in data:
                return min(100, val * 25)
            return max(0, min(100, int(val)))
        return None

    def _extract_policy_score(self, data: Dict[str, Any]) -> Optional[int]:
        """Extract policy compliance score (0-100)."""
        if not data:
            return None
        val = data.get("policy_score")
        if val is not None:
            return max(0, min(100, int(val)))
        return None

    def _extract_leak_score(self, data: Dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
        """
        Extract leak exposure risk score and compute breach safety score.
        Breach Safety Score = 100 - Leak Risk Score.
        """
        if not data:
            return None, None
        is_breached = data.get("breached", False)
        raw_score = data.get("password_score", data.get("score", 0))

        if is_breached:
            leak_risk = max(10, int(raw_score)) if raw_score else 85
            safety_score = max(0, 100 - leak_risk)
        else:
            leak_risk = 0
            safety_score = 100

        return safety_score, leak_risk

    def _extract_mfa_score(self, data: Dict[str, Any]) -> Optional[int]:
        """Extract MFA readiness score (0-100)."""
        if not data:
            return None
        val = data.get("mfa_score")
        if val is None:
            val = data.get("dashboard", {}).get("mfa_score")
        if val is not None:
            return max(0, min(100, int(val)))
        return None

    def _compute_weighted_score(
        self,
        str_score: Optional[int],
        pol_score: Optional[int],
        breach_safety_score: Optional[int],
        mfa_score: Optional[int]
    ) -> int:
        """Computes overall weighted password security score (0-100)."""
        components = {
            "strength": str_score,
            "policy": pol_score,
            "leak": breach_safety_score,
            "mfa": mfa_score
        }

        available = {k: v for k, v in components.items() if v is not None}
        if not available:
            return 0

        weight_sum = sum(DEFAULT_WEIGHTS[k] for k in available)
        weighted_val = sum(available[k] * (DEFAULT_WEIGHTS[k] / weight_sum) for k in available)
        return int(round(weighted_val))

    def _determine_overall_risk(self, score: int, is_breached: bool, mfa_enabled: bool) -> str:
        """Determine overall risk classification."""
        if (is_breached and not mfa_enabled) or score < 40:
            return "CRITICAL"
        if is_breached or score < 60:
            return "HIGH"
        if score < 80:
            return "MEDIUM"
        return "LOW"

    def _compute_confidence(self, tool_outputs: List[Dict[str, Any]]) -> int:
        """Compute confidence score based on tool data availability."""
        provided_tools = sum(1 for t in tool_outputs if t and t.get("success", True))
        if provided_tools == 4:
            return 98
        elif provided_tools == 3:
            return 85
        elif provided_tools == 2:
            return 70
        elif provided_tools == 1:
            return 50
        return 20

    def _merge_evidence(
        self,
        strength: Dict[str, Any],
        policy: Dict[str, Any],
        leak: Dict[str, Any],
        mfa: Dict[str, Any]
    ) -> List[str]:
        """Merge, deduplicate, and prioritize evidence findings."""
        raw_evidence: List[str] = []
        for t in (strength, policy, leak, mfa):
            if t and isinstance(t.get("findings"), list):
                raw_evidence.extend(t["findings"])

        # Deduplicate
        deduped = list(dict.fromkeys(raw_evidence))

        # Sort by severity priority
        def severity_key(item: str) -> int:
            lower_item = item.lower()
            for idx, kw in enumerate(_SEVERITY_KEYWORDS):
                if kw in lower_item:
                    return idx
            return 999

        deduped.sort(key=severity_key)
        return deduped

    def _merge_recommendations(
        self,
        strength: Dict[str, Any],
        policy: Dict[str, Any],
        leak: Dict[str, Any],
        mfa: Dict[str, Any],
        is_breached: bool,
        mfa_enabled: bool,
        risk: str
    ) -> List[str]:
        """Merge and refine targeted recommendations."""
        recs: List[str] = []

        if is_breached:
            recs.append("Replace breached password immediately across all accounts.")

        if not mfa_enabled:
            recs.append("Enable Multi-Factor Authentication (MFA) immediately to prevent unauthorized access.")

        # Collect sub-tool recommendations
        for t in (leak, strength, policy, mfa):
            if t and isinstance(t.get("recommendations"), list):
                recs.extend(t["recommendations"])

        recs.append("Use an enterprise password manager to generate and store high-entropy passwords.")
        recs.append("Ensure password complies with all enterprise length and complexity policy guidelines.")

        return list(dict.fromkeys(recs))

    def _generate_executive_summary(
        self,
        overall_score: int,
        overall_risk: str,
        confidence: int,
        is_breached: bool,
        mfa_enabled: bool,
        str_score: Optional[int],
        pol_score: Optional[int],
        mfa_score: Optional[int]
    ) -> str:
        """Generate enterprise executive summary."""
        if overall_risk == "CRITICAL":
            if is_breached and not mfa_enabled:
                return (
                    f"CRITICAL RISK IDENTIFIED (Security Score: {overall_score}/100, Confidence: {confidence}%). "
                    "The credential has appeared in public data breaches and lacks Multi-Factor Authentication (MFA) protection. "
                    "Immediate password replacement and MFA enablement are required to prevent account compromise."
                )
            return (
                f"CRITICAL RISK IDENTIFIED (Security Score: {overall_score}/100, Confidence: {confidence}%). "
                "Severe security vulnerabilities detected, including policy non-compliance and weak password characteristics. "
                "Immediate remediation is required."
            )
        elif overall_risk == "HIGH":
            return (
                f"ELEVATED RISK IDENTIFIED (Security Score: {overall_score}/100, Confidence: {confidence}%). "
                "Password security assessment indicates elevated risk due to credential breach exposure or policy violations. "
                "Prompt password rotation and security hardening are recommended."
            )
        elif overall_risk == "MEDIUM":
            return (
                f"MODERATE RISK IDENTIFIED (Security Score: {overall_score}/100, Confidence: {confidence}%). "
                "Password meets basic operational requirements but exhibits minor policy gaps or missing MFA protections."
            )
        else:
            return (
                f"LOW RISK — STRONG POSTURE (Security Score: {overall_score}/100, Confidence: {confidence}%). "
                "Password meets high-entropy standards, enterprise policy guidelines, has no breach exposure, and is backed by robust MFA."
            )
