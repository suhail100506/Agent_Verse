"""
risk_calculator.py — Platform-Level Risk Aggregation
=====================================================
Calculates a single enterprise risk score across all
specialist results using a weighted average with
critical-incident escalation rules.
"""

from __future__ import annotations

from typing import List

from cyberverse.orchestrator.models import PlatformRisk, RiskLevel, SpecialistResult


# ---------------------------------------------------------------------------
# Weights — adjust to tune sensitivity of each specialist's contribution
# ---------------------------------------------------------------------------

_SPECIALIST_WEIGHTS: dict[str, float] = {
    "certificate_verification_specialist": 0.08,
    "privacy_compliance_analyst": 0.12,
    "malware_analysis_specialist": 0.15,
    "threat_detection_specialist": 0.13,
    "identity_verification_specialist": 0.10,
    "fraud_detection_specialist": 0.12,
    "phishing_detection_specialist": 0.10,
    "password_security_advisor": 0.10,
    "incident_response_specialist": 0.10,
}

_DEFAULT_WEIGHT = 0.10


def _score_to_risk(score: int) -> RiskLevel:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def calculate_platform_risk(specialist_results: List[SpecialistResult]) -> PlatformRisk:
    """
    Aggregate specialist results into a platform-level PlatformRisk object.

    Algorithm
    ---------
    1. Weighted average of all successful specialist scores.
    2. If any specialist returned CRITICAL → overall cannot drop below HIGH.
    3. Confidence = average confidence of successful specialists (capped at 99).
    4. Count by risk level for the dashboard breakdown.
    """
    if not specialist_results:
        return PlatformRisk(
            overall_score=0,
            overall_risk="UNKNOWN",
            confidence=0,
            specialists_run=0,
            specialists_succeeded=0,
        )

    succeeded = [r for r in specialist_results if r.success]
    failed = [r for r in specialist_results if not r.success]

    if not succeeded:
        return PlatformRisk(
            overall_score=0,
            overall_risk="UNKNOWN",
            confidence=0,
            specialists_run=len(specialist_results),
            specialists_succeeded=0,
        )

    # --- Weighted score ---
    total_weight = 0.0
    weighted_score = 0.0
    for r in succeeded:
        w = _SPECIALIST_WEIGHTS.get(r.specialist, _DEFAULT_WEIGHT)
        weighted_score += r.score * w
        total_weight += w

    raw_score = int(weighted_score / total_weight) if total_weight > 0 else 0
    overall_score = max(0, min(100, raw_score))

    # --- Risk level + escalation ---
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in succeeded:
        lvl = r.risk_level if r.risk_level in risk_counts else "UNKNOWN"
        risk_counts[lvl] += 1

    overall_risk = _score_to_risk(overall_score)

    # Escalation rules
    if risk_counts["CRITICAL"] >= 1 and overall_risk == "MEDIUM":
        overall_risk = "HIGH"
    if risk_counts["CRITICAL"] >= 2:
        overall_risk = "CRITICAL"

    # --- Confidence ---
    avg_confidence = int(sum(r.confidence for r in succeeded) / len(succeeded))
    # Penalise for failures
    if failed:
        penalty = min(20, len(failed) * 5)
        avg_confidence = max(0, avg_confidence - penalty)
    confidence = min(99, avg_confidence)

    # --- Score breakdown ---
    score_breakdown = {r.specialist: r.score for r in succeeded}

    return PlatformRisk(
        overall_score=overall_score,
        overall_risk=overall_risk,
        confidence=confidence,
        specialists_run=len(specialist_results),
        specialists_succeeded=len(succeeded),
        critical_count=risk_counts["CRITICAL"],
        high_count=risk_counts["HIGH"],
        medium_count=risk_counts["MEDIUM"],
        low_count=risk_counts["LOW"],
        score_breakdown=score_breakdown,
    )
