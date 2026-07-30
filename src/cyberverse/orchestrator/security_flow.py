"""
security_flow.py — CyberVerse Multi-Agent Orchestrator Flow
============================================================
Uses CrewAI Flow to fan-out analysis across selected specialists
in parallel (asyncio.gather), then aggregate into an OrchestratorReport.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from crewai.flow.flow import Flow, listen, start

from cyberverse.orchestrator.models import (
    OrchestratorReport,
    OrchestratorState,
    SecurityAnalysisRequest,
    SpecialistResult,
)
from cyberverse.orchestrator.risk_calculator import calculate_platform_risk
from cyberverse.orchestrator.specialist_registry import run_specialist

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Executive Summary Generator
# ---------------------------------------------------------------------------

_RISK_PHRASES = {
    "CRITICAL": (
        "CRITICAL security posture detected. Immediate executive escalation and emergency "
        "response protocols are required. Multiple high-severity vulnerabilities and/or active "
        "threats have been identified across the platform."
    ),
    "HIGH": (
        "HIGH risk security posture identified. Significant vulnerabilities require prioritized "
        "remediation within 24 hours. Security team escalation is recommended."
    ),
    "MEDIUM": (
        "MEDIUM risk security posture. Several issues require attention. Remediation should be "
        "scheduled within the next sprint cycle."
    ),
    "LOW": (
        "LOW risk security posture. The platform demonstrates strong security controls. "
        "Continue monitoring and address minor findings as part of routine maintenance."
    ),
    "UNKNOWN": (
        "Security posture could not be fully determined. Review individual specialist results "
        "and re-run failed analyses."
    ),
}


def _generate_executive_summary(
    platform_risk,
    specialist_results: List[SpecialistResult],
    inputs: Dict[str, Any],
) -> str:
    succeeded = [r for r in specialist_results if r.success]
    failed = [r for r in specialist_results if not r.success]

    base = _RISK_PHRASES.get(platform_risk.overall_risk, _RISK_PHRASES["UNKNOWN"])

    critical_specialists = [r.display_name for r in succeeded if r.risk_level == "CRITICAL"]
    high_specialists = [r.display_name for r in succeeded if r.risk_level == "HIGH"]

    parts = [base]
    if critical_specialists:
        parts.append(
            f"Critical findings from: {', '.join(critical_specialists)}."
        )
    if high_specialists:
        parts.append(
            f"High-severity findings from: {', '.join(high_specialists)}."
        )
    parts.append(
        f"Analysis completed across {platform_risk.specialists_succeeded}/"
        f"{platform_risk.specialists_run} specialists "
        f"with {platform_risk.confidence}% confidence."
    )
    if failed:
        parts.append(
            f"Note: {len(failed)} specialist(s) could not complete analysis: "
            f"{', '.join(r.display_name for r in failed)}."
        )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# SecurityAnalysisFlow
# ---------------------------------------------------------------------------

class SecurityAnalysisFlow(Flow[OrchestratorState]):
    """
    CyberVerse Multi-Agent Orchestration Flow.

    Steps
    -----
    1. dispatch()  — fan-out: run each specialist in a ThreadPoolExecutor
    2. aggregate() — merge results into an OrchestratorReport
    """

    # ── Step 1 ──────────────────────────────────────────────────────────────

    @start()
    def dispatch(self) -> List[SpecialistResult]:
        """Dispatch analysis to all selected specialists in parallel."""
        if self.state.request is None:
            logger.error("No request set on flow state before kickoff.")
            return []

        request = self.state.request
        specialists = request.resolved_specialists()
        inputs = request.inputs

        logger.info("Dispatching to %d specialists: %s", len(specialists), specialists)

        results: List[SpecialistResult] = []

        def _run_one(spec: str) -> SpecialistResult:
            logger.info("Starting specialist: %s", spec)
            return run_specialist(spec, inputs)

        with ThreadPoolExecutor(max_workers=min(len(specialists), 9)) as executor:
            futures = {executor.submit(_run_one, s): s for s in specialists}
            for future in futures:
                try:
                    result = future.result(timeout=120)
                    results.append(result)
                    logger.info(
                        "Specialist %s completed — score=%d risk=%s",
                        result.specialist,
                        result.score,
                        result.risk_level,
                    )
                except Exception as exc:
                    spec = futures[future]
                    logger.exception("Specialist %s raised an exception: %s", spec, exc)
                    results.append(
                        SpecialistResult(
                            specialist=spec,
                            display_name=spec.replace("_", " ").title(),
                            success=False,
                            error=str(exc),
                        )
                    )

        self.state.specialist_results = results
        return results

    # ── Step 2 ──────────────────────────────────────────────────────────────

    @listen(dispatch)
    def aggregate(self, specialist_results: List[SpecialistResult]) -> OrchestratorReport:
        """Aggregate specialist results into a final OrchestratorReport."""
        request = self.state.request
        inputs = request.inputs if request else {}

        # --- Platform risk ---
        platform_risk = calculate_platform_risk(specialist_results)

        # --- Merge evidence + recommendations ---
        all_findings: List[str] = []
        all_recommendations: List[str] = []
        total_duration = 0

        for r in specialist_results:
            all_findings.extend(r.findings)
            all_recommendations.extend(r.recommendations)
            total_duration += r.duration_ms

        # Deduplicate while preserving order
        seen: set = set()
        deduped_findings: List[str] = []
        for f in all_findings:
            if f not in seen:
                seen.add(f)
                deduped_findings.append(f)

        seen = set()
        deduped_recs: List[str] = []
        for r in all_recommendations:
            if r not in seen:
                seen.add(r)
                deduped_recs.append(r)

        # --- Executive summary ---
        executive_summary = _generate_executive_summary(
            platform_risk, specialist_results, inputs
        )

        report = OrchestratorReport(
            label=request.label if request else None,
            status="completed",
            request_inputs=inputs,
            platform_risk=platform_risk,
            specialist_results=specialist_results,
            all_findings=deduped_findings,
            all_recommendations=deduped_recs,
            executive_summary=executive_summary,
            total_duration_ms=total_duration,
        )

        self.state.report = report
        logger.info(
            "Orchestration complete — report_id=%s overall_risk=%s score=%d",
            report.report_id,
            platform_risk.overall_risk,
            platform_risk.overall_score,
        )
        return report


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def run_security_analysis(
    request: SecurityAnalysisRequest,
) -> OrchestratorReport:
    """
    Synchronous convenience wrapper around SecurityAnalysisFlow.
    Builds a fresh flow, sets the request on state, and kicks off.
    Returns the final OrchestratorReport.
    """
    flow = SecurityAnalysisFlow()
    flow.state.request = request
    t0 = time.monotonic()
    flow.kickoff()
    elapsed = int((time.monotonic() - t0) * 1000)

    if flow.state.report is None:
        # Shouldn't happen, but guard defensively
        from cyberverse.orchestrator.models import PlatformRisk
        return OrchestratorReport(
            label=request.label,
            status="failed",
            request_inputs=request.inputs,
            platform_risk=PlatformRisk(
                overall_score=0,
                overall_risk="UNKNOWN",
                confidence=0,
                specialists_run=0,
                specialists_succeeded=0,
            ),
            executive_summary="Orchestration failed to produce a report.",
            total_duration_ms=elapsed,
        )

    flow.state.report.total_duration_ms = elapsed
    return flow.state.report
