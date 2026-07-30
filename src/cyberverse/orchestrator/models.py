"""
models.py — Pydantic models for the CyberVerse Multi-Agent Orchestrator
========================================================================
Defines all data contracts flowing through the orchestration layer:
  - SecurityAnalysisRequest   (API input)
  - SpecialistResult          (per-specialist output)
  - OrchestratorReport        (final merged report)
  - OrchestratorState         (CrewAI Flow state)
  - ReportSummary             (list-view DTO)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

AVAILABLE_SPECIALISTS = [
    "certificate_verification_specialist",
    "privacy_compliance_analyst",
    "malware_analysis_specialist",
    "threat_detection_specialist",
    "identity_verification_specialist",
    "fraud_detection_specialist",
    "phishing_detection_specialist",
    "password_security_advisor",
    "incident_response_specialist",
]


# ---------------------------------------------------------------------------
# API Input
# ---------------------------------------------------------------------------

class SecurityAnalysisRequest(BaseModel):
    """
    Input payload sent to POST /api/v1/analyze.

    `specialists` — list of specialist keys to invoke.
                   Pass an empty list or omit to run ALL specialists.
    `inputs`      — free-form dict passed into each specialist's tools.
    `label`       — optional human-readable label for the report.
    """

    specialists: List[str] = Field(
        default_factory=list,
        description="Specialist keys to invoke. Empty = run all.",
        examples=[["password_security_advisor", "phishing_detection_specialist"]],
    )
    inputs: Dict[str, Any] = Field(
        default_factory=dict,
        description="Freeform input dict forwarded to each specialist.",
        examples=[{"password": "P@ssw0rd!123", "email_subject": "Verify your account"}],
    )
    label: Optional[str] = Field(
        default=None,
        description="Optional human-readable label for this analysis run.",
        examples=["Production audit — Q3 2026"],
    )

    def resolved_specialists(self) -> List[str]:
        """Return the de-duplicated specialist list, defaulting to all."""
        if not self.specialists:
            return list(AVAILABLE_SPECIALISTS)
        return list(dict.fromkeys(s for s in self.specialists if s in AVAILABLE_SPECIALISTS))


# ---------------------------------------------------------------------------
# Per-Specialist Result
# ---------------------------------------------------------------------------

class SpecialistResult(BaseModel):
    """Result produced by one specialist during an orchestration run."""

    specialist: str = Field(description="Specialist key name.")
    display_name: str = Field(description="Human-readable specialist name.")
    success: bool = Field(default=True)
    score: int = Field(default=0, ge=0, le=100, description="Primary risk/security score (0-100).")
    risk_level: RiskLevel = Field(default="UNKNOWN")
    confidence: int = Field(default=0, ge=0, le=100)
    dashboard: Dict[str, Any] = Field(default_factory=dict)
    findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    executive_summary: str = Field(default="")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Full tool output.")
    error: Optional[str] = Field(default=None)
    duration_ms: int = Field(default=0, description="Wall-clock execution time in ms.")


# ---------------------------------------------------------------------------
# Platform Risk Score
# ---------------------------------------------------------------------------

class PlatformRisk(BaseModel):
    """Aggregated platform-level risk metrics."""

    overall_score: int = Field(ge=0, le=100)
    overall_risk: RiskLevel
    confidence: int = Field(ge=0, le=100)
    specialists_run: int
    specialists_succeeded: int
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    score_breakdown: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Final Orchestrator Report
# ---------------------------------------------------------------------------

class OrchestratorReport(BaseModel):
    """
    Final enterprise-grade report produced by the orchestrator.
    This is the top-level object stored and returned by the API.
    """

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    label: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: Literal["pending", "running", "completed", "failed"] = "completed"
    request_inputs: Dict[str, Any] = Field(default_factory=dict)

    platform_risk: PlatformRisk
    specialist_results: List[SpecialistResult] = Field(default_factory=list)

    # Merged outputs
    all_findings: List[str] = Field(default_factory=list)
    all_recommendations: List[str] = Field(default_factory=list)
    executive_summary: str = Field(default="")

    total_duration_ms: int = Field(default=0)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ---------------------------------------------------------------------------
# Report List DTO
# ---------------------------------------------------------------------------

class ReportSummary(BaseModel):
    """Lightweight DTO for report list views."""

    report_id: str
    label: Optional[str] = None
    created_at: datetime
    overall_risk: RiskLevel
    overall_score: int
    specialists_run: int
    status: str

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ---------------------------------------------------------------------------
# CrewAI Flow State
# ---------------------------------------------------------------------------

class OrchestratorState(BaseModel):
    """Mutable state threaded through the SecurityAnalysisFlow."""

    request: Optional[SecurityAnalysisRequest] = None
    specialist_results: List[SpecialistResult] = Field(default_factory=list)
    report: Optional[OrchestratorReport] = None
    errors: List[str] = Field(default_factory=list)
