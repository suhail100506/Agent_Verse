"""
IncidentResponseTool — Unified Enterprise Incident Response Assessment Aggregator
===================================================================================
Aggregates telemetry from IncidentClassificationTool, MITREMappingTool,
ForensicEvidenceTool, and ContainmentPlanTool into a final SOC-ready Enterprise
Incident Response Assessment Report.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Severity to baseline score map
_SEVERITY_SCORE_MAP = {
    "CRITICAL": 95,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 30,
    "UNKNOWN": 40,
}

_SEVERITY_KEYWORDS = [
    "critical", "ransomware", "exfiltration", "p1", "breach", "lsass",
    "mimikatz", "vssadmin", "isolated", "malware", "priority", "suspicious"
]


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class IncidentResponseToolInput(BaseModel):
    """Input schema for IncidentResponseTool."""

    classification: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from IncidentClassificationTool.",
    )
    mitre: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from MITREMappingTool.",
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from ForensicEvidenceTool.",
    )
    containment: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dict output from ContainmentPlanTool.",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class IncidentResponseTool(BaseTool):
    """
    Unified Enterprise Incident Response Assessment Aggregator.

    Fuses incident classification, MITRE ATT&CK technique mapping, read-only forensic
    evidence, and containment response plans into a SOC-ready incident assessment report.
    Computes overall incident score (0–100), confidence level, response priority (P1–P5),
    merged evidence, recommendations, and executive summary.
    """

    name: str = "Incident Response Tool"
    description: str = (
        "Aggregates outputs from IncidentClassificationTool, MITREMappingTool, "
        "ForensicEvidenceTool, and ContainmentPlanTool to produce a final SOC-ready "
        "Enterprise Incident Response Report. Computes overall incident score (0–100), "
        "confidence level, response priority (P1–P5), merged evidence, recommendations, "
        "and executive summary."
    )
    args_schema: Type[BaseModel] = IncidentResponseToolInput

    def _run(
        self,
        classification: Optional[Dict[str, Any]] = None,
        mitre: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        containment: Optional[Dict[str, Any]] = None
    ) -> str:
        """Execute unified incident response aggregation."""
        classification = classification or {}
        mitre = mitre or {}
        evidence = evidence or {}
        containment = containment or {}

        logger.info("IncidentResponseTool: aggregating incident response telemetry")

        try:
            # 1. Extract Sub-Tool Metrics
            severity = classification.get("severity", containment.get("severity", "HIGH")).upper()
            priority = classification.get("priority", containment.get("priority", "P1")).upper()
            incident_type = classification.get("incident_type", "Malware")

            mapped_techniques = mitre.get("mapped_techniques", [])
            evidence_items = evidence.get("evidence", [])
            evidence_score = evidence.get("evidence_score", 0)

            containment_actions = containment.get("containment_actions", [])
            recovery_actions = containment.get("recovery_actions", [])

            # 2. Compute Overall Incident Score & Risk
            incident_score = self._compute_incident_score(
                severity=severity,
                priority=priority,
                techniques_count=len(mapped_techniques),
                evidence_count=len(evidence_items),
                evidence_score=evidence_score
            )

            overall_risk = self._determine_overall_risk(severity, priority, incident_score)
            confidence = self._compute_confidence([classification, mitre, evidence, containment])

            # 3. Formulate Telemetry Dashboard
            dashboard = {
                "incident_score": incident_score,
                "severity": severity,
                "priority": priority,
                "incident_type": incident_type,
                "mapped_techniques": len(mapped_techniques),
                "evidence_items": len(evidence_items),
                "containment_actions": len(containment_actions) + len(recovery_actions),
                "overall_score": incident_score
            }

            # 4. Merge Evidence & Recommendations
            merged_evidence = self._merge_evidence(classification, mitre, evidence, containment)
            merged_recommendations = self._merge_recommendations(
                classification, mitre, evidence, containment, priority, severity, incident_type
            )

            # 5. Generate Executive Summary
            executive_summary = self._generate_executive_summary(
                incident_type=incident_type,
                severity=severity,
                priority=priority,
                incident_score=incident_score,
                confidence=confidence,
                techniques_count=len(mapped_techniques),
                evidence_count=len(evidence_items),
                actions_count=len(containment_actions)
            )

            return json.dumps({
                "success": True,
                "overall_risk": overall_risk,
                "incident_score": incident_score,
                "confidence": confidence,
                "priority": priority,
                "dashboard": dashboard,
                "evidence": merged_evidence,
                "recommendations": merged_recommendations,
                "executive_summary": executive_summary,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing IncidentResponseTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "overall_risk": "CRITICAL",
                "incident_score": 0,
                "confidence": 0,
                "priority": "P1",
                "dashboard": {},
                "evidence": [],
                "recommendations": [],
                "executive_summary": "",
                "error": f"Incident response aggregation failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER SCORING & AGGREGATION METHODS ─────────────────────────────────
    # =========================================================================

    def _compute_incident_score(
        self,
        severity: str,
        priority: str,
        techniques_count: int,
        evidence_count: int,
        evidence_score: int
    ) -> int:
        """Computes 0–100 overall incident severity/urgency score."""
        base = _SEVERITY_SCORE_MAP.get(severity, 75)

        # Priority boost
        if priority == "P1":
            base = max(base, 90)
        elif priority == "P2":
            base = max(base, 80)

        # MITRE technique boost
        base += min(10, techniques_count * 2)

        # Evidence completeness boost
        if evidence_score >= 80 or evidence_count >= 5:
            base += 5

        return min(100, max(0, base))

    def _determine_overall_risk(self, severity: str, priority: str, score: int) -> str:
        """Determines overall risk level."""
        if priority == "P1" or severity == "CRITICAL" or score >= 90:
            return "CRITICAL"
        if priority == "P2" or severity == "HIGH" or score >= 75:
            return "HIGH"
        if priority == "P3" or severity == "MEDIUM" or score >= 50:
            return "MEDIUM"
        return "LOW"

    def _compute_confidence(self, tool_outputs: List[Dict[str, Any]]) -> int:
        """Computes confidence level based on tool outputs completeness."""
        provided = sum(1 for t in tool_outputs if t and t.get("success", True))
        if provided == 4:
            return 99
        elif provided == 3:
            return 88
        elif provided == 2:
            return 72
        elif provided == 1:
            return 55
        return 20

    def _merge_evidence(
        self,
        classification: Dict[str, Any],
        mitre: Dict[str, Any],
        evidence: Dict[str, Any],
        containment: Dict[str, Any]
    ) -> List[str]:
        """Merge, deduplicate, and prioritize evidence items."""
        raw: List[str] = []
        for t in (classification, mitre, evidence, containment):
            if t and isinstance(t.get("findings"), list):
                raw.extend(t["findings"])

        # Add explicit evidence items if present
        if evidence and isinstance(evidence.get("evidence"), list):
            for item in evidence["evidence"]:
                if isinstance(item, dict):
                    raw.append(f"Forensic Artifact [{item.get('artifact_type', 'FILE')}]: {item.get('name', 'artifact')} (Hash: {item.get('hash_sha256', '')[:12]}...)")

        # Deduplicate
        deduped = list(dict.fromkeys(raw))

        # Sort by severity keyword priority
        def severity_key(text: str) -> int:
            lower_text = text.lower()
            for idx, kw in enumerate(_SEVERITY_KEYWORDS):
                if kw in lower_text:
                    return idx
            return 999

        deduped.sort(key=severity_key)
        return deduped

    def _merge_recommendations(
        self,
        classification: Dict[str, Any],
        mitre: Dict[str, Any],
        evidence: Dict[str, Any],
        containment: Dict[str, Any],
        priority: str,
        severity: str,
        incident_type: str
    ) -> List[str]:
        """Merge and refine targeted incident response playbooks."""
        recs: List[str] = []

        # Standard Incident Response Core Playbook Actions
        if priority in ("P1", "P2"):
            recs.append("Immediate containment: Isolate affected host(s) and block malicious IPs/domains at network perimeter.")
            recs.append("Forensic preservation: Seal disk/memory evidence inventory in WORM storage with SHA-256 chain-of-custody verification.")
            recs.append("Credential rotation: Force domain-wide password resets and revoke active OAuth & session tokens for compromised accounts.")

        recs.append("Threat hunting: Search SIEM/EDR logs for co-occurring MITRE ATT&CK techniques across enterprise endpoints.")
        recs.append("Continuous monitoring: Enable elevated SOC monitoring and host telemetry logging for at least 72 hours.")
        recs.append("Executive notification: Brief CISO, Legal, and PR stakeholders according to enterprise incident management guidelines.")

        # Sub-tool recommendations
        for t in (containment, mitre, classification, evidence):
            if t and isinstance(t.get("recommendations"), list):
                recs.extend(t["recommendations"])

        return list(dict.fromkeys(recs))

    def _generate_executive_summary(
        self,
        incident_type: str,
        severity: str,
        priority: str,
        incident_score: int,
        confidence: int,
        techniques_count: int,
        evidence_count: int,
        actions_count: int
    ) -> str:
        """Generate a concise, SOC-ready executive summary."""
        if priority in ("P1", "P2") or severity in ("CRITICAL", "HIGH"):
            return (
                f"CRITICAL INCIDENT IDENTIFIED — Priority: {priority}, Severity: {severity} "
                f"(Incident Score: {incident_score}/100, Confidence: {confidence}%). "
                f"Triage classified incident as [{incident_type}] with {techniques_count} mapped MITRE ATT&CK technique(s) "
                f"and {evidence_count} forensic artifact(s) secured under chain-of-custody. "
                f"Immediate host isolation, credential revocation, and {actions_count} containment action(s) are required."
            )
        return (
            f"INCIDENT ASSESSMENT COMPLETE — Priority: {priority}, Severity: {severity} "
            f"(Incident Score: {incident_score}/100, Confidence: {confidence}%). "
            f"Incident categorized as [{incident_type}]. {actions_count} containment and recovery action(s) recommended."
        )
