"""
MITREMappingTool — MITRE ATT&CK Framework Mapping Engine
=========================================================
Maps detected indicators, commands, behaviors, and incident telemetry to the
MITRE ATT&CK Enterprise Framework (Tactics, Technique IDs, Kill Chain stages, Threat Actor Hints).
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── MITRE ATT&CK TECHNIQUE KNOWLEDGE BASE ───────────────────────────────────
# ===========================================================================

_ATTACK_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "kill_chain_phase": "Execution",
        "patterns": [r"\bpowershell(?:\.exe)?\b", r"\bposh\b", r"\bpwsh\b"],
    },
    {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "kill_chain_phase": "Execution",
        "patterns": [r"\bcmd(?:\.exe)?\b", r"\bcommand\s+prompt\b"],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Exploitation",
        "patterns": [r"\bbase64\b", r"\bencoded\s+command\b", r"-enc(?:odedcommand)?\b", r"\bobfuscat\w*\b"],
    },
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "patterns": [r"\bphish\w*\b", r"\battachment\s+lure\b", r"\bmalicious\s+(?:doc|docx|pdf|zip|rar)\b"],
    },
    {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "patterns": [r"\bmalicious\s+link\b", r"\bphish\w*\s+link\b", r"\bspoofed\s+url\b"],
    },
    {
        "id": "T1003.001",
        "name": "LSASS Memory Credential Dumping",
        "tactic": "Credential Access",
        "kill_chain_phase": "Actions on Objectives",
        "patterns": [r"\bmimikatz\b", r"\blsass(?:\.exe)?\b", r"\bprocdump\b", r"\bpass-the-hash\b", r"\bsekurlsa\b"],
    },
    {
        "id": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "Credential Access",
        "kill_chain_phase": "Actions on Objectives",
        "patterns": [r"\bkerberoast\w*\b", r"\bspn\s+request\b", r"\btgs-req\b"],
    },
    {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "kill_chain_phase": "Actions on Objectives",
        "patterns": [r"\bvssadmin\b", r"\bshadow\s*cop(y|ies)\b", r"\bdelete\s+shadows\b", r"\bwbadmin\b", r"\bbcdedit\b"],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "kill_chain_phase": "Actions on Objectives",
        "patterns": [r"\bransom(?:ware)?\b", r"\bencrypt\w*\b", r"\.locked\b", r"\bransom_note\b"],
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "kill_chain_phase": "Command & Control",
        "patterns": [r"\bbeacon\b", r"\bc2\b", r"\bcommand\s+and\s+control\b", r"\bhttp(?:s)?\s+c2\b", r"\bcobalt\s*strike\b"],
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "kill_chain_phase": "Actions on Objectives",
        "patterns": [r"\bexfil\w*\b", r"\brclone\b", r"\bmega\.nz\b", r"\bdata\s+leak\b"],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "kill_chain_phase": "Exploitation",
        "patterns": [r"\bsql\s+injection\b", r"\bsqli\b", r"\bxss\b", r"\bwebshell\b", r"\brce\b", r"\bpath\s+traversal\b"],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "kill_chain_phase": "Exploitation",
        "patterns": [r"\baccount\s+takeover\b", r"\bato\b", r"\bimpossible\s+travel\b", r"\bmfa\s+fatigue\b"],
    },
]

# Threat actor correlation hints based on technique combinations
_ACTOR_HINTS: Dict[str, List[str]] = {
    "Wizard Spider / Conti / LockBit": ["T1490", "T1486", "T1059.001", "T1003.001"],
    "APT29 (Cozy Bear / Nobelium)": ["T1566.001", "T1059.001", "T1027", "T1071.001"],
    "FIN7": ["T1566.001", "T1059.001", "T1003.001", "T1027"],
    "Lazarus Group": ["T1190", "T1059.001", "T1041"],
}


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class MITREMappingToolInput(BaseModel):
    """Input schema for MITREMappingTool."""

    title: Optional[str] = Field(
        default="",
        description="Alert or incident title (e.g. 'Suspicious PowerShell Execution').",
    )
    description: Optional[str] = Field(
        default="",
        description="Alert description or process command line telemetry.",
    )
    text: Optional[str] = Field(
        default="",
        description="General text block or log snippet to parse.",
    )
    ioc: Optional[List[str]] = Field(
        default_factory=list,
        description="List of indicators of compromise (e.g. ['powershell.exe', 'Base64 Command']).",
    )
    incident_type: Optional[str] = Field(
        default="",
        description="Incident type category (e.g. 'Malware', 'Ransomware', 'Phishing').",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class MITREMappingTool(BaseTool):
    """
    MITRE ATT&CK Framework Automated Mapping Tool.

    Maps security indicators, commands, behaviors, and alert telemetry to MITRE ATT&CK
    tactics, technique IDs (Txxxx), Cyber Kill Chain stages, and threat actor hints.
    """

    name: str = "MITRE Mapping Tool"
    description: str = (
        "Maps incident indicators, commands, and telemetry to the MITRE ATT&CK framework. "
        "Returns mapped techniques (ID, Name, Tactic, Kill Chain Phase), tactics summary, "
        "threat actor hints, confidence rating, and dashboard telemetry."
    )
    args_schema: Type[BaseModel] = MITREMappingToolInput

    def _run(
        self,
        title: Optional[str] = "",
        description: Optional[str] = "",
        text: Optional[str] = "",
        ioc: Optional[List[str]] = None,
        incident_type: Optional[str] = ""
    ) -> str:
        """Execute rule-based MITRE ATT&CK mapping."""
        ioc = ioc or []
        combined_text = f"{title} {description} {text} {incident_type} {' '.join(ioc)}".lower()

        logger.info("MITREMappingTool: mapping telemetry to ATT&CK framework (len=%d)", len(combined_text))

        try:
            if not combined_text.strip():
                return json.dumps({
                    "success": False,
                    "mapped_techniques": [],
                    "confidence": 0,
                    "dashboard": {},
                    "findings": ["No input telemetry provided for MITRE ATT&CK mapping."],
                    "recommendations": ["Provide incident title, description, or IoCs for mapping."],
                    "error": "Input text or IoCs required."
                }, indent=2)

            # 1. Match ATT&CK Techniques
            mapped_techniques, matched_ids = self._map_techniques(combined_text)

            # 2. Extract Tactics & Primary Stage
            tactics = list(dict.fromkeys(t["tactic"] for t in mapped_techniques))
            kill_chain_phases = list(dict.fromkeys(t["kill_chain_phase"] for t in mapped_techniques))
            primary_tactic = tactics[0] if tactics else "Unknown"
            primary_kill_chain = kill_chain_phases[0] if kill_chain_phases else "Unknown"

            # 3. Correlate Threat Actor Hints
            actor_hints = self._correlate_threat_actors(matched_ids)

            # 4. Calculate Confidence Score
            tech_count = len(mapped_techniques)
            confidence = 95 if tech_count >= 2 else (85 if tech_count == 1 else 50)

            # 5. Formulate Telemetry Dashboard
            dashboard = {
                "techniques_count": tech_count,
                "tactics_count": len(tactics),
                "primary_tactic": primary_tactic,
                "kill_chain_stage": primary_kill_chain,
                "tactics_summary": tactics,
                "threat_actor_hints": actor_hints,
                "confidence": confidence
            }

            # 6. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_findings_and_recs(
                mapped_techniques=mapped_techniques,
                tactics=tactics,
                actor_hints=actor_hints,
                findings=findings,
                recommendations=recommendations
            )

            return json.dumps({
                "success": True,
                "mapped_techniques": mapped_techniques,
                "tactics_summary": tactics,
                "threat_actor_hints": actor_hints,
                "confidence": confidence,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing MITREMappingTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "mapped_techniques": [],
                "confidence": 0,
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"MITRE ATT&CK mapping failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _map_techniques(self, text: str) -> tuple[List[Dict[str, str]], Set[str]]:
        """Maps input text against ATT&CK pattern rules."""
        mapped = []
        matched_ids = set()

        for rule in _ATTACK_PATTERNS:
            for pattern in rule["patterns"]:
                if re.search(pattern, text, re.I):
                    tech_id = rule["id"]
                    if tech_id not in matched_ids:
                        matched_ids.add(tech_id)
                        mapped.append({
                            "id": rule["id"],
                            "name": rule["name"],
                            "tactic": rule["tactic"],
                            "kill_chain_phase": rule["kill_chain_phase"]
                        })
                    break
        return mapped, matched_ids

    def _correlate_threat_actors(self, matched_ids: Set[str]) -> List[str]:
        """Correlates matched ATT&CK techniques with threat actor profiles."""
        actor_hints = []
        for group_name, required_techs in _ACTOR_HINTS.items():
            intersection = set(required_techs).intersection(matched_ids)
            if len(intersection) >= 2:
                actor_hints.append(group_name)
        return actor_hints

    def _generate_findings_and_recs(
        self,
        mapped_techniques: List[Dict[str, str]],
        tactics: List[str],
        actor_hints: List[str],
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Populate findings and recommendations."""
        if not mapped_techniques:
            findings.append("No specific MITRE ATT&CK technique signatures identified in telemetry.")
            recommendations.append("Enhance endpoint command line auditing and SIEM detection coverage.")
            return

        tech_summary = ", ".join(f"{t['id']} ({t['name']})" for t in mapped_techniques[:4])
        findings.append(f"Mapped {len(mapped_techniques)} MITRE ATT&CK technique(s): {tech_summary}.")
        findings.append(f"Spans ATT&CK Tactic(s): {', '.join(tactics)}.")

        if actor_hints:
            findings.append(f"Tactical pattern correlates with threat actor behavior: {', '.join(actor_hints)}.")
            recommendations.append(f"Review threat intelligence advisories for {', '.join(actor_hints)}.")

        # MITRE mitigations based on mapped techniques
        matched_ids = {t["id"] for t in mapped_techniques}

        if "T1059.001" in matched_ids or "T1059.003" in matched_ids:
            recommendations.append("Enforce PowerShell Script Block Logging (Event ID 4104) and Constrained Language Mode.")
        if "T1003.001" in matched_ids:
            recommendations.append("Enable LSA Protection (RunAsPPL) and Credential Guard to prevent LSASS memory dumping.")
        if "T1490" in matched_ids:
            recommendations.append("Restrict administrative privileges for vssadmin.exe and monitor shadow copy deletion commands.")
        if "T1566.001" in matched_ids or "T1566.002" in matched_ids:
            recommendations.append("Harden email gateway controls with attachment sandboxing and link rewrites.")
