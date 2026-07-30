"""
IncidentClassificationTool — Automated Incident Categorization & Triage Engine
================================================================================
Classifies security alerts into incident categories (Malware, Ransomware, Phishing,
Credential Theft, Exfiltration, ATO, Web Attack, DDoS, Supply Chain, Insider Threat),
calculating incident severity, asset criticality, business impact, and priority (P1–P5).
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── INCIDENT TAXONOMY & KEYWORD PATTERNS ────────────────────────────────────
# ===========================================================================

_INCIDENT_RULES: Dict[str, List[str]] = {
    "Ransomware": [
        r"\bransom(?:ware)?\b", r"\bencrypt(?:ed|ion)?\b", r"\.locked\b",
        r"\bvssadmin\b", r"\bshadow\s*cop(y|ies)\b", r"\bransom_note\b",
        r"\bbitlocker\b", r"\bwannacry\b", r"\brevil\b", r"\blockbit\b",
    ],
    "Malware": [
        r"\bpowershell(?:\.exe)?\b", r"\bbase64\b", r"\bencoded\s+command\b",
        r"\btrojan\b", r"\bbackdoor\b", r"\bbeacon\b", r"\bc2\b", r"\bcommand\s+and\s+control\b",
        r"\bmalware\b", r"\bshellcode\b", r"\binject(?:ed|ion)?\b", r"\brundll32\b",
        r"\bmshta\b", r"\bprocdump\b",
    ],
    "Phishing": [
        r"\bphish(?:ing)?\b", r"\bemail\s+lure\b", r"\bspoofed?\s+sender\b",
        r"\bmalicious\s+link\b", r"\bcredential\s+harvest\b", r"\bspear\s*phish\b",
        r"\bdkim\s+fail\b", r"\bspf\s+fail\b",
    ],
    "Credential Theft": [
        r"\bmimikatz\b", r"\blsass(?:\.exe)?\b", r"\bpass-the-hash\b", r"\bpass\s+the\s+ticket\b",
        r"\bkerberoast(?:ing)?\b", r"\bntds\.dit\b", r"\bpassword\s+spray(?:ing)?\b",
        r"\bcredential\s+(?:theft|dump(?:ing)?)\b",
    ],
    "Insider Threat": [
        r"\binsider\b", r"\bunauthorized\s+export\b", r"\bmass\s+copy\b",
        r"\bafter\s+hours\s+download\b", r"\bdata\s+leak\b", r"\bemployee\s+misconduct\b",
    ],
    "Data Exfiltration": [
        r"\bexfil(?:tration)?\b", r"\brclone\b", r"\bmega\.nz\b", r"\blarge\s+outbound\b",
        r"\bdata\s+theft\b", r"\bsftp\s+transfer\b", r"\bstaging\s+folder\b",
    ],
    "Web Attack": [
        r"\bsql\s+injection\b", r"\bsqli\b", r"\bxss\b", r"\bcross-site\b",
        r"\bpath\s+traversal\b", r"\bwebshell\b", r"\brce\b", r"\bremote\s+code\s+execution\b",
        r"\bwaf\s+alert\b",
    ],
    "DDoS": [
        r"\bddos\b", r"\bdenial\s+of\s+service\b", r"\bsyn\s+flood\b", r"\budp\s+flood\b",
        r"\bvolumetric\s+attack\b", r"\btraffic\s+spike\b",
    ],
    "Account Takeover": [
        r"\baccount\s+takeover\b", r"\bato\b", r"\bimpossible\s+travel\b",
        r"\bmfa\s+fatigue\b", r"\bsession\s+hijack(?:ing)?\b", r"\bunusual\s+login\b",
    ],
    "Supply Chain": [
        r"\bsupply\s+chain\b", r"\bdependency\s+confusion\b", r"\bmalicious\s+package\b",
        r"\bsolarwinds\b", r"\bthird-party\s+breach\b", r"\bcompromised\s+vendor\b",
    ]
}

# High/Critical asset hostname patterns
_CRITICAL_ASSET_PATTERNS = [
    r"\bdc-?\d*\b", r"\bad-?\d*\b", r"\bdomain-?controller\b",
    r"\bprod-?\d*\b", r"\bdb-?\d*\b", r"\bdatabase\b",
    r"\bfinance-?\w*\b", r"\bpay-?\w*\b", r"\bexec-?\w*\b", r"\bceo-?\w*\b",
]


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class IncidentClassificationToolInput(BaseModel):
    """Input schema for IncidentClassificationTool."""

    incident_id: str = Field(
        default="INC-001",
        description="Unique incident identifier (e.g. 'INC-001', 'ALERT-9942').",
    )
    title: str = Field(
        ...,
        description="Alert or incident title (e.g. 'Suspicious PowerShell Execution').",
    )
    description: str = Field(
        default="",
        description="Detailed description of the incident telemetry.",
    )
    source: str = Field(
        default="SIEM",
        description="Detection telemetry source (e.g. 'EDR', 'SIEM', 'NDR', 'WAF', 'User Report').",
    )
    asset: str = Field(
        default="UNKNOWN-HOST",
        description="Affected asset hostname or IP address (e.g. 'FINANCE-PC-01', 'DC-01').",
    )
    severity: Optional[str] = Field(
        default="Unknown",
        description="Initial reported severity (e.g. 'Low', 'Medium', 'High', 'Critical', 'Unknown').",
    )
    ioc: Optional[List[str]] = Field(
        default_factory=list,
        description="List of associated indicators of compromise (e.g. ['powershell.exe', 'Base64 Command']).",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class IncidentClassificationTool(BaseTool):
    """
    Automated Incident Classification & Triage Tool.

    Classifies cybersecurity incidents based on title, description, telemetry source,
    affected assets, and indicators of compromise. Determines incident category,
    severity, asset criticality, business impact, and priority (P1–P5).
    """

    name: str = "Incident Classification Tool"
    description: str = (
        "Classifies cybersecurity incidents into taxonomy categories (Malware, Ransomware, "
        "Phishing, Credential Theft, Exfiltration, ATO, Web Attack, DDoS, Supply Chain, Insider Threat). "
        "Evaluates asset criticality, business impact, severity, and assigns priority (P1–P5)."
    )
    args_schema: Type[BaseModel] = IncidentClassificationToolInput

    def _run(
        self,
        incident_id: str = "INC-001",
        title: str = "",
        description: str = "",
        source: str = "SIEM",
        asset: str = "UNKNOWN-HOST",
        severity: Optional[str] = "Unknown",
        ioc: Optional[List[str]] = None
    ) -> str:
        """Execute automated incident classification and priority triage."""
        ioc = ioc or []

        logger.info(
            "IncidentClassificationTool: classifying incident %s — title='%s', asset='%s'",
            incident_id, title, asset
        )

        try:
            if not title and not description:
                return json.dumps({
                    "success": False,
                    "incident_type": "Unknown",
                    "severity": "LOW",
                    "priority": "P5",
                    "confidence": 0,
                    "dashboard": {},
                    "findings": ["No incident title or description provided."],
                    "recommendations": ["Provide alert title and description for triage."],
                    "error": "Title or description required for classification."
                }, indent=2)

            # 1. Classify Incident Type / Category
            text_block = f"{title} {description} {' '.join(ioc)}".lower()
            incident_type, confidence = self._classify_incident_type(text_block)

            # 2. Evaluate Asset Criticality
            asset_criticality = self._evaluate_asset_criticality(asset)

            # 3. Compute Calculated Severity & Business Impact
            calculated_severity = self._calculate_severity(severity, incident_type, asset_criticality, text_block)
            business_impact = self._calculate_business_impact(incident_type, asset_criticality, calculated_severity)

            # 4. Determine Triage Priority (P1 - P5)
            priority = self._assign_priority(calculated_severity, business_impact, asset_criticality, incident_type)

            # 5. Formulate Telemetry Dashboard
            dashboard = {
                "incident_id": incident_id,
                "title": title,
                "source": source,
                "asset": asset,
                "incident_type": incident_type,
                "severity": calculated_severity,
                "business_impact": business_impact,
                "asset_criticality": asset_criticality,
                "priority": priority,
                "confidence": confidence,
                "ioc_count": len(ioc)
            }

            # 6. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_findings_and_recs(
                incident_id=incident_id,
                incident_type=incident_type,
                severity=calculated_severity,
                priority=priority,
                asset=asset,
                asset_criticality=asset_criticality,
                business_impact=business_impact,
                ioc=ioc,
                findings=findings,
                recommendations=recommendations
            )

            return json.dumps({
                "success": True,
                "incident_type": incident_type,
                "severity": calculated_severity,
                "priority": priority,
                "confidence": confidence,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing IncidentClassificationTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "incident_type": "Unknown",
                "severity": "UNKNOWN",
                "priority": "P5",
                "confidence": 0,
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"Incident classification failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _classify_incident_type(self, text: str) -> tuple[str, int]:
        """Pattern-matches text against incident category rules."""
        matched_category = "Unknown"
        max_matches = 0

        for cat, patterns in _INCIDENT_RULES.items():
            matches = sum(1 for p in patterns if re.search(p, text, re.I))
            if matches > max_matches:
                max_matches = matches
                matched_category = cat

        if max_matches >= 3:
            confidence = 98
        elif max_matches == 2:
            confidence = 90
        elif max_matches == 1:
            confidence = 78
        else:
            confidence = 50

        return matched_category, confidence

    def _evaluate_asset_criticality(self, asset: str) -> str:
        """Determines asset criticality based on hostname patterns."""
        asset_lower = asset.lower()
        if any(re.search(p, asset_lower, re.I) for p in _CRITICAL_ASSET_PATTERNS):
            return "CRITICAL"
        if "server" in asset_lower or "srv" in asset_lower or "host" in asset_lower:
            return "HIGH"
        if "pc" in asset_lower or "laptop" in asset_lower or "desk" in asset_lower:
            return "MEDIUM"
        return "MEDIUM"

    def _calculate_severity(self, reported_sev: Optional[str], inc_type: str, asset_crit: str, text: str) -> str:
        """Calculates final incident severity."""
        sev_upper = (reported_sev or "UNKNOWN").upper()
        if sev_upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            base_sev = sev_upper
        else:
            base_sev = "MEDIUM"

        if inc_type in ("Ransomware", "Data Exfiltration", "Supply Chain") or asset_crit == "CRITICAL":
            return "CRITICAL" if base_sev in ("CRITICAL", "HIGH", "MEDIUM") else "HIGH"

        if inc_type in ("Malware", "Credential Theft", "Account Takeover", "Web Attack"):
            return "HIGH" if base_sev != "LOW" else "MEDIUM"

        return base_sev

    def _calculate_business_impact(self, inc_type: str, asset_crit: str, severity: str) -> str:
        """Estimates business impact (LOW, MEDIUM, HIGH, CRITICAL)."""
        if inc_type == "Ransomware" or (asset_crit == "CRITICAL" and severity == "CRITICAL"):
            return "CRITICAL"
        if inc_type in ("Data Exfiltration", "Credential Theft", "Supply Chain") or asset_crit in ("CRITICAL", "HIGH"):
            return "HIGH"
        if severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"

    def _assign_priority(self, severity: str, impact: str, asset_crit: str, inc_type: str) -> str:
        """
        Assigns Incident Response Priority:
            P1: Critical (Immediate response, emergency escalation)
            P2: High (Urgent containment required)
            P3: Medium (Standard incident triage)
            P4: Low (Routine remediation)
            P5: Informational (Policy / low priority)
        """
        if severity == "CRITICAL" or impact == "CRITICAL" or inc_type == "Ransomware":
            return "P1"
        if severity == "HIGH" or impact == "HIGH" or asset_crit == "CRITICAL":
            return "P2"
        if severity == "MEDIUM" or impact == "MEDIUM":
            return "P3"
        if severity == "LOW":
            return "P4"
        return "P5"

    def _generate_findings_and_recs(
        self,
        incident_id: str,
        incident_type: str,
        severity: str,
        priority: str,
        asset: str,
        asset_criticality: str,
        business_impact: str,
        ioc: List[str],
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Populate findings and recommendations."""
        findings.append(
            f"Incident {incident_id} classified as [{incident_type}] with Severity: {severity}, Priority: {priority}."
        )
        findings.append(
            f"Affected asset [{asset}] evaluated with Criticality: {asset_criticality}, Business Impact: {business_impact}."
        )

        if ioc:
            findings.append(f"Identified {len(ioc)} Indicator(s) of Compromise: {', '.join(ioc[:3])}.")

        # Recommendations
        if priority in ("P1", "P2"):
            recommendations.append(f"Initiate Immediate Response Protocol for {priority} [{incident_type}] incident.")
            recommendations.append(f"Isolate host {asset} from local network to contain threat propagation.")
            recommendations.append("Notify Incident Response Team and SOC Lead immediately.")
        else:
            recommendations.append(f"Assign incident {incident_id} to SOC analyst for standard triage.")

        if incident_type == "Ransomware":
            recommendations.append("Verify offline backup integrity and halt shadow copy deletion commands.")
        elif incident_type in ("Malware", "Credential Theft"):
            recommendations.append("Terminate malicious processes and force password resets for compromised accounts.")
