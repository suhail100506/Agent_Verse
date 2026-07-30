"""
ContainmentPlanTool — Actionable Incident Containment & Recovery Response Engine
=================================================================================
Generates prioritized, step-by-step containment and recovery plans categorized by
time horizon (Immediate: 0-1h, Short-term: 1-24h, Long-term: 1-30d) based on incident
classification, risk severity, and affected assets.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class ContainmentPlanToolInput(BaseModel):
    """Input schema for ContainmentPlanTool."""

    incident_id: str = Field(
        default="INC-001",
        description="Unique incident identifier.",
    )
    incident_type: str = Field(
        default="Malware",
        description="Category of incident (e.g. 'Ransomware', 'Malware', 'Phishing', 'Credential Theft', 'Data Exfiltration', 'Account Takeover').",
    )
    severity: str = Field(
        default="HIGH",
        description="Incident severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').",
    )
    priority: str = Field(
        default="P1",
        description="Response priority designation ('P1', 'P2', 'P3', 'P4', 'P5').",
    )
    asset: Optional[str] = Field(
        default="UNKNOWN-HOST",
        description="Affected asset hostname or IP address.",
    )
    compromised_accounts: Optional[List[str]] = Field(
        default_factory=list,
        description="List of compromised user accounts or usernames.",
    )
    malicious_ips: Optional[List[str]] = Field(
        default_factory=list,
        description="List of malicious C2 or attacker IP addresses to block.",
    )
    malicious_domains: Optional[List[str]] = Field(
        default_factory=list,
        description="List of malicious domain names to sinkhole or block.",
    )
    malicious_pids: Optional[List[int]] = Field(
        default_factory=list,
        description="List of malicious process IDs (PIDs) to terminate.",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class ContainmentPlanTool(BaseTool):
    """
    Automated Incident Containment & Recovery Response Plan Generator.

    Generates categorized, step-by-step containment and recovery actions (Immediate 0-1h,
    Short-Term 1-24h, Long-Term 1-30d) tailored to incident classification, severity,
    and technical indicators (PIDs, accounts, IPs, domains).
    """

    name: str = "Containment Plan Tool"
    description: str = (
        "Generates prioritized containment and recovery actions based on incident classification, "
        "severity, and affected assets. Categorizes actions into Immediate (0–1h), Short-term (1–24h), "
        "and Long-term (1–30d) phases, providing estimated business impact and priority."
    )
    args_schema: Type[BaseModel] = ContainmentPlanToolInput

    def _run(
        self,
        incident_id: str = "INC-001",
        incident_type: str = "Malware",
        severity: str = "HIGH",
        priority: str = "P1",
        asset: Optional[str] = "UNKNOWN-HOST",
        compromised_accounts: Optional[List[str]] = None,
        malicious_ips: Optional[List[str]] = None,
        malicious_domains: Optional[List[str]] = None,
        malicious_pids: Optional[List[int]] = None
    ) -> str:
        """Execute containment and recovery plan generation."""
        compromised_accounts = compromised_accounts or []
        malicious_ips = malicious_ips or []
        malicious_domains = malicious_domains or []
        malicious_pids = malicious_pids or []

        logger.info(
            "ContainmentPlanTool: generating response plan for %s — type='%s', priority='%s'",
            incident_id, incident_type, priority
        )

        try:
            # 1. Generate Containment Actions (Immediate, Short-term)
            containment_actions = self._generate_containment_actions(
                incident_id=incident_id,
                incident_type=incident_type,
                priority=priority,
                asset=asset,
                compromised_accounts=compromised_accounts,
                malicious_ips=malicious_ips,
                malicious_domains=malicious_domains,
                malicious_pids=malicious_pids
            )

            # 2. Generate Recovery & Remediation Actions (Short-term, Long-term)
            recovery_actions = self._generate_recovery_actions(
                incident_id=incident_id,
                incident_type=incident_type,
                priority=priority,
                asset=asset,
                compromised_accounts=compromised_accounts
            )

            # 3. Estimate Business Impact
            estimated_business_impact = self._estimate_business_impact(severity, priority, incident_type)

            # 4. Formulate Telemetry Dashboard
            imm_cnt = sum(1 for a in containment_actions if a.get("category") == "Immediate")
            st_cnt = sum(1 for a in containment_actions + recovery_actions if a.get("category") == "Short-term")
            lt_cnt = sum(1 for a in recovery_actions if a.get("category") == "Long-term")

            dashboard = {
                "incident_id": incident_id,
                "incident_type": incident_type,
                "severity": severity,
                "priority": priority,
                "immediate_actions_count": imm_cnt,
                "short_term_actions_count": st_cnt,
                "long_term_actions_count": lt_cnt,
                "estimated_business_impact": estimated_business_impact
            }

            # 5. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_findings_and_recs(
                incident_id=incident_id,
                priority=priority,
                containment_actions=containment_actions,
                recovery_actions=recovery_actions,
                impact=estimated_business_impact,
                findings=findings,
                recommendations=recommendations
            )

            return json.dumps({
                "success": True,
                "priority": priority,
                "containment_actions": containment_actions,
                "recovery_actions": recovery_actions,
                "estimated_business_impact": estimated_business_impact,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing ContainmentPlanTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "priority": priority,
                "containment_actions": [],
                "recovery_actions": [],
                "estimated_business_impact": "Unknown",
                "dashboard": {},
                "findings": [],
                "recommendations": [],
                "error": f"Containment plan generation failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _generate_containment_actions(
        self,
        incident_id: str,
        incident_type: str,
        priority: str,
        asset: Optional[str],
        compromised_accounts: List[str],
        malicious_ips: List[str],
        malicious_domains: List[str],
        malicious_pids: List[int]
    ) -> List[Dict[str, Any]]:
        """Generates prioritized immediate and short-term containment steps."""
        actions: List[Dict[str, Any]] = []
        act_counter = 1

        # Action 1: Network Host Isolation
        if asset and asset != "UNKNOWN-HOST":
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": f"Isolate Host [{asset}]",
                "category": "Immediate",
                "priority": priority,
                "target": asset,
                "description": f"Disconnect {asset} from local network and internet using EDR agent or VLAN quarantine to halt spread."
            })
            act_counter += 1

        # Action 2: Process Termination
        if malicious_pids:
            pids_str = ", ".join(map(str, malicious_pids))
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Kill Malicious Processes",
                "category": "Immediate",
                "priority": priority,
                "target": pids_str,
                "description": f"Force terminate malicious active process PIDs ({pids_str}) on endpoint."
            })
            act_counter += 1
        elif incident_type in ("Malware", "Ransomware"):
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Terminate Malicious Process Execution",
                "category": "Immediate",
                "priority": priority,
                "target": asset or "Endpoint",
                "description": "Terminate suspicious command shells, PowerShell instances, or unauthorized processes."
            })
            act_counter += 1

        # Action 3: Account Disablement & Token Revocation
        if compromised_accounts:
            accts_str = ", ".join(compromised_accounts)
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Disable Compromised Accounts & Revoke Tokens",
                "category": "Immediate",
                "priority": priority,
                "target": accts_str,
                "description": f"Disable Active Directory / IdP accounts ({accts_str}) and invalidate all active OAuth & session tokens."
            })
            act_counter += 1

        # Action 4: Perimeter IP Blocking
        if malicious_ips:
            ips_str = ", ".join(malicious_ips)
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Block Malicious IP Addresses at Perimeter",
                "category": "Immediate",
                "priority": "P2" if priority != "P1" else "P1",
                "target": ips_str,
                "description": f"Enforce perimeter firewall and WAF block rules for attacker IPs: {ips_str}."
            })
            act_counter += 1

        # Action 5: Domain Sinkholing
        if malicious_domains:
            doms_str = ", ".join(malicious_domains)
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Sinkhole & Block Malicious Domains",
                "category": "Immediate",
                "priority": "P2" if priority != "P1" else "P1",
                "target": doms_str,
                "description": f"Configure enterprise DNS sinkhole and web proxy block rules for C2 domains: {doms_str}."
            })
            act_counter += 1

        # Action 6: Ransomware VSS & Backup Safeguard
        if incident_type == "Ransomware":
            actions.append({
                "action_id": f"ACT-{act_counter:03d}",
                "title": "Halt Volume Shadow Copy Deletion & Secure Backups",
                "category": "Immediate",
                "priority": "P1",
                "target": "Backup Infrastructure",
                "description": "Disconnect backup repositories from network and block administrative credential access to prevent backup destruction."
            })
            act_counter += 1

        return actions

    def _generate_recovery_actions(
        self,
        incident_id: str,
        incident_type: str,
        priority: str,
        asset: Optional[str],
        compromised_accounts: List[str]
    ) -> List[Dict[str, Any]]:
        """Generates short-term and long-term recovery and remediation steps."""
        actions: List[Dict[str, Any]] = []
        rec_counter = 1

        # Recovery 1: Credential Reset
        actions.append({
            "action_id": f"REC-{rec_counter:03d}",
            "title": "Force Enterprise Credential Resets",
            "category": "Short-term",
            "priority": "P2",
            "target": ", ".join(compromised_accounts) if compromised_accounts else "Affected User Accounts",
            "description": "Force password reset across Active Directory and mandate FIDO2/TOTP step-up authentication."
        })
        rec_counter += 1

        # Recovery 2: Persistence Removal
        actions.append({
            "action_id": f"REC-{rec_counter:03d}",
            "title": "Remove Persistence Mechanisms",
            "category": "Short-term",
            "priority": "P2",
            "target": asset or "Affected Endpoint",
            "description": "Clean unauthorized registry Run keys, scheduled tasks, startup scripts, and unauthorized service entries."
        })
        rec_counter += 1

        # Recovery 3: System Reimaging / Clean Restore
        if incident_type in ("Ransomware", "Malware", "Credential Theft"):
            actions.append({
                "action_id": f"REC-{rec_counter:03d}",
                "title": "Reimage Host from Clean Gold Master",
                "category": "Short-term",
                "priority": "P2",
                "target": asset or "Endpoint",
                "description": "Wipe affected host and deploy fresh OS build from validated gold image following forensic acquisition."
            })
            rec_counter += 1

        # Recovery 4: Stakeholder & Regulatory Notification
        actions.append({
            "action_id": f"REC-{rec_counter:03d}",
            "title": "Executive & Stakeholder Notification",
            "category": "Short-term",
            "priority": "P3",
            "target": "CISO / Legal / PR",
            "description": "Brief executive leadership and coordinate regulatory disclosure if PII or sensitive data was breached."
        })
        rec_counter += 1

        # Recovery 5: Vulnerability Patching & Security Hardening
        actions.append({
            "action_id": f"REC-{rec_counter:03d}",
            "title": "Patch Exploited Vulnerabilities & Harden Controls",
            "category": "Long-term",
            "priority": "P3",
            "target": "Infrastructure",
            "description": "Apply vendor security patches for root-cause CVEs and enforce LSA Protection and Credential Guard."
        })
        rec_counter += 1

        # Recovery 6: Post-Incident Review (Lessons Learned)
        actions.append({
            "action_id": f"REC-{rec_counter:03d}",
            "title": "Post-Incident Review & Playbook Refinement",
            "category": "Long-term",
            "priority": "P4",
            "target": "Incident Response Team",
            "description": "Conduct formal PIR meeting, update detection rules, and refine automated response playbooks."
        })
        rec_counter += 1

        return actions

    def _estimate_business_impact(self, severity: str, priority: str, incident_type: str) -> str:
        """Estimates overall business impact level (Critical, High, Medium, Low)."""
        if priority == "P1" or severity == "CRITICAL" or incident_type == "Ransomware":
            return "Critical"
        if priority == "P2" or severity == "HIGH":
            return "High"
        if priority == "P3" or severity == "MEDIUM":
            return "Medium"
        return "Low"

    def _generate_findings_and_recs(
        self,
        incident_id: str,
        priority: str,
        containment_actions: List[Dict[str, Any]],
        recovery_actions: List[Dict[str, Any]],
        impact: str,
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Populate response plan findings and recommendations."""
        findings.append(
            f"Containment plan generated for incident {incident_id} (Priority: {priority}, Estimated Impact: {impact})."
        )
        findings.append(
            f"Formulated {len(containment_actions)} containment action(s) and {len(recovery_actions)} recovery action(s)."
        )

        for act in containment_actions:
            if act.get("category") == "Immediate":
                recommendations.append(f"Immediate Action [{act['action_id']}]: {act['title']} — {act['target']}.")

        recommendations.append("Execute containment actions strictly in order of assigned priority.")
