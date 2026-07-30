import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ThreatRiskToolInput(BaseModel):
    """Input schema for ThreatRiskTool."""
    ip_reputation: Optional[str] = Field(None, description="Raw JSON string or dict output from IPReputationTool.")
    url_reputation: Optional[str] = Field(None, description="Raw JSON string or dict output from URLReputationTool.")
    dns_analysis: Optional[str] = Field(None, description="Raw JSON string or dict output from DNSAnalysisTool.")
    ioc_analysis: Optional[str] = Field(None, description="Raw JSON string or dict output from IOCAnalysisTool.")
    combined_json: Optional[str] = Field(None, description="Combined JSON containing outputs from IPReputationTool, URLReputationTool, DNSAnalysisTool, and IOCAnalysisTool.")


class ThreatRiskTool(BaseTool):
    name: str = "Threat Risk Tool"
    description: str = (
        "Aggregates outputs from IPReputationTool, URLReputationTool, DNSAnalysisTool, and IOCAnalysisTool into a single "
        "enterprise Threat Intelligence Assessment with overall risk rating (LOW, MEDIUM, HIGH, CRITICAL), threat score (0-100), "
        "active threat status, telemetry dashboard, forensic evidence list, prioritized recommendations, and executive summary."
    )
    args_schema: Type[BaseModel] = ThreatRiskToolInput

    def _run(
        self,
        ip_reputation: Optional[str] = None,
        url_reputation: Optional[str] = None,
        dns_analysis: Optional[str] = None,
        ioc_analysis: Optional[str] = None,
        combined_json: Optional[str] = None
    ) -> str:
        """Execute Threat Risk synthesis and calculate enterprise threat score."""
        try:
            # 1. Parse JSON inputs into structured dictionaries
            ip_data, url_data, dns_data, ioc_data = self._parse_inputs(
                ip_reputation, url_reputation, dns_analysis, ioc_analysis, combined_json
            )

            # 2. Collect Forensic Evidence & Calculate Weighted Threat Score
            evidence: List[str] = []
            threat_score = 0
            active_tools_count = 0
            
            malicious_ips_count = 0
            malicious_urls_count = 0
            dns_issues_count = 0
            ioc_count = ioc_data.get("ioc_count", 0)

            # --- A. IP Reputation Analysis ---
            if ip_data.get("success"):
                active_tools_count += 1
                abuse_score = ip_data.get("abuse_score", 0)
                ip_val = ip_data.get("ip", "Unknown IP")
                
                if abuse_score >= 80:
                    threat_score += 40
                    malicious_ips_count += 1
                    evidence.append(f"IP address ({ip_val}) flagged with CRITICAL AbuseIPDB score ({abuse_score}%).")
                elif abuse_score >= 50:
                    threat_score += 25
                    malicious_ips_count += 1
                    evidence.append(f"IP address ({ip_val}) flagged with HIGH AbuseIPDB score ({abuse_score}%).")
                elif abuse_score >= 15:
                    threat_score += 10
                    evidence.append(f"IP address ({ip_val}) has suspicious AbuseIPDB reports.")

            # --- B. URL Reputation Analysis ---
            if url_data.get("success"):
                active_tools_count += 1
                target_url = url_data.get("url", "Unknown URL")
                sb = url_data.get("safe_browsing", {})
                vt = url_data.get("virus_total", {})
                vt_detections = vt.get("detections", 0)

                if sb.get("malicious"):
                    threat_score += 45
                    malicious_urls_count += 1
                    threats_str = ", ".join(sb.get("threat_types", []))
                    evidence.append(f"Google Safe Browsing flagged URL ({target_url}) for {threats_str or 'Malware/Phishing'}.")
                elif vt_detections >= 5:
                    threat_score += 40
                    malicious_urls_count += 1
                    evidence.append(f"VirusTotal URL scanner flagged ({target_url}) with {vt_detections} vendor detections.")
                elif vt_detections >= 1:
                    threat_score += 20
                    malicious_urls_count += 1
                    evidence.append(f"VirusTotal URL scanner flagged ({target_url}) with {vt_detections} vendor detection.")

                for w in url_data.get("warnings", []):
                    if "raw IP address" in w or "internal/private IP" in w:
                        threat_score += 10
                        evidence.append(f"URL Security Warning: {w}")

            # --- C. DNS Security Analysis ---
            if dns_data.get("success"):
                active_tools_count += 1
                dns_warnings = dns_data.get("warnings", [])
                dns_issues_count = len(dns_warnings)

                for w in dns_warnings:
                    if "Missing SPF" in w:
                        threat_score += 15
                        evidence.append("SPF record missing - Domain is vulnerable to email spoofing.")
                    elif "Missing DMARC" in w:
                        threat_score += 20
                        evidence.append("DMARC policy missing - Email spoofing protection is disabled.")
                    elif "Weak DMARC" in w:
                        threat_score += 10
                        evidence.append("Weak DMARC policy set to 'p=none' (monitoring only).")
                    elif "+all" in w:
                        threat_score += 25
                        evidence.append("Dangerous SPF record directive '+all' detected.")

            # --- D. IOC Extraction Analysis ---
            if ioc_data.get("success") and ioc_count > 0:
                active_tools_count += 1
                summary = ioc_data.get("summary", {})
                cve_count = summary.get("cves", 0)
                mitre_count = summary.get("mitre", 0)

                if ioc_count >= 10:
                    threat_score += 20
                    evidence.append(f"High volume of extracted Indicators of Compromise ({ioc_count} IOCs).")
                elif ioc_count >= 1:
                    threat_score += 10
                    evidence.append(f"Extracted {ioc_count} Indicators of Compromise from threat input.")

                if cve_count > 0:
                    threat_score += 15
                    evidence.append(f"Known CVE vulnerability identifiers detected ({cve_count} CVEs found).")

                if mitre_count > 0:
                    threat_score += 10
                    evidence.append(f"MITRE ATT&CK technique or software references identified ({mitre_count} references).")

            # 3. Finalize Risk Score & Categorization
            final_threat_score = min(100, threat_score)

            if final_threat_score >= 76:
                overall_risk = "CRITICAL"
            elif final_threat_score >= 51:
                overall_risk = "HIGH"
            elif final_threat_score >= 26:
                overall_risk = "MEDIUM"
            else:
                overall_risk = "LOW"

            active_threat = final_threat_score >= 50 or malicious_ips_count > 0 or malicious_urls_count > 0
            confidence = min(99, 75 + (active_tools_count * 6)) if active_tools_count > 0 else 50

            # 4. Formulate Telemetry Dashboard
            dashboard = {
                "ioc_count": ioc_count,
                "malicious_ips": malicious_ips_count,
                "malicious_urls": malicious_urls_count,
                "dns_issues": dns_issues_count
            }

            # 5. Formulate Recommendations & Executive Summary
            recommendations = self._generate_recommendations(
                overall_risk, malicious_ips_count, malicious_urls_count, dns_issues_count, ioc_data
            )
            exec_summary = self._generate_executive_summary(
                overall_risk, final_threat_score, active_threat, ioc_count
            )

            return json.dumps({
                "success": True,
                "overall_risk": overall_risk,
                "threat_score": final_threat_score,
                "confidence": confidence,
                "active_threat": active_threat,
                "dashboard": dashboard,
                "evidence": evidence,
                "recommendations": recommendations,
                "executive_summary": exec_summary,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing ThreatRiskTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "overall_risk": "LOW",
                "threat_score": 0,
                "confidence": 0,
                "active_threat": False,
                "dashboard": {"ioc_count": 0, "malicious_ips": 0, "malicious_urls": 0, "dns_issues": 0},
                "evidence": [],
                "recommendations": [],
                "executive_summary": "Unable to compute threat intelligence synthesis due to error.",
                "error": f"Threat risk evaluation error: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        ip_reputation: Optional[str],
        url_reputation: Optional[str],
        dns_analysis: Optional[str],
        ioc_analysis: Optional[str],
        combined_json: Optional[str]
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Parse input JSON strings or dicts into structured dictionaries."""
        ip_data: Dict[str, Any] = {}
        url_data: Dict[str, Any] = {}
        dns_data: Dict[str, Any] = {}
        ioc_data: Dict[str, Any] = {}

        if combined_json:
            try:
                cdata = json.loads(combined_json) if isinstance(combined_json, str) else combined_json
                ip_data = cdata.get("ip_reputation", {}) or cdata.get("ip", {})
                url_data = cdata.get("url_reputation", {}) or cdata.get("url", {})
                dns_data = cdata.get("dns_analysis", {}) or cdata.get("dns", {})
                ioc_data = cdata.get("ioc_analysis", {}) or cdata.get("ioc", {})
            except Exception:
                pass

        if ip_reputation:
            try:
                ip_data = json.loads(ip_reputation) if isinstance(ip_reputation, str) else ip_reputation
            except Exception:
                pass

        if url_reputation:
            try:
                url_data = json.loads(url_reputation) if isinstance(url_reputation, str) else url_reputation
            except Exception:
                pass

        if dns_analysis:
            try:
                dns_data = json.loads(dns_analysis) if isinstance(dns_analysis, str) else dns_analysis
            except Exception:
                pass

        if ioc_analysis:
            try:
                ioc_data = json.loads(ioc_analysis) if isinstance(ioc_analysis, str) else ioc_analysis
            except Exception:
                pass

        return ip_data, url_data, dns_data, ioc_data

    def _generate_recommendations(
        self,
        overall_risk: str,
        mal_ips: int,
        mal_urls: int,
        dns_issues: int,
        ioc_data: Dict[str, Any]
    ) -> List[str]:
        """Generate prioritized remediation action list."""
        recs = []
        if overall_risk in {"CRITICAL", "HIGH"}:
            if mal_ips > 0:
                recs.append("Block malicious IP addresses immediately at the boundary firewall and WAF.")
            if mal_urls > 0:
                recs.append("Disable access to malicious URLs and block domain resolves at DNS gateway.")
            recs.append("Quarantine affected host endpoints and isolate from internal network.")
            recs.append("Enable strict DNS filtering and perimeter inspection.")

        if dns_issues > 0:
            recs.append("Implement DMARC policy with 'p=reject' or 'p=quarantine' enforcement.")
            recs.append("Harden SPF policy and remove dangerous directives.")

        summary = ioc_data.get("summary", {})
        if summary.get("cves", 0) > 0:
            recs.append("Review extracted CVE identifiers and apply emergency security patches.")

        if not recs:
            recs.append("Continue standard security monitoring and baseline threat logging.")

        return recs

    def _generate_executive_summary(self, overall_risk: str, threat_score: int, active_threat: bool, ioc_count: int) -> str:
        """Formulate concise enterprise summary string."""
        threat_state = "an ACTIVE THREAT" if active_threat else "no active threat"
        return (
            f"Threat assessment completed successfully. Overall threat level is {overall_risk} "
            f"with a threat score of {threat_score}/100. Extracted {ioc_count} Indicators of Compromise "
            f"with {threat_state} detected requiring immediate security review."
        )
