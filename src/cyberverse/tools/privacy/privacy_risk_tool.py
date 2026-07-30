import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class PrivacyRiskToolInput(BaseModel):
    """Input schema for PrivacyRiskTool."""
    pii_json: Optional[str] = Field(None, description="Raw JSON string from PIIDetectionTool.")
    secret_json: Optional[str] = Field(None, description="Raw JSON string from SecretScannerTool.")
    compliance_json: Optional[str] = Field(None, description="Raw JSON string from ComplianceTool.")
    combined_json: Optional[str] = Field(None, description="Combined JSON containing pii_findings, secret_findings, and compliance_findings.")


class PrivacyRiskTool(BaseTool):
    name: str = "Privacy Risk Tool"
    description: str = (
        "Synthesizes PII detections, Secret scanner findings, and Regulatory Compliance evaluations "
        "to calculate an overall Privacy Risk Score (0-100), Overall Risk Rating (LOW, MEDIUM, HIGH, CRITICAL), "
        "Data Exposure Level, Compliance Readiness status, critical finding metrics, executive summary, and recommendations."
    )
    args_schema: Type[BaseModel] = PrivacyRiskToolInput

    def _run(
        self,
        pii_json: Optional[str] = None,
        secret_json: Optional[str] = None,
        compliance_json: Optional[str] = None,
        combined_json: Optional[str] = None
    ) -> str:
        """Execute privacy risk synthesis across PII, Secret, and Compliance outputs."""
        try:
            # 1. Parse findings from all input sources
            pii_entities, secret_findings, compliance_data = self._parse_inputs(
                pii_json, secret_json, compliance_json, combined_json
            )

            # 2. Extract metrics & counts
            pii_count = len(pii_entities)
            secret_count = len(secret_findings)
            critical_findings_count = self._count_critical_findings(pii_entities, secret_findings, compliance_data)
            frameworks_failed_count = self._count_failed_frameworks(compliance_data)

            # 3. Calculate Scores and Categorizations using Modular Functions
            privacy_score = self._calculate_privacy_score(pii_entities, secret_findings)
            risk_score = self._calculate_risk_score(privacy_score, compliance_data, critical_findings_count)
            overall_risk = self._calculate_overall_risk(risk_score, critical_findings_count)
            data_exposure = self._calculate_exposure_level(pii_count, secret_count)
            compliance_readiness = self._calculate_readiness(overall_risk, frameworks_failed_count)

            # 4. Dashboard Metrics
            dashboard = {
                "pii_count": pii_count,
                "secret_count": secret_count,
                "frameworks_failed": frameworks_failed_count
            }

            # 5. Formulate Executive Summary & Recommendations
            exec_summary = self._generate_executive_summary(
                overall_risk, risk_score, privacy_score, pii_count, secret_count,
                frameworks_failed_count, data_exposure, compliance_readiness
            )
            recommendations = self._generate_recommendations(pii_entities, secret_findings, compliance_data)

            return json.dumps({
                "success": True,
                "overall_risk": overall_risk,
                "risk_score": risk_score,
                "privacy_score": privacy_score,
                "data_exposure": data_exposure,
                "compliance_readiness": compliance_readiness,
                "critical_findings": critical_findings_count,
                "executive_summary": exec_summary,
                "recommendations": recommendations,
                "dashboard": dashboard,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing PrivacyRiskTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "overall_risk": "HIGH",
                "risk_score": 0,
                "privacy_score": 0,
                "data_exposure": "NONE",
                "compliance_readiness": "NOT_READY",
                "critical_findings": 0,
                "executive_summary": f"Privacy risk synthesis error: {str(e)}",
                "recommendations": [],
                "dashboard": {"pii_count": 0, "secret_count": 0, "frameworks_failed": 0},
                "error": f"Risk assessment calculation failed: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        pii_json: Optional[str],
        secret_json: Optional[str],
        compliance_json: Optional[str],
        combined_json: Optional[str]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """Extract structured data arrays from input arguments."""
        pii_entities: List[Dict[str, Any]] = []
        secret_findings: List[Dict[str, Any]] = []
        compliance_data: Dict[str, Any] = {}

        if combined_json:
            try:
                data = json.loads(combined_json)
                pii_entities = data.get("pii_findings", []) or data.get("entities", [])
                secret_findings = data.get("secret_findings", []) or data.get("findings", [])
                compliance_data = data.get("compliance_findings", {}) or data.get("compliance", {})
            except Exception:
                pass

        if pii_json:
            try:
                pdata = json.loads(pii_json)
                pii_entities = pdata.get("entities", []) if isinstance(pdata, dict) else []
            except Exception:
                pass

        if secret_json:
            try:
                sdata = json.loads(secret_json)
                secret_findings = sdata.get("findings", []) if isinstance(sdata, dict) else []
            except Exception:
                pass

        if compliance_json:
            try:
                cdata = json.loads(compliance_json)
                compliance_data = cdata if isinstance(cdata, dict) else {}
            except Exception:
                pass

        return pii_entities, secret_findings, compliance_data

    def _count_critical_findings(
        self,
        pii: List[Dict[str, Any]],
        secrets: List[Dict[str, Any]],
        compliance: Dict[str, Any]
    ) -> int:
        """Count total CRITICAL findings across secrets, high-sensitivity PII, and violations."""
        critical_count = 0

        # Critical secrets
        for s in secrets:
            if s.get("severity", "").upper() == "CRITICAL":
                critical_count += 1

        # High sensitivity PII (Aadhaar, SSN, Credit Cards)
        high_pii = {"IN_AADHAAR", "CREDIT_CARD", "US_SSN", "PASSPORT"}
        for p in pii:
            if p.get("type", "") in high_pii:
                critical_count += 1

        # Critical compliance violations
        violations = compliance.get("violations", [])
        for v in violations:
            if v.get("severity", "").upper() == "CRITICAL":
                critical_count += 1

        return critical_count

    def _count_failed_frameworks(self, compliance: Dict[str, Any]) -> int:
        """Count frameworks with status NON_COMPLIANT."""
        frameworks = compliance.get("frameworks", {})
        failed = 0
        for fname, fdata in frameworks.items():
            if fdata.get("status", "").upper() == "NON_COMPLIANT":
                failed += 1
        return failed

    def _calculate_privacy_score(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> int:
        """Calculate standalone Privacy Risk Score (0-100)."""
        score = 0
        high_sensitivity_types = {"IN_AADHAAR", "CREDIT_CARD", "US_SSN", "PASSPORT", "IN_PAN"}

        for p in pii:
            ptype = p.get("type", "")
            if ptype in high_sensitivity_types:
                score += 15
            else:
                score += 8

        for s in secrets:
            sev = s.get("severity", "").upper()
            if sev == "CRITICAL":
                score += 20
            elif sev == "HIGH":
                score += 12
            else:
                score += 5

        return min(100, score)

    def _calculate_risk_score(
        self,
        privacy_score: int,
        compliance: Dict[str, Any],
        critical_findings: int
    ) -> int:
        """Calculate overall combined Risk Score (0-100)."""
        comp_score = compliance.get("overall_score", 100)
        # Higher compliance score means lower risk, so compliance risk = 100 - comp_score
        compliance_risk = 100 - comp_score

        combined = int((privacy_score * 0.5) + (compliance_risk * 0.5)) + (critical_findings * 5)
        return min(100, combined)

    def _calculate_overall_risk(self, risk_score: int, critical_findings: int) -> str:
        """Categorize overall risk rating: LOW, MEDIUM, HIGH, CRITICAL."""
        if risk_score >= 80 or critical_findings >= 3:
            return "CRITICAL"
        elif risk_score >= 60 or critical_findings >= 1:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        return "LOW"

    def _calculate_exposure_level(self, pii_count: int, secret_count: int) -> str:
        """Determine data exposure level: NONE, LIMITED, MODERATE, EXTENSIVE."""
        total_items = pii_count + secret_count
        if total_items > 5 or pii_count >= 3 or secret_count >= 2:
            return "EXTENSIVE"
        elif total_items >= 2:
            return "MODERATE"
        elif total_items == 1:
            return "LIMITED"
        return "NONE"

    def _calculate_readiness(self, overall_risk: str, failed_frameworks: int) -> str:
        """Determine deployment compliance readiness: READY, NEEDS_REVIEW, NOT_READY."""
        if overall_risk in {"HIGH", "CRITICAL"} or failed_frameworks >= 3:
            return "NOT_READY"
        elif overall_risk == "MEDIUM" or failed_frameworks >= 1:
            return "NEEDS_REVIEW"
        return "READY"

    def _generate_executive_summary(
        self,
        risk: str,
        risk_score: int,
        privacy_score: int,
        pii_count: int,
        secret_count: int,
        failed_fw: int,
        exposure: str,
        readiness: str
    ) -> str:
        """Formulate a comprehensive executive synthesis summary."""
        return (
            f"Overall Privacy Risk assessed as {risk} (Risk Score: {risk_score}/100, Privacy Score: {privacy_score}/100). "
            f"Data Exposure Level is {exposure} with {pii_count} PII entity record(s) and {secret_count} exposed credential secret(s). "
            f"Regulatory Compliance Readiness is {readiness} with {failed_fw} regulatory framework(s) failing compliance controls. "
            "Immediate credential revocation and cryptographic data masking are required before production deployment."
        )

    def _generate_recommendations(
        self,
        pii: List[Dict[str, Any]],
        secrets: List[Dict[str, Any]],
        compliance: Dict[str, Any]
    ) -> List[str]:
        """Generate prioritized remediation action items."""
        recs = []

        if secrets:
            recs.append("Rotate exposed credentials immediately in relevant provider consoles.")
            recs.append("Remove hardcoded secrets from configuration files and store in a secure vault.")

        if pii:
            recs.append("Encrypt sensitive PII records at rest and in transit.")
            recs.append("Apply credit card and PAN number masking.")

        comp_recs = compliance.get("recommendations", [])
        for r in comp_recs:
            if r not in recs:
                recs.append(r)

        if not recs:
            recs.append("Maintain continuous automated PII and secret scanning in CI/CD pipelines.")

        return recs
