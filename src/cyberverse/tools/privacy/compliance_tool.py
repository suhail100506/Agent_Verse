import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ComplianceToolInput(BaseModel):
    """Input schema for ComplianceTool."""
    pii_json: Optional[str] = Field(None, description="Raw JSON string output from PIIDetectionTool.")
    secret_json: Optional[str] = Field(None, description="Raw JSON string output from SecretScannerTool.")
    raw_findings_json: Optional[str] = Field(None, description="Combined JSON containing pii_findings and secret_findings arrays.")


class ComplianceTool(BaseTool):
    name: str = "Compliance Tool"
    description: str = (
        "Evaluates PII entity detections and secret scanning findings against 7 major regulatory & security frameworks: "
        "GDPR, CCPA, HIPAA, PCI DSS, ISO/IEC 27001, SOC 2 Type II, and NIST CSF 2.0. "
        "Computes framework compliance statuses, numerical compliance scores, control violations, executive summary, and remediation guidance."
    )
    args_schema: Type[BaseModel] = ComplianceToolInput

    def _run(
        self,
        pii_json: Optional[str] = None,
        secret_json: Optional[str] = None,
        raw_findings_json: Optional[str] = None
    ) -> str:
        """Execute regulatory compliance evaluation across all 7 frameworks."""
        try:
            # 1. Parse findings from input JSON sources
            pii_entities, secret_findings = self._parse_inputs(pii_json, secret_json, raw_findings_json)

            # 2. Modular Framework Evaluators List
            evaluators = [
                ("GDPR", self._eval_gdpr),
                ("CCPA", self._eval_ccpa),
                ("HIPAA", self._eval_hipaa),
                ("PCI DSS", self._eval_pci_dss),
                ("ISO 27001", self._eval_iso27001),
                ("SOC 2", self._eval_soc2),
                ("NIST CSF 2.0", self._eval_nist)
            ]

            all_violations: List[Dict[str, Any]] = []
            framework_summary: Dict[str, Dict[str, Any]] = {}
            total_scores = []
            statuses = []

            # 3. Execute each framework evaluator independently
            for fname, eval_fn in evaluators:
                res = eval_fn(pii_entities, secret_findings)
                framework_summary[fname] = {
                    "status": res["status"],
                    "score": res["score"]
                }
                all_violations.extend(res["violations"])
                total_scores.append(res["score"])
                statuses.append(res["status"])

            # 4. Compute Overall Compliance Score and Status
            overall_score = int(sum(total_scores) / len(total_scores)) if total_scores else 100
            
            if "NON_COMPLIANT" in statuses:
                overall_status = "NON_COMPLIANT"
            elif "PARTIALLY_COMPLIANT" in statuses:
                overall_status = "PARTIALLY_COMPLIANT"
            else:
                overall_status = "COMPLIANT"

            # 5. Formulate Executive Summary & Actionable Recommendations
            exec_summary = self._generate_executive_summary(pii_entities, secret_findings, overall_status, all_violations)
            recommendations = self._generate_recommendations(all_violations)

            return json.dumps({
                "success": True,
                "overall_score": overall_score,
                "overall_status": overall_status,
                "frameworks": framework_summary,
                "violations": all_violations,
                "executive_summary": exec_summary,
                "recommendations": recommendations,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing ComplianceTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "overall_score": 0,
                "overall_status": "NON_COMPLIANT",
                "frameworks": {},
                "violations": [],
                "executive_summary": f"Compliance evaluation error: {str(e)}",
                "recommendations": [],
                "error": f"Compliance calculation failed: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        pii_json: Optional[str],
        secret_json: Optional[str],
        raw_findings_json: Optional[str]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract PII entities and Secret findings from input JSON arguments."""
        pii_entities: List[Dict[str, Any]] = []
        secret_findings: List[Dict[str, Any]] = []

        if raw_findings_json:
            try:
                data = json.loads(raw_findings_json)
                pii_entities = data.get("pii_findings", []) or data.get("entities", [])
                secret_findings = data.get("secret_findings", []) or data.get("findings", [])
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

        return pii_entities, secret_findings

    def _eval_gdpr(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate EU GDPR compliance (Articles 5, 25, 32)."""
        violations = []
        deductions = 0

        # Check for exposed PII
        if pii:
            deductions += 25
            violations.append({
                "framework": "GDPR",
                "control": "Article 5(1)(f) - Integrity and Confidentiality",
                "severity": "HIGH",
                "description": f"Exposed PII detected ({len(pii)} records found in plaintext).",
                "reason": "GDPR requires appropriate technical measures to prevent unauthorized disclosure of personal data.",
                "recommendation": "Implement encryption at rest and pseudonymize personal data."
            })

        # Check for exposed secrets/credentials
        if secrets:
            deductions += 30
            violations.append({
                "framework": "GDPR",
                "control": "Article 32 - Security of Processing",
                "severity": "CRITICAL",
                "description": f"Exposed secrets or API keys detected ({len(secrets)} credentials found).",
                "reason": "Hardcoded authentication credentials compromise systemic security processing controls.",
                "recommendation": "Revoke exposed credentials immediately and purge from application source files."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_ccpa(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate California Consumer Privacy Act (CCPA) compliance."""
        violations = []
        deductions = 0

        if pii:
            deductions += 20
            violations.append({
                "framework": "CCPA",
                "control": "Cal. Civ. Code § 1798.81.5 - Duty to Maintain Reasonable Security",
                "severity": "HIGH",
                "description": f"Unencrypted California consumer personal information detected ({len(pii)} items).",
                "reason": "Businesses must maintain reasonable security procedures appropriate to the nature of personal information.",
                "recommendation": "Encrypt consumer PII at rest and restrict access permissions."
            })

        if secrets:
            deductions += 25
            violations.append({
                "framework": "CCPA",
                "control": "Cal. Civ. Code § 1798.150 - Data Breach Security Mandate",
                "severity": "CRITICAL",
                "description": f"Exposed system credentials detected ({len(secrets)} items).",
                "reason": "Exposed credentials create high risk of unauthorized access leading to statutory consumer data breach liability.",
                "recommendation": "Move secrets to an environment secrets manager."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_hipaa(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate Health Insurance Portability and Accountability Act (HIPAA) compliance."""
        violations = []
        deductions = 0

        # Check for potential PHI / PII
        phi_types = {"PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN", "DATE_TIME"}
        detected_phi = [item for item in pii if item.get("type") in phi_types]

        if detected_phi:
            deductions += 30
            violations.append({
                "framework": "HIPAA",
                "control": "45 CFR § 164.312(a)(1) - Technical Safeguards: Access Control",
                "severity": "CRITICAL",
                "description": f"Plaintext Protected Health Information (PHI/PII) detected ({len(detected_phi)} items).",
                "reason": "HIPAA Security Rule mandates strict technical access controls and encryption for electronic PHI.",
                "recommendation": "Enforce NIST-compliant AES-256 encryption and role-based access control (RBAC)."
            })

        if secrets:
            deductions += 25
            violations.append({
                "framework": "HIPAA",
                "control": "45 CFR § 164.312(e)(1) - Transmission and Storage Security",
                "severity": "HIGH",
                "description": f"Exposed authentication keys or database strings detected ({len(secrets)} secrets).",
                "reason": "Hardcoded keys violate transmission security safeguards for ePHI access points.",
                "recommendation": "Rotate API keys and enforce encrypted secret management."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_pci_dss(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate Payment Card Industry Data Security Standard (PCI DSS v4.0) compliance."""
        violations = []
        deductions = 0

        card_pii = [item for item in pii if item.get("type") == "CREDIT_CARD"]
        db_secrets = [s for s in secrets if "URI" in s.get("type", "") or "KEY" in s.get("type", "")]

        if card_pii:
            deductions += 40
            violations.append({
                "framework": "PCI DSS",
                "control": "Requirement 3 - Protect Stored Account Data",
                "severity": "CRITICAL",
                "description": f"Unencrypted Primary Account Numbers (PAN / Credit Cards) detected ({len(card_pii)} instances).",
                "reason": "PCI DSS mandates that PAN data must be unreadable anywhere it is stored.",
                "recommendation": "Truncate, mask, or format-preserving encrypt cardholder account data."
            })

        if secrets or db_secrets:
            deductions += 30
            violations.append({
                "framework": "PCI DSS",
                "control": "Requirement 8 - Identify Users and Authenticate Access",
                "severity": "CRITICAL",
                "description": f"Exposed authentication credentials or database strings detected ({len(secrets)} secrets).",
                "reason": "Hardcoded credentials violate PCI DSS user authentication and secret management requirements.",
                "recommendation": "Rotate credentials immediately and move to secure vault."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_iso27001(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate ISO/IEC 27001:2022 Information Security Management System controls."""
        violations = []
        deductions = 0

        if secrets:
            deductions += 25
            violations.append({
                "framework": "ISO 27001",
                "control": "Control A.5.15 - Access Control & Authentication",
                "severity": "HIGH",
                "description": f"Plaintext secret tokens or private keys detected ({len(secrets)} items).",
                "reason": "Exposed keys compromise information access control policies and cryptographic protection.",
                "recommendation": "Enforce Control A.8.24 (Use of Cryptography) for key management."
            })

        if pii:
            deductions += 20
            violations.append({
                "framework": "ISO 27001",
                "control": "Control A.8.10 - Information Protection & Data Masking",
                "severity": "MEDIUM",
                "description": f"Unmasked personally identifiable information detected ({len(pii)} items).",
                "reason": "Data protection controls require data masking and access restrictions.",
                "recommendation": "Apply data masking in accordance with organizational classification policies."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_soc2(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate SOC 2 Type II Trust Services Criteria (Security & Confidentiality)."""
        violations = []
        deductions = 0

        if secrets:
            deductions += 25
            violations.append({
                "framework": "SOC 2",
                "control": "CC6.1 - Logical Access Security Controls",
                "severity": "HIGH",
                "description": f"Hardcoded system credentials or API tokens detected ({len(secrets)} items).",
                "reason": "Logical access controls require credentials to be encrypted and managed via key management software.",
                "recommendation": "Revoke credentials and implement automated secret rotation."
            })

        if pii:
            deductions += 15
            violations.append({
                "framework": "SOC 2",
                "control": "P3.1 - Privacy Notice and Data Protection",
                "severity": "MEDIUM",
                "description": f"Exposed personal data detected in plaintext ({len(pii)} records).",
                "reason": "Privacy criteria require personal data to be protected against unauthorized access.",
                "recommendation": "Restrict data access boundaries to authorized system components."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _eval_nist(self, pii: List[Dict[str, Any]], secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate NIST Cybersecurity Framework (CSF) 2.0 Controls."""
        violations = []
        deductions = 0

        if secrets:
            deductions += 25
            violations.append({
                "framework": "NIST CSF 2.0",
                "control": "PR.AA-01 - Identity and Access Management",
                "severity": "HIGH",
                "description": f"Exposed identity keys or access tokens detected ({len(secrets)} items).",
                "reason": "NIST PR.AA-01 requires identities and credentials to be protected throughout their lifecycle.",
                "recommendation": "Enforce central Identity & Secrets Management."
            })

        if pii:
            deductions += 15
            violations.append({
                "framework": "NIST CSF 2.0",
                "control": "PR.DS-01 - Data-at-Rest Security Controls",
                "severity": "MEDIUM",
                "description": f"Unencrypted sensitive data records detected ({len(pii)} items).",
                "reason": "NIST PR.DS-01 requires sensitive data at rest to be protected with encryption.",
                "recommendation": "Apply cryptographic protection for sensitive data assets."
            })

        score = max(0, 100 - deductions)
        status = "COMPLIANT" if score == 100 else ("PARTIALLY_COMPLIANT" if score >= 70 else "NON_COMPLIANT")
        return {"score": score, "status": status, "violations": violations}

    def _generate_executive_summary(
        self,
        pii: List[Dict[str, Any]],
        secrets: List[Dict[str, Any]],
        status: str,
        violations: List[Dict[str, Any]]
    ) -> str:
        """Formulate a professional executive summary string."""
        if not pii and not secrets:
            return "No regulatory compliance violations or exposed credentials detected. Asset conforms to privacy and security baseline standards."

        summary_parts = []
        if pii:
            summary_parts.append(f"{len(pii)} Personally Identifiable Information (PII) record(s)")
        if secrets:
            summary_parts.append(f"{len(secrets)} exposed authentication secret(s) or API key(s)")

        findings_str = " and ".join(summary_parts)
        return (
            f"Regulatory compliance status assessed as {status}. "
            f"Analysis identified {findings_str} in plaintext. "
            f"Total {len(violations)} control violation(s) flagged across evaluated frameworks. "
            "Immediate credential rotation and data encryption remediation is recommended before deployment."
        )

    def _generate_recommendations(self, violations: List[Dict[str, Any]]) -> List[str]:
        """Compile prioritized remediation recommendations."""
        recs = []
        seen = set()
        for v in violations:
            rec = v.get("recommendation")
            if rec and rec not in seen:
                seen.add(rec)
                recs.append(rec)
        return recs
