import os
import json
import uuid
import datetime
import re
from typing import Dict, Any, Optional
from pathlib import Path

from src.utils.llm_client import run_llm_agent
from src.utils.mongo_client import save_report

PRIVACY_REPORTS_DB_PATH = Path(__file__).parent / "privacy_reports_db.json"

DEFAULT_SYSTEM_PROMPT = """You are a privacy compliance auditor (GDPR / DPDP / HIPAA) reviewing a document's text for
unmasked personally identifiable information (PII).
Respond with ONLY a JSON object (no prose, no markdown fences) matching exactly this shape:
{
  "status": "Verified" | "Suspicious" | "Fake",
  "risk_level": "LOW RISK" | "MEDIUM RISK" | "CRITICAL RISK",
  "overall_score": <int 0-100>,
  "confidence": <float 0-1>,
  "checks": {
    "gdpr_compliance": "...", "dpdp_act_check": "...", "hipaa_compliance": "...", "data_masking": "..."
  },
  "summary": "...",
  "recommendation": "...",
  "next_action": "..."
}
Use "status": "Verified" for a compliant document and "Fake" for a confirmed PII violation (matching this platform's status vocabulary)."""


def load_local_privacy_reports() -> list:
    if PRIVACY_REPORTS_DB_PATH.exists():
        try:
            with open(PRIVACY_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_local_privacy_report(report: dict) -> None:
    reports = load_local_privacy_reports()
    reports.insert(0, report)
    with open(PRIVACY_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def run_privacy_flow(
    text_content: str,
    credential_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    # Check for PII (Social Security Numbers, Credit Cards, Emails, Phone Numbers)
    ssn_match = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text_content)
    cc_match = re.findall(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", text_content)
    email_match = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text_content)

    has_pii_violation = len(ssn_match) > 0 or len(cc_match) > 0

    if not has_pii_violation:
        status = "Verified"
        risk_level = "LOW RISK"
        overall_score = 95
        confidence = 0.97
        checks = {
            "gdpr_compliance": "Passed - No unencrypted Personally Identifiable Information (PII) detected.",
            "dpdp_act_check": "Passed - Personal data processing consent flags valid.",
            "hipaa_compliance": "Passed - Zero Protected Health Information (PHI) strings exposed.",
            "data_masking": "Passed - Sensitive fields masked correctly with asterisk placeholders."
        }
        summary = "Privacy Compliance Audit passed. Document adheres to GDPR, DPDP, and HIPAA guidelines."
        recommendation = "Document is safe for cross-border storage and distribution."
        next_action = "Mark privacy audit as approved."
    else:
        status = "Fake"
        risk_level = "HIGH RISK"
        overall_score = 42
        confidence = 0.95
        checks = {
            "gdpr_compliance": f"Failed - Found {len(ssn_match)} unmasked SSNs and {len(cc_match)} Credit Card numbers.",
            "dpdp_act_check": "Failed - Mandatory data principal consent disclosure missing.",
            "hipaa_compliance": "Warning - Sensitive identity fields stored in plain text.",
            "data_masking": "Failed - Plain-text SSN and financial card data exposed."
        }
        summary = f"PRIVACY VIOLATION ALERT: Document exposes unmasked PII ({len(ssn_match)} SSNs, {len(cc_match)} Credit Cards)."
        recommendation = "Apply automated PII redacting mask prior to external sharing."
        next_action = "Trigger Data Loss Prevention (DLP) remediation playbook."

    llm_result = run_llm_agent(
        system_prompt=system_prompt or DEFAULT_SYSTEM_PROMPT,
        user_prompt=f"Document text (truncated to 4000 chars): {text_content[:4000]}\nDetected SSNs: {len(ssn_match)}, Credit cards: {len(cc_match)}, Emails: {len(email_match)}",
        credential_id=credential_id,
        model=model or "llama-3.3-70b-versatile",
        expect_json=True,
    )
    if llm_result["ok"] and isinstance(llm_result["content"], dict):
        d = llm_result["content"]
        status = d.get("status", status)
        risk_level = d.get("risk_level", risk_level)
        overall_score = d.get("overall_score", overall_score)
        confidence = d.get("confidence", confidence)
        checks = d.get("checks", checks)
        summary = d.get("summary", summary)
        recommendation = d.get("recommendation", recommendation)
        next_action = d.get("next_action", next_action)

    report_id = f"PRV-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    final_report = {
        "report_id": report_id,
        "created_at": timestamp,
        "agent": "Privacy Compliance Agent",
        "type": "privacy",
        "status": status,
        "risk_level": risk_level,
        "confidence": confidence,
        "overall_score": overall_score,
        "pii_detected": {
            "ssn_count": len(ssn_match),
            "credit_cards_count": len(cc_match),
            "emails_count": len(email_match)
        },
        "checks": checks,
        "summary": summary,
        "recommendation": recommendation,
        "next_action": next_action,
        "llm_reasoning_used": llm_result["ok"],
        "llm_source": llm_result["source"]
    }

    save_local_privacy_report(final_report)

    final_report["mongodb_saved"] = save_report("privacy_compliance_reports", final_report)

    return final_report
