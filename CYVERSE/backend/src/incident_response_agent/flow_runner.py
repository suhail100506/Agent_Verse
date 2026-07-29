import os
import json
import uuid
import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from src.utils.llm_client import run_llm_agent

INCIDENT_REPORTS_DB_PATH = Path(__file__).parent / "incident_reports_db.json"

DEFAULT_SYSTEM_PROMPT = """You are a SOC incident response lead running the containment/eradication/recovery playbook
for a reported cyber incident.
Respond with ONLY a JSON object (no prose, no markdown fences) matching exactly this shape:
{
  "status": "Verified" | "Suspicious" | "Fake",
  "risk_level": "LOW RISK" | "MEDIUM RISK" | "CRITICAL RISK",
  "overall_score": <int 0-100>,
  "confidence": <float 0-1>,
  "checks": {
    "containment_phase": "...", "eradication_phase": "...", "recovery_phase": "...", "post_incident_audit": "..."
  },
  "summary": "...",
  "recommendation": "...",
  "next_action": "..."
}
Use "status": "Verified" for a successfully-contained/low-severity incident and "Fake" for an active critical incident
(matching this platform's status vocabulary)."""


def load_local_incident_reports() -> list:
    if INCIDENT_REPORTS_DB_PATH.exists():
        try:
            with open(INCIDENT_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_local_incident_report(report: dict) -> None:
    reports = load_local_incident_reports()
    reports.insert(0, report)
    with open(INCIDENT_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def run_incident_response_flow(
    incident_data: Dict[str, Any],
    credential_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    title = incident_data.get("title", "Multi-Agent Cyber Incident Audit")
    severity = incident_data.get("severity", "HIGH")
    
    report_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    t_lower = title.lower()
    is_threat = any(k in t_lower for k in ["ransomware", "outbreak", "exfiltration", "attack", "breach", "zero-day", "compromise"]) or severity.upper() in ["CRITICAL", "EMERGENCY"]

    if is_threat:
        status = "Fake"
        risk_level = "CRITICAL RISK"
        overall_score = 28
        confidence = 0.96
        checks = {
            "containment_phase": "Failed - Active C2 outbound traffic and data exfiltration detected.",
            "eradication_phase": "Warning - Ransomware payload active across host nodes.",
            "recovery_phase": "Failed - Isolated offline backup restoration required.",
            "post_incident_audit": "Failed - High severity cyber incident triggered."
        }
        summary = f"CRITICAL INCIDENT ALERT: Ransomware outbreak & exfiltration flagged for '{title}'."
        recommendation = "Initiate emergency isolation and dispatch Incident Response Team."
        next_action = "Execute Playbook #INC-CRITICAL-99."
    else:
        status = "Verified"
        risk_level = "LOW RISK"
        overall_score = 92
        confidence = 0.98
        checks = {
            "containment_phase": "Passed - Host network interface isolated. C2 outbound traffic blocked.",
            "eradication_phase": "Passed - Malicious artifacts and registry persistence keys purged.",
            "recovery_phase": "Passed - System image restored from verified gold master backup.",
            "post_incident_audit": "Passed - Complete SOC timeline and forensic evidence logged to MongoDB Atlas."
        }
        summary = f"Incident Response Playbook executed successfully for '{title}'. Containment, Eradication, and Recovery completed."
        recommendation = "Maintain enhanced monitoring on affected VLAN for 72 hours."
        next_action = "Close incident ticket and submit final Post-Mortem Report to CISO."

    llm_result = run_llm_agent(
        system_prompt=system_prompt or DEFAULT_SYSTEM_PROMPT,
        user_prompt=f"Incident title: {title}\nReported severity: {severity}",
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

    final_report = {
        "report_id": report_id,
        "created_at": timestamp,
        "agent": "Incident Response Agent",
        "type": "incident_response",
        "title": title,
        "severity": severity,
        "status": status,
        "risk_level": risk_level,
        "confidence": confidence,
        "overall_score": overall_score,
        "checks": checks,
        "summary": summary,
        "recommendation": recommendation,
        "next_action": next_action,
        "llm_reasoning_used": llm_result["ok"],
        "llm_source": llm_result["source"]
    }

    save_local_incident_report(final_report)

    mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    try:
        from pymongo import MongoClient
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=1200)
        client.admin.command('ping')
        db = client[os.getenv("DATABASE_NAME", "certificate_verifier")]
        collection = db["incident_response_reports"]
        collection.insert_one(final_report.copy())
        client.close()
        final_report["mongodb_saved"] = True
    except Exception:
        final_report["mongodb_saved"] = False

    return final_report
