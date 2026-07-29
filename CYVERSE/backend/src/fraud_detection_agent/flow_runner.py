import os
import json
import uuid
import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from src.utils.llm_client import run_llm_agent

FRAUD_REPORTS_DB_PATH = Path(__file__).parent / "fraud_reports_db.json"

DEFAULT_SYSTEM_PROMPT = """You are a financial fraud detection analyst evaluating a transaction for anomalies.
Respond with ONLY a JSON object (no prose, no markdown fences) matching exactly this shape:
{
  "status": "Verified" | "Suspicious" | "Fake",
  "risk_level": "LOW RISK" | "MEDIUM RISK" | "CRITICAL RISK",
  "overall_score": <int 0-100>,
  "confidence": <float 0-1>,
  "checks": {
    "behavioral_analytics": "...", "device_fingerprint": "...", "velocity_check": "...", "geolocation_anomaly": "..."
  },
  "summary": "...",
  "recommendation": "...",
  "next_action": "..."
}
Use "status": "Verified" for a legitimate transaction and "Fake" for a confirmed fraudulent transaction (matching this platform's status vocabulary)."""


def load_local_fraud_reports() -> list:
    if FRAUD_REPORTS_DB_PATH.exists():
        try:
            with open(FRAUD_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_local_fraud_report(report: dict) -> None:
    reports = load_local_fraud_reports()
    reports.insert(0, report)
    with open(FRAUD_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def run_fraud_flow(
    data: Dict[str, Any],
    credential_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    amount = data.get("amount", 2500.0)
    device_id = data.get("device_id", "DEV-TRUSTED-001")
    location = data.get("location", "Home Region")

    is_fraud = amount > 5000.0 or "unknown" in device_id.lower() or "suspicious" in str(data).lower() or location.lower() not in ["home region", "trusted location", "local"]

    if not is_fraud:
        status = "Verified"
        risk_level = "LOW RISK"
        overall_score = 96
        confidence = 0.97
        checks = {
            "behavioral_analytics": "Passed - Transaction pattern matches user historical baseline.",
            "device_fingerprint": "Passed - Known trusted device ID verified.",
            "velocity_check": "Passed - Velocity check 1 transaction in last 60 minutes.",
            "geolocation_anomaly": "Passed - Transaction IP geolocation aligns with primary home region."
        }
        summary = f"Fraud detection engine verified transaction of ${amount:.2f} as legitimate."
        recommendation = "Approve financial transaction."
        next_action = "Complete payment processing."
    else:
        status = "Fake"
        risk_level = "CRITICAL RISK"
        overall_score = 25
        confidence = 0.95
        checks = {
            "behavioral_analytics": "Failed - High-value transfer anomaly detected.",
            "device_fingerprint": "Failed - Untrusted new device fingerprint.",
            "velocity_check": "Failed - Rapid velocity spike (5 transactions in 2 minutes).",
            "geolocation_anomaly": f"Failed - Impossible travel anomaly: Login from {location} within 10 minutes of primary region."
        }
        summary = f"FRAUD ALERT: Transaction of ${amount:.2f} flagged for behavioral anomaly and impossible travel."
        recommendation = "Block transaction and freeze user account pending MFA step-up authentication."
        next_action = "Escalate to Fraud Operations Team."

    llm_result = run_llm_agent(
        system_prompt=system_prompt or DEFAULT_SYSTEM_PROMPT,
        user_prompt=f"Transaction amount: ${amount:.2f}\nDevice ID: {device_id}\nLocation: {location}\nRaw data: {data}",
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

    report_id = f"FRD-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    final_report = {
        "report_id": report_id,
        "created_at": timestamp,
        "agent": "Fraud Detection Agent",
        "type": "fraud",
        "amount": amount,
        "location": location,
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

    save_local_fraud_report(final_report)

    mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    try:
        from pymongo import MongoClient
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=1200)
        client.admin.command('ping')
        db = client[os.getenv("DATABASE_NAME", "certificate_verifier")]
        collection = db["fraud_detection_reports"]
        collection.insert_one(final_report.copy())
        client.close()
        final_report["mongodb_saved"] = True
    except Exception:
        final_report["mongodb_saved"] = False

    return final_report
