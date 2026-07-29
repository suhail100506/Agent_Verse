import os
import json
import uuid
import datetime
import re
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from src.fake_certificate_verification_agent.flow_runner import run_certificate_flow
from src.identity_verification_agent.flow_runner import run_identity_flow
from src.malware_analyzer_agent.flow_runner import run_malware_flow
from src.threat_detection_agent.flow_runner import run_threat_flow
from src.phishing_detection_agent.flow_runner import run_phishing_flow
from src.privacy_compliance_agent.flow_runner import run_privacy_flow
from src.password_advisor_agent.flow_runner import run_password_flow
from src.fraud_detection_agent.flow_runner import run_fraud_flow
from src.incident_response_agent.flow_runner import run_incident_response_flow
from src.social_engineering_agent.flow_runner import run_social_engineering_flow

ORCHESTRATOR_REPORTS_DB_PATH = Path(__file__).parent / "orchestrator_reports_db.json"


def load_local_orchestrator_reports() -> list:
    if ORCHESTRATOR_REPORTS_DB_PATH.exists():
        try:
            with open(ORCHESTRATOR_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_local_orchestrator_report(report: dict) -> None:
    reports = load_local_orchestrator_reports()
    reports.insert(0, report)
    with open(ORCHESTRATOR_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def classify_user_request(prompt: str, file_path: Optional[str] = None) -> Tuple[str, str, float]:
    """
    Master Orchestrator Classifier:
    Determines target agent, agent description, and classification confidence.
    """
    p_lower = prompt.lower() if prompt else ""
    f_lower = os.path.basename(file_path).lower() if file_path else ""
    ext = os.path.splitext(f_lower)[1] if f_lower else ""

    # 1. Malware Analysis
    if ext in [".exe", ".dll", ".bin", ".vbs", ".bat", ".apk", ".elf", ".sys"] or any(k in p_lower for k in ["malware", "virus", "trojan", "executable", "yara", "payload", "ransomware"]):
        return "malware_analysis", "Malware Analyzer Agent", 0.98

    # 2. Threat Intelligence / IP / URL
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p_lower) or any(k in p_lower for k in ["ip", "url", "domain", "threat", "virustotal", "abuseipdb", "port scan", "ddos", "http"]) or f_lower.endswith((".pcap", ".log")):
        return "threat_detection", "Cyber Threat Detection Agent", 0.96

    # 3. Phishing Detection
    if any(k in p_lower for k in ["phishing", "spam", "suspicious email", "fake link", "spoof"]):
        return "phishing_detection", "Phishing Detection Agent", 0.95

    # 4. Social Engineering / Deepfake Detection
    if any(k in p_lower for k in ["deepfake", "impersonat", "social engineer", "vishing", "pretexting", "ceo fraud", "voice clone", "manipulation tactic"]):
        return "social_engineering", "Social Engineering / Deepfake Detection Agent", 0.96

    # 5. Privacy Compliance
    if any(k in p_lower for k in ["pii", "gdpr", "dpdp", "privacy", "compliance", "personal data", "hipaa"]):
        return "privacy_compliance", "Privacy Compliance Agent", 0.95

    # 6. Password Security
    if any(k in p_lower for k in ["password", "passphrase", "credential strength", "entropy"]):
        return "password_advisor", "Password Security Advisor Agent", 0.95

    # 7. Fraud Detection
    if any(k in p_lower for k in ["transaction", "fraud", "chargeback", "payment anomaly", "wire transfer"]):
        return "fraud_detection", "Fraud Detection Agent", 0.94

    # 8. Incident Response
    if any(k in p_lower for k in ["incident", "breach", "containment", "playbook", "post-mortem"]):
        return "incident_response", "Incident Response Agent", 0.93

    # 9. Identity Verification
    if any(k in p_lower for k in ["identity", "passport", "id card", "license", "selfie", "face match", "liveness", "ssn", "voter"]) or "passport" in f_lower or "license" in f_lower or "selfie" in f_lower or "id" in f_lower:
        return "identity_verification", "Identity Verification Agent", 0.97

    # 10. Certificate Verification (Default for PDFs / Degree images unless specified)
    if any(k in p_lower for k in ["cert", "degree", "diploma", "university", "stanford", "mit", "academic", "grade", "transcript"]) or "cert" in f_lower or "degree" in f_lower or "diploma" in f_lower:
        return "certificate_verification", "Fake Certificate Verification Agent", 0.97

    # Default fallback
    if file_path:
        return "certificate_verification", "Fake Certificate Verification Agent", 0.85
    return "incident_response", "Incident Response Agent", 0.90


def run_master_orchestrator(
    prompt: str = "",
    file_path: Optional[str] = None,
    selfie_path: Optional[str] = None,
    file_type: str = "pdf",
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Master Orchestrator Engine:
    Classifies, dispatches to sub-agents, and synthesizes final CyberVerse Security Audit Report.
    """
    target_key, target_name, confidence = classify_user_request(prompt, file_path)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    orchestration_id = f"ORCH-{uuid.uuid4().hex[:8].upper()}"

    if target_key == "certificate_verification":
        effective_path = file_path if file_path else "test_cert.pdf"
        sub_report = run_certificate_flow(effective_path, file_type, credential_id=credential_id)
    elif target_key == "identity_verification":
        effective_doc = file_path if file_path else "id_doc.pdf"
        sub_report = run_identity_flow(effective_doc, selfie_path, file_type, credential_id=credential_id)
    elif target_key == "malware_analysis":
        effective_path = file_path if file_path else "suspicious_payload.bin"
        sub_report = run_malware_flow(effective_path, "binary", credential_id=credential_id)
    elif target_key == "threat_detection":
        sub_report = run_threat_flow(prompt, file_path, credential_id=credential_id)
    elif target_key == "phishing_detection":
        sub_report = run_phishing_flow(prompt, credential_id=credential_id)
    elif target_key == "social_engineering":
        sub_report = run_social_engineering_flow(prompt, file_path, credential_id=credential_id)
    elif target_key == "privacy_compliance":
        sub_report = run_privacy_flow(prompt, credential_id=credential_id)
    elif target_key == "password_advisor":
        sub_report = run_password_flow(prompt, credential_id=credential_id)
    elif target_key == "fraud_detection":
        sub_report = run_fraud_flow({"amount": 2500.0, "location": prompt or "Unknown"}, credential_id=credential_id)
    elif target_key == "incident_response":
        sub_report = run_incident_response_flow({"title": prompt or "Multi-Agent Cyber Incident Audit", "severity": "HIGH"}, credential_id=credential_id)
    else:
        effective_path = file_path if file_path else "security_audit.pdf"
        sub_report = run_certificate_flow(effective_path, file_type, credential_id=credential_id)

    master_report = {
        "orchestration_id": orchestration_id,
        "created_at": timestamp,
        "platform": "CyberVerse AI Multi-Agent Platform",
        "user_query": prompt if prompt else f"File Analysis: {os.path.basename(file_path) if file_path else 'Security Audit'}",
        "router_diagnostics": {
            "selected_agent": target_name,
            "agent_key": target_key,
            "classification_confidence": confidence,
            "routing_reason": f"Dispatched based on prompt tokens and artifact metadata to '{target_name}'."
        },
        "sub_agent_report": sub_report,
        "status": sub_report.get("status", "Verified"),
        "overall_score": sub_report.get("overall_score", 95),
        "summary": f"[Master Orchestrator -> {target_name}] {sub_report.get('summary', 'Analysis complete.')}",
        "recommendation": sub_report.get("recommendation", "Follow security guidelines."),
        "next_action": sub_report.get("next_action", "Archive report.")
    }

    save_local_orchestrator_report(master_report)

    mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    try:
        from pymongo import MongoClient
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=1200)
        client.admin.command('ping')
        db = client[os.getenv("DATABASE_NAME", "certificate_verifier")]
        collection = db["cyberverse_orchestrator_reports"]
        collection.insert_one(master_report.copy())
        client.close()
        master_report["mongodb_saved"] = True
    except Exception:
        master_report["mongodb_saved"] = False

    return master_report
