import os
import uuid
import time
import httpx
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from email import message_from_bytes
from email.message import Message

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from src.email_threat_template.email_automation import send_alert_email_if_needed
from src.utils.mongo_client import get_mongo_collection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Email Threat Investigation Template",
    description="Orchestrator for the Email Threat Investigation Workflow.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

def parse_eml_for_attachment(file_bytes: bytes) -> tuple[Optional[bytes], Optional[str]]:
    """Simple parser to extract the first attachment from an .eml file."""
    try:
        msg: Message = message_from_bytes(file_bytes)
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                return part.get_payload(decode=True), filename
    except Exception as e:
        logger.warning(f"Failed to parse EML for attachment: {e}")
    return None, None

@app.post("/api/template/email-threat-investigation")
async def execute_email_threat_workflow(
    email_text: Optional[str] = Form(None, alias="url_or_text"),
    file: Optional[UploadFile] = File(None),
    notify_email: Optional[str] = Form(None)
):
    start_time = time.time()
    investigation_id = f"ETI-{uuid.uuid4().hex[:8].upper()}"
    logger.info(f"[{investigation_id}] Starting Email Threat Investigation workflow")

    attachment_bytes = None
    attachment_name = None
    email_content_str = email_text or ""

    # Step 1 & 3 (Extract attachment if .eml)
    if file:
        file_bytes = await file.read()
        filename = file.filename.lower()
        if filename.endswith(".eml") or filename.endswith(".msg"):
            logger.info(f"[{investigation_id}] Parsing {filename} for attachments")
            email_content_str += f"\n[File: {filename}]"
            attachment_bytes, attachment_name = parse_eml_for_attachment(file_bytes)
        elif filename.endswith(".txt"):
            email_content_str += f"\n{file_bytes.decode('utf-8', errors='ignore')}"
        else:
            # Assume the uploaded file itself is the suspicious attachment if no text is provided
            attachment_bytes = file_bytes
            attachment_name = file.filename

    if not email_content_str and attachment_bytes is None:
        raise HTTPException(status_code=400, detail="Must provide email text or an .eml/.msg/.txt file.")

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Step 2: Phishing Detection Agent
        logger.info(f"[{investigation_id}] Calling Phishing Detection Agent")
        phishing_report = {}
        try:
            phish_resp = await client.post(
                f"{API_BASE}/api/analyze/phishing", 
                data={"url_or_text": email_content_str, "notify_email": notify_email}
            )
            phish_resp.raise_for_status()
            phishing_report = phish_resp.json()
        except Exception as e:
            logger.error(f"[{investigation_id}] Phishing analysis failed: {e}. Stopping workflow.")
            raise HTTPException(status_code=500, detail=f"Phishing analysis failed: {e}")

        phishing_risk_score = phishing_report.get("risk_score", 0)

        # Step 3: Malware Analysis Agent (Conditional)
        malware_report = {}
        malware_detected = False
        if attachment_bytes and attachment_name:
            logger.info(f"[{investigation_id}] Extracted attachment '{attachment_name}'. Calling Malware Agent.")
            try:
                files_payload = {"file": (attachment_name, attachment_bytes, "application/octet-stream")}
                malw_resp = await client.post(
                    f"{API_BASE}/api/malware/analyze",
                    files=files_payload
                )
                malw_resp.raise_for_status()
                malware_report = malw_resp.json()
                malware_detected = malware_report.get("malware_detected", False)
            except Exception as e:
                logger.error(f"[{investigation_id}] Malware analysis failed: {e}. Continuing without malware result.")
                malware_report = {"error": str(e), "malware_detected": False}
        else:
            logger.info(f"[{investigation_id}] No attachment found to analyze.")

        # Step 4: Incident Response Agent
        logger.info(f"[{investigation_id}] Calling Incident Response Agent")
        incident_report = {}
        try:
            ir_payload = {
                "phishing_result": phishing_report,
                "malware_result": malware_report if malware_report else None,
                "other_findings": {"title": f"Email Investigation {investigation_id}"}
            }
            ir_resp = await client.post(
                f"{API_BASE}/api/incident/respond",
                json=ir_payload
            )
            ir_resp.raise_for_status()
            incident_report = ir_resp.json()
        except Exception as e:
            logger.error(f"[{investigation_id}] Incident Response failed: {e}. Generating fallback report.")
            incident_report = {
                "incident_type": "Email Threat Analysis",
                "severity": "Unknown",
                "business_impact": "Unknown",
                "containment_plan": "Analyze logs manually.",
                "recovery_plan": "Restore safely.",
                "executive_summary": "Incident response agent failed."
            }

        # Step 5: Email Alert Automation
        logger.info(f"[{investigation_id}] Executing Email Alert Automation rules")
        send_alert_email_if_needed(
            investigation_id=investigation_id,
            phishing_risk_score=phishing_risk_score,
            malware_detected=malware_detected,
            recipient_email=notify_email,
            incident_severity=incident_report.get("severity", "Unknown"),
            threat_level=malware_report.get("threat_level", phishing_report.get("risk_level", "Unknown")),
            recommended_action=incident_report.get("containment_plan", "Unknown")
        )

        # Step 6: Generate Final Investigation Report
        execution_time_seconds = round(time.time() - start_time, 2)
        logger.info(f"[{investigation_id}] Workflow completed in {execution_time_seconds}s")
        
        final_report = {
            "investigation_id": investigation_id,
            "risk_score": phishing_risk_score,
            "threat_level": malware_report.get("threat_level", phishing_report.get("risk_level", "Safe")),
            "malware_status": "Detected" if malware_detected else ("Clean" if attachment_bytes else "No Attachment"),
            "incident_type": incident_report.get("incident_type", "Phishing Attempt"),
            "business_impact": incident_report.get("business_impact", "TBD"),
            "containment_actions": incident_report.get("containment_plan", "TBD"),
            "recovery_actions": incident_report.get("recovery_plan", "TBD"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ai_executive_summary": incident_report.get("executive_summary", "Review the generated logs."),
            "execution_time_seconds": execution_time_seconds
        }

        # Log final report to MongoDB
        collection = get_mongo_collection("email_threat_reports")
        if collection is not None:
            collection.insert_one(final_report.copy())

        return final_report
