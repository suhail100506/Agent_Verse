import os
import json
import uuid
import datetime
import re
from typing import Dict, Any, Optional
from pathlib import Path
import logging

from src.utils.email_service import send_alert
from src.utils.mongo_client import save_report

logger = logging.getLogger(__name__)

PHISHING_REPORTS_DB_PATH = Path(__file__).parent / "phishing_reports_db.json"

def load_local_phishing_reports() -> list:
    if PHISHING_REPORTS_DB_PATH.exists():
        try:
            with open(PHISHING_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_local_phishing_report(report: dict) -> None:
    reports = load_local_phishing_reports()
    reports.insert(0, report)
    with open(PHISHING_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)

def run_phishing_flow(
    url_or_text: str,
    credential_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
    event_id: Optional[str] = None
) -> Dict[str, Any]:
    url_match = re.search(r"https?://[^\s]+", url_or_text)
    target_url = url_match.group(0) if url_match else "No link detected"

    report_id = f"PHISH-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        from crewai import Agent, Task, Crew, Process
        
        # We allow overriding with the passed model if available, otherwise default to gemini
        # Using 1.5-flash as 3.5-flash doesn't exist in standard litellm yet.
        model_name = model or os.getenv("GEMINI_MODEL", "gemini/gemini-1.5-flash-latest")
        
        # Ensure API key is set if not already in environment
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if not gemini_api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set. Please provide a valid key.")
        os.environ["GEMINI_API_KEY"] = gemini_api_key
        
        analyst = Agent(
            role='Cybersecurity Phishing Analyst',
            goal='Analyze the URL or text for phishing indicators and credential harvesting attempts.',
            backstory='Expert cybersecurity analyst specializing in identifying deceptive URLs, typosquatting, and malicious payloads.',
            verbose=True,
            allow_delegation=False,
            llm=model_name
        )
        
        analyze_task = Task(
            description=(
                f"Examine the provided text or URL: {url_or_text}\n"
                f"{'System Prompt Override: ' + system_prompt if system_prompt else ''}\n"
                "Analyze it for typosquatting, domain age probability, and credential harvesting indicators.\n"
                "Determine if it is a legitimate site or a phishing attempt.\n"
                "Output MUST be a valid raw JSON object. Do not include markdown code block syntax (like ```json)."
            ),
            expected_output=(
                "A valid JSON object with the following structure:\n"
                "{\n"
                f'  "target_url": "{target_url}",\n'
                '  "status": "Fake" or "Verified",\n'
                '  "risk_level": "HIGH RISK" or "LOW RISK",\n'
                '  "confidence": 0.95,\n'
                '  "overall_score": 32,\n'
                '  "checks": {\n'
                '    "url_typosquatting": "Failed - Domain ... / Passed - Domain ...",\n'
                '    "ssl_certificate": "Failed - ... / Passed - ...",\n'
                '    "email_header_dkim": "Failed - ... / Passed - ...",\n'
                '    "credential_harvesting": "Failed - ... / Passed - ..."\n'
                '  },\n'
                '  "summary": "A 1-2 sentence summary of the findings.",\n'
                '  "recommendation": "What the user should do.",\n'
                '  "next_action": "What the system should do next."\n'
                "}"
            ),
            agent=analyst
        )
        
        crew = Crew(
            agents=[analyst],
            tasks=[analyze_task],
            process=Process.sequential,
            verbose=True
        )
        
        result = crew.kickoff()
        
        raw_output = str(result.raw) if hasattr(result, "raw") else str(result)
        if raw_output.startswith("```json"):
            raw_output = raw_output.replace("```json", "", 1)
        if raw_output.startswith("```"):
            raw_output = raw_output.replace("```", "", 1)
        if raw_output.endswith("```"):
            raw_output = raw_output.rsplit("```", 1)[0]
            
        parsed_result = json.loads(raw_output.strip())
        
        status = parsed_result.get("status", "Fake")
        risk_level = parsed_result.get("risk_level", "HIGH RISK")
        overall_score = parsed_result.get("overall_score", 32)
        confidence = parsed_result.get("confidence", 0.95)
        checks = parsed_result.get("checks", {})
        summary = parsed_result.get("summary", "Analysis completed.")
        recommendation = parsed_result.get("recommendation", "")
        next_action = parsed_result.get("next_action", "")
        llm_used = True
        
    except Exception as e:
        logger.error(f"CrewAI execution failed: {e}")
        status = "Fake"
        risk_level = "HIGH RISK"
        overall_score = 32
        confidence = 0.95
        checks = {}
        summary = f"Error during AI analysis: {e}"
        recommendation = "Manual review required due to analysis error."
        next_action = "Investigate system error."
        llm_used = False

    final_report = {
        "report_id": report_id,
        "event_id": event_id,
        "created_at": timestamp,
        "agent": "Phishing Detection Agent",
        "type": "phishing",
        "target_url": target_url,
        "status": status,
        "risk_level": risk_level,
        "confidence": confidence,
        "overall_score": overall_score,
        "checks": checks,
        "summary": summary,
        "recommendation": recommendation,
        "next_action": next_action,
        "email_delivery_status": "skipped",
        "email_delivery_error": None,
        "llm_reasoning_used": llm_used,
        "llm_source": "CrewAI"
    }

    if status == "Fake":
        email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", url_or_text)
        recipient_email = email_match.group(0) if email_match else os.getenv("EMAIL_USER", "kavin88701@gmail.com")
        
        logger.info(f"Phishing detected! Triggering email alert to {recipient_email}")
        email_result = send_alert(recipient_email, final_report)
        final_report["email_delivery_status"] = email_result["status"]
        final_report["email_delivery_error"] = email_result["error"]

    save_local_phishing_report(final_report)

    # Use the existing mongo client utility to be consistent with the backend architecture
    final_report["mongodb_saved"] = save_report("phishing_detection_reports", final_report)

    return final_report
