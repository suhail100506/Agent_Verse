import time
import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import JSONResponse
import json
from pydantic import ValidationError

from src.phishing_detection_agent.models import PhishingAnalyzeRequest, PhishingAnalyzeResponse
from src.phishing_detection_agent.services import (
    analyze_sender, 
    analyze_subject, 
    analyze_urls, 
    analyze_headers, 
    calculate_overall_risk,
    send_alert_email
)
from src.phishing_detection_agent.crew import run_ai_analysis
from src.phishing_detection_agent.database import log_analysis_request
from dotenv import load_dotenv
import os

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Detection Agent",
    description="Standalone AI Agent for detecting phishing emails using heuristics and Gemini.",
    version="1.0.0"
)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={"success": False, "error": "Invalid input format or missing fields.", "details": exc.errors()},
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "An internal error occurred.", "details": str(exc)},
    )

@app.get("/api/phishing/health")
async def health_check():
    return {"status": "ok", "service": "Phishing Detection Agent"}

@app.post("/api/analyze/phishing")
async def analyze_phishing(
    url_or_text: str = Form(..., alias="url_or_text"),
    notify_email: Optional[str] = Form(None, alias="notify_email")
):
    start_time = time.time()
    
    logger.info(f"Received phishing analysis request")
    
    # Try to parse as JSON if the user pasted JSON in the frontend box
    req_data = {}
    try:
        req_data = json.loads(url_or_text)
    except:
        req_data = {"body": url_or_text}

    sender = req_data.get("sender", "unknown@example.com")
    subject = req_data.get("subject", "No Subject")
    body = req_data.get("body", "")
    urls = req_data.get("urls", [])
    headers = req_data.get("headers", "")
    
    # Target email to alert (frontend sets notify_email, or fallback to JSON payload)
    target_email = notify_email or req_data.get("recipient")

    try:
        # Heuristics
        sender_score, sender_findings = analyze_sender(sender)
        subject_score, subject_findings = analyze_subject(subject)
        url_score, url_findings = analyze_urls(urls)
        header_score, header_findings = analyze_headers(headers or "")
        
        # Combine static findings
        findings = sender_findings + subject_findings + url_findings + header_findings
        
        # CrewAI Gemini reasoning
        try:
            ai_result = run_ai_analysis(
                sender=sender,
                subject=subject,
                body=body,
                urls=urls
            )
            
            ai_score = ai_result.confidence // 3  # E.g. 90% confidence = 30 points
            findings.append(f"AI Assessment: {ai_result.risk_summary}")
            recommendations = ai_result.recommendations
            attack_type = ai_result.attack_type
            confidence = ai_result.confidence
            
        except Exception as e:
            logger.error(f"CrewAI/Gemini execution failed: {e}")
            ai_score = 0
            attack_type = "Unknown"
            confidence = 0
            findings.append("AI reasoning failed or timed out.")
            recommendations = ["Analyze manually - AI component failed"]
            
        # Calculate Risk Score
        risk_score, risk_level = calculate_overall_risk(
            sender_score, subject_score, url_score, header_score, ai_score
        )
        
        email_status = None
        email_error = None
        
        # If it's suspicious (not Safe) and we have an email address to notify
        if risk_level != "Safe" and target_email:
            success, err_msg = send_alert_email(target_email, risk_level, findings)
            if success:
                email_status = "sent"
                logger.info(f"Sent alert email to {target_email}")
            else:
                email_status = "failed"
                email_error = err_msg
                logger.warning(f"Failed to send alert email: {err_msg}")
        
        response_data = PhishingAnalyzeResponse(
            success=True,
            risk_score=risk_score,
            risk_level=risk_level,
            attack_type=attack_type,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            next_step="Malware Analysis Agent",
            email_delivery_status=email_status,
            email_delivery_error=email_error
        )
        
        execution_time_ms = (time.time() - start_time) * 1000
        
        # Log to MongoDB
        await log_analysis_request(
            input_data=req_data,
            output_data=response_data.model_dump(),
            execution_time_ms=execution_time_ms,
            status="success"
        )
        
        logger.info(f"Analysis complete. Risk Level: {risk_level}, Time: {execution_time_ms:.2f}ms")
        return response_data
        
    except Exception as e:
        execution_time_ms = (time.time() - start_time) * 1000
        logger.error(f"Analysis failed: {e}")
        
        await log_analysis_request(
            input_data=req_data,
            output_data={"error": str(e)},
            execution_time_ms=execution_time_ms,
            status="error"
        )
        
        raise HTTPException(status_code=500, detail=str(e))

