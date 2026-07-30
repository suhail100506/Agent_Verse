import time
import logging
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from src.phishing_detection_agent.models import PhishingAnalyzeRequest, PhishingAnalyzeResponse
from src.phishing_detection_agent.services import (
    analyze_sender, 
    analyze_subject, 
    analyze_urls, 
    analyze_headers, 
    calculate_overall_risk
)
from src.phishing_detection_agent.crew import run_ai_analysis
from src.phishing_detection_agent.database import log_analysis_request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Detection Agent",
    description="Standalone AI Agent for detecting phishing emails using heuristics and Gemini.",
    version="1.0.0"
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

@app.post("/api/phishing/analyze", response_model=PhishingAnalyzeResponse)
async def analyze_phishing(request: PhishingAnalyzeRequest):
    start_time = time.time()
    
    logger.info(f"Received phishing analysis request for sender: {request.sender}")
    
    try:
        # Heuristics
        sender_score, sender_findings = analyze_sender(request.sender)
        subject_score, subject_findings = analyze_subject(request.subject)
        url_score, url_findings = analyze_urls(request.urls)
        header_score, header_findings = analyze_headers(request.headers or "")
        
        # Combine static findings
        findings = sender_findings + subject_findings + url_findings + header_findings
        
        # CrewAI Gemini reasoning
        try:
            ai_result = run_ai_analysis(
                sender=request.sender,
                subject=request.subject,
                body=request.body,
                urls=request.urls
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
        
        response_data = PhishingAnalyzeResponse(
            success=True,
            risk_score=risk_score,
            risk_level=risk_level,
            attack_type=attack_type,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            next_step="Malware Analysis Agent"
        )
        
        execution_time_ms = (time.time() - start_time) * 1000
        
        # Log to MongoDB
        await log_analysis_request(
            input_data=request.model_dump(),
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
            input_data=request.model_dump(),
            output_data={"error": str(e)},
            execution_time_ms=execution_time_ms,
            status="error"
        )
        
        raise HTTPException(status_code=500, detail=str(e))

