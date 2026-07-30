import os
import time
import json
from fastapi import FastAPI, HTTPException, Form, Body, Request
from fastapi.middleware.cors import CORSMiddleware
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    load_dotenv(env_path)
except ImportError:
    pass

from src.incident_response_agent.models import IncidentRequest
from src.incident_response_agent.services import process_incident

app = FastAPI(
    title="Incident Response Agent API",
    description="Cyberverse AI Agent for Incident Classification and Response Planning",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/incident/health")
def health_check():
    return {
        "status": "online",
        "service": "Incident Response Agent",
        "version": "1.0.0"
    }

@app.post("/api/incident/respond")
async def respond_to_incident(request: Request):
    """
    Analyzes security findings (e.g., malware/phishing) and outputs
    a structured incident response plan.
    Supports both raw JSON body and Form Data (payload=...).
    """
    start_time = time.time()
    
    # Try parsing as JSON first (direct API usage)
    try:
        body_json = await request.json()
        incident_req = IncidentRequest(**body_json)
    except Exception:
        # Fallback to Form Data (Frontend Canvas usage)
        form_data = await request.form()
        payload_str = form_data.get("payload") or form_data.get("title")
        if not payload_str:
            raise HTTPException(status_code=400, detail="Missing JSON body or 'payload' in form data.")
        try:
            parsed_payload = json.loads(payload_str)
            incident_req = IncidentRequest(**parsed_payload)
        except json.JSONDecodeError:
            # Maybe it's just a raw text title, create a generic request
            incident_req = IncidentRequest(other_findings={"title": payload_str})

    if not incident_req.phishing_result and not incident_req.malware_result and not incident_req.other_findings:
        raise HTTPException(
            status_code=400,
            detail="Must provide at least one finding (phishing_result, malware_result, or other_findings)."
        )
        
    try:
        final_report = await process_incident(incident_req)
        final_report["execution_time_seconds"] = round(time.time() - start_time, 2)
        return final_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incident Response analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # Standalone execution on port 8008
    uvicorn.run("src.incident_response_agent.main:app", host="0.0.0.0", port=8008, reload=True)
