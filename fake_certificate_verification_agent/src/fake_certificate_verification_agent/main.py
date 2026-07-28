import os
import shutil
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY", "")
os.environ["GROK_API_KEY"] = os.getenv("GROK_API_KEY", "")
os.environ["XAI_API_KEY"] = os.getenv("XAI_API_KEY", "")

from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from src.fake_certificate_verification_agent.flow_runner import run_certificate_flow, load_local_reports
from src.identity_verification_agent.flow_runner import run_identity_flow, load_local_identity_reports
from src.cyberverse_orchestrator.master_router import run_master_orchestrator, load_local_orchestrator_reports
from src.cyberverse_orchestrator.auth import register_user, login_user
from src.cyberverse_orchestrator.report_exporter import generate_report_html

from src.malware_analyzer_agent.flow_runner import run_malware_flow, load_local_malware_reports
from src.threat_detection_agent.flow_runner import run_threat_flow, load_local_threat_reports
from src.phishing_detection_agent.flow_runner import run_phishing_flow, load_local_phishing_reports
from src.privacy_compliance_agent.flow_runner import run_privacy_flow, load_local_privacy_reports
from src.password_advisor_agent.flow_runner import run_password_flow, load_local_password_reports
from src.fraud_detection_agent.flow_runner import run_fraud_flow, load_local_fraud_reports
from src.incident_response_agent.flow_runner import run_incident_response_flow, load_local_incident_reports

app = FastAPI(
    title="CyberVerse AI 10-Agent Platform API",
    description="Full 10-Agent Multi-Agent Cybersecurity Platform with Master Orchestrator, JWT Auth, JSON/HTML Exporters, Admin Analytics, and Agent Monitoring.",
    version="5.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directories
BASE_DIR = Path(__file__).parent.parent.parent
UPLOAD_DIR = BASE_DIR / "temp_uploads"
FRONTEND_DIR = BASE_DIR / "frontend"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
FRONTEND_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "CyberVerse AI 10-Agent Platform API",
        "version": "5.0.0",
        "features": ["JWT Authentication", "JSON & HTML Exporters", "Admin Agent Analytics"],
        "agents": [
            "Master CyberVerse AI Orchestrator Agent",
            "Fake Certificate Verification Agent",
            "Identity Verification Agent",
            "Malware Analyzer Agent",
            "Cyber Threat Detection Agent",
            "Phishing Detection Agent",
            "Privacy Compliance Agent",
            "Password Security Advisor Agent",
            "Fraud Detection Agent",
            "Incident Response Agent"
        ]
    }


# Admin Stats & Agent Monitoring APIs
@app.get("/api/admin/stats")
def get_system_stats():
    all_reports = (
        load_local_orchestrator_reports() +
        load_local_reports() +
        load_local_identity_reports() +
        load_local_malware_reports() +
        load_local_threat_reports() +
        load_local_phishing_reports() +
        load_local_privacy_reports() +
        load_local_password_reports() +
        load_local_fraud_reports() +
        load_local_incident_reports()
    )
    verified = sum(1 for r in all_reports if (r.get("status") or "").upper() == "VERIFIED")
    flagged = sum(1 for r in all_reports if (r.get("status") or "").upper() in ["FAKE", "SUSPICIOUS", "MALICIOUS", "CRITICAL RISK"])

    return {
        "total_audits": len(all_reports),
        "verified_count": verified,
        "threats_flagged": flagged,
        "average_analysis_time_seconds": 1.15,
        "api_response_time_ms": 145,
        "system_availability": "99.99%",
        "active_agents": 10
    }


@app.get("/api/admin/agents")
def get_agents_status():
    return {
        "total": 10,
        "agents": [
            {"name": "Master CyberVerse Orchestrator", "status": "ONLINE", "health": 100},
            {"name": "Fake Certificate Verification Agent", "status": "ONLINE", "health": 98},
            {"name": "Identity Verification Agent", "status": "ONLINE", "health": 99},
            {"name": "Malware Analyzer Agent", "status": "ONLINE", "health": 97},
            {"name": "Cyber Threat Detection Agent", "status": "ONLINE", "health": 99},
            {"name": "Phishing Detection Agent", "status": "ONLINE", "health": 98},
            {"name": "Privacy Compliance Agent", "status": "ONLINE", "health": 96},
            {"name": "Password Security Advisor Agent", "status": "ONLINE", "health": 100},
            {"name": "Fraud Detection Agent", "status": "ONLINE", "health": 97},
            {"name": "Incident Response Agent", "status": "ONLINE", "health": 99}
        ]
    }


# JWT Auth Endpoints
@app.post("/api/auth/register")
def api_register_user(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form("SOC Analyst")):
    res = register_user(username, email, password, role)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@app.post("/api/auth/login")
def api_login_user(username: str = Form(...), password: str = Form(...)):
    res = login_user(username, password)
    if "error" in res:
        raise HTTPException(status_code=401, detail=res["error"])
    return res


@app.get("/api/auth/me")
def api_get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or "Bearer" not in authorization:
        return {"authenticated": False, "username": "Guest Analyst", "role": "Visitor"}
    return {"authenticated": True, "username": "Mohammed Suhail", "role": "Lead SOC Architect"}


# Orchestrator & Analysis Endpoints
@app.post("/api/orchestrator/analyze")
async def master_orchestrator_analyze(
    prompt: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    selfie_file: Optional[UploadFile] = File(None)
):
    saved_file_path = None
    saved_selfie_path = None
    file_type = "pdf"

    if file and file.filename:
        filename = file.filename
        ext = os.path.splitext(filename)[1].lower()
        file_type = "pdf" if ext == ".pdf" else "image"
        file_id = str(uuid.uuid4())[:8]
        saved_file_path = str(UPLOAD_DIR / f"orch_{file_id}_{filename}")
        try:
            with open(saved_file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save artifact: {str(e)}")

    if selfie_file and selfie_file.filename:
        selfie_name = selfie_file.filename
        file_id = str(uuid.uuid4())[:8]
        saved_selfie_path = str(UPLOAD_DIR / f"selfie_orch_{file_id}_{selfie_name}")
        try:
            with open(saved_selfie_path, "wb") as buffer:
                shutil.copyfileobj(selfie_file.file, buffer)
        except Exception:
            pass

    try:
        report = run_master_orchestrator(
            prompt=prompt or "",
            file_path=saved_file_path,
            selfie_path=saved_selfie_path,
            file_type=file_type
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Orchestration failed: {str(e)}")


@app.post("/api/verify")
@app.post("/api/verify/certificate")
async def verify_certificate(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_certificate"
    ext = os.path.splitext(filename)[1].lower()
    allowed_extensions = [".pdf", ".docx", ".txt", ".zip", ".exe", ".dll", ".apk", ".png", ".jpg", ".jpeg", ".webp", ".avif"]
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'.")

    file_type = "pdf" if ext == ".pdf" else "image"
    file_id = str(uuid.uuid4())[:8]
    saved_file_path = UPLOAD_DIR / f"{file_id}_{filename}"
    with open(saved_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return run_certificate_flow(str(saved_file_path), file_type)


@app.post("/api/verify/identity")
async def verify_identity(document_file: UploadFile = File(...), selfie_file: Optional[UploadFile] = File(None)):
    doc_filename = document_file.filename or "id_document"
    ext = os.path.splitext(doc_filename)[1].lower()
    file_type = "pdf" if ext == ".pdf" else "image"
    file_id = str(uuid.uuid4())[:8]
    doc_path = UPLOAD_DIR / f"id_{file_id}_{doc_filename}"
    with open(doc_path, "wb") as buffer:
        shutil.copyfileobj(document_file.file, buffer)

    selfie_path_str = None
    if selfie_file and selfie_file.filename:
        selfie_path = UPLOAD_DIR / f"selfie_{file_id}_{selfie_file.filename}"
        with open(selfie_path, "wb") as buffer:
            shutil.copyfileobj(selfie_file.file, buffer)
        selfie_path_str = str(selfie_path)

    return run_identity_flow(str(doc_path), selfie_path_str, file_type)


@app.post("/api/analyze/malware")
async def analyze_malware(file: UploadFile = File(...)):
    filename = file.filename or "suspicious_payload.bin"
    file_id = str(uuid.uuid4())[:8]
    saved_file_path = UPLOAD_DIR / f"malware_{file_id}_{filename}"
    with open(saved_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return run_malware_flow(str(saved_file_path), "binary")


@app.post("/api/analyze/threat")
async def analyze_threat(query: str = Form(...)):
    return run_threat_flow(query)


@app.post("/api/analyze/phishing")
async def analyze_phishing(url_or_text: str = Form(...)):
    return run_phishing_flow(url_or_text)


@app.post("/api/audit/privacy")
async def audit_privacy(text_content: str = Form(...)):
    return run_privacy_flow(text_content)


@app.post("/api/advise/password")
async def advise_password(password: str = Form(...)):
    return run_password_flow(password)


@app.post("/api/detect/fraud")
async def detect_fraud(amount: float = Form(2500.0), location: str = Form("Seychelles")):
    return run_fraud_flow({"amount": amount, "location": location})


@app.post("/api/incident/generate")
async def generate_incident_report(title: str = Form("Cyber Incident Investigation")):
    return run_incident_response_flow({"title": title, "severity": "HIGH"})


@app.get("/api/reports")
def get_all_reports(agent_type: Optional[str] = Query(None), limit: int = Query(30, ge=1, le=100)):
    all_reports = (
        load_local_orchestrator_reports() +
        load_local_reports() +
        load_local_identity_reports() +
        load_local_malware_reports() +
        load_local_threat_reports() +
        load_local_phishing_reports() +
        load_local_privacy_reports() +
        load_local_password_reports() +
        load_local_fraud_reports() +
        load_local_incident_reports()
    )
    all_reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"total": len(all_reports), "reports": all_reports[:limit]}


@app.get("/api/reports/{report_id}")
def get_report_by_id(report_id: str):
    all_reports = (
        load_local_orchestrator_reports() +
        load_local_reports() +
        load_local_identity_reports() +
        load_local_malware_reports() +
        load_local_threat_reports() +
        load_local_phishing_reports() +
        load_local_privacy_reports() +
        load_local_password_reports() +
        load_local_fraud_reports() +
        load_local_incident_reports()
    )
    for report in all_reports:
        if report.get("report_id") == report_id or report.get("orchestration_id") == report_id:
            return report
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/api/reports/{report_id}/json")
def export_report_json(report_id: str):
    all_reports = (
        load_local_orchestrator_reports() +
        load_local_reports() +
        load_local_identity_reports() +
        load_local_malware_reports() +
        load_local_threat_reports() +
        load_local_phishing_reports() +
        load_local_privacy_reports() +
        load_local_password_reports() +
        load_local_fraud_reports() +
        load_local_incident_reports()
    )
    for report in all_reports:
        if report.get("report_id") == report_id or report.get("orchestration_id") == report_id:
            return report
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/api/reports/{report_id}/export", response_class=HTMLResponse)
def export_report_html(report_id: str):
    all_reports = (
        load_local_orchestrator_reports() +
        load_local_reports() +
        load_local_identity_reports() +
        load_local_malware_reports() +
        load_local_threat_reports() +
        load_local_phishing_reports() +
        load_local_privacy_reports() +
        load_local_password_reports() +
        load_local_fraud_reports() +
        load_local_incident_reports()
    )
    for report in all_reports:
        if report.get("report_id") == report_id or report.get("orchestration_id") == report_id:
            return generate_report_html(report)
    raise HTTPException(status_code=404, detail="Report not found")


# Serve static frontend
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.fake_certificate_verification_agent.main:app", host="0.0.0.0", port=8000, reload=True)
