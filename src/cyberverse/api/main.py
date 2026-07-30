"""
main.py — CyberVerse FastAPI Application
=========================================
Enterprise REST API for the CyberVerse security platform.

Endpoints
---------
POST   /api/v1/auth/token           — Get JWT access token
POST   /api/v1/analyze              — Trigger a security analysis
GET    /api/v1/reports              — List all reports (paginated)
GET    /api/v1/reports/{report_id}  — Get a specific report
DELETE /api/v1/reports/{report_id}  — Delete a report
GET    /api/v1/specialists          — List available specialists
GET    /api/v1/health               — Health check
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from cyberverse.api.auth import User, auth_router, get_current_user
from cyberverse.api.report_store import (
    delete_report,
    get_report,
    list_reports,
    report_count,
    save_report,
)
from cyberverse.orchestrator.models import (
    AVAILABLE_SPECIALISTS,
    OrchestratorReport,
    SecurityAnalysisRequest,
)
from cyberverse.orchestrator.security_flow import run_security_analysis
from cyberverse.orchestrator.specialist_registry import DISPLAY_NAMES

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberVerse Security Platform API",
    description=(
        "Enterprise multi-agent cybersecurity platform. "
        "Orchestrates 9 specialist AI agents for comprehensive security analysis."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow the React dev server and any production origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server
        "http://localhost:3000",   # CRA fallback
        "http://localhost:8080",
        "*",                       # TODO: lock down in production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include auth router
app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    specialists: List[str] = []
    inputs: Dict[str, Any] = {}
    label: Optional[str] = None
    async_mode: bool = False


class AnalyzeResponse(BaseModel):
    report_id: str
    status: str
    message: str


class SpecialistInfo(BaseModel):
    key: str
    display_name: str
    available: bool = True


class HealthResponse(BaseModel):
    status: str
    version: str
    specialists_available: int
    reports_stored: int
    timestamp: str


# ---------------------------------------------------------------------------
# Background task wrapper
# ---------------------------------------------------------------------------

def _background_analyze(request: SecurityAnalysisRequest, report_id: str) -> None:
    """Run analysis in background and save the completed report."""
    try:
        report = run_security_analysis(request)
        report.report_id = report_id
        save_report(report)
        logger.info("Background analysis complete for report %s", report_id)
    except Exception as exc:
        logger.exception("Background analysis failed for report %s: %s", report_id, exc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Platform health check."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        specialists_available=len(AVAILABLE_SPECIALISTS),
        reports_stored=report_count(),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


@app.get("/api/v1/specialists", response_model=List[SpecialistInfo], tags=["System"])
async def get_specialists(current_user: User = Depends(get_current_user)):
    """List all available cybersecurity specialists."""
    return [
        SpecialistInfo(
            key=key,
            display_name=DISPLAY_NAMES.get(key, key.replace("_", " ").title()),
        )
        for key in AVAILABLE_SPECIALISTS
    ]


@app.post(
    "/api/v1/analyze",
    response_model=OrchestratorReport,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
)
async def analyze(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """
    Trigger a full or partial security analysis.

    - Pass `specialists=[]` to run all 9 specialists.
    - Pass `async_mode=true` to run in background and poll `/reports/{id}`.
    - Synchronous mode (default) blocks until all specialists complete.
    """
    import uuid
    report_id = str(uuid.uuid4())

    security_request = SecurityAnalysisRequest(
        specialists=req.specialists,
        inputs=req.inputs,
        label=req.label,
    )

    if req.async_mode:
        background_tasks.add_task(_background_analyze, security_request, report_id)
        # Return a stub report immediately
        from cyberverse.orchestrator.models import PlatformRisk
        stub = OrchestratorReport(
            report_id=report_id,
            label=req.label,
            status="running",
            request_inputs=req.inputs,
            platform_risk=PlatformRisk(
                overall_score=0,
                overall_risk="UNKNOWN",
                confidence=0,
                specialists_run=0,
                specialists_succeeded=0,
            ),
            executive_summary="Analysis in progress…",
        )
        save_report(stub)
        return stub

    # Synchronous execution
    try:
        report = run_security_analysis(security_request)
        report.report_id = report_id
        save_report(report)
        return report
    except Exception as exc:
        logger.exception("Analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {exc}",
        )


@app.get(
    "/api/v1/reports",
    tags=["Reports"],
)
async def get_reports(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
):
    """List all security analysis reports (paginated, newest first)."""
    summaries = list_reports(limit=limit, offset=offset)
    return {
        "total": report_count(),
        "limit": limit,
        "offset": offset,
        "reports": [s.model_dump() for s in summaries],
    }


@app.get(
    "/api/v1/reports/{report_id}",
    response_model=OrchestratorReport,
    tags=["Reports"],
)
async def get_report_by_id(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Retrieve a specific security analysis report."""
    report = get_report(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found.",
        )
    return report


@app.delete(
    "/api/v1/reports/{report_id}",
    tags=["Reports"],
)
async def delete_report_by_id(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a report by ID."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete reports.",
        )
    deleted = delete_report(report_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found.",
        )
    return {"deleted": True, "report_id": report_id}


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("cyberverse.api.main:app", host="0.0.0.0", port=8000, reload=True)
