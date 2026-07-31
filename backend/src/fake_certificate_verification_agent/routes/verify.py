import os
import threading
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from src.fake_certificate_verification_agent.services.workflow_manager import (
    create_workflow_job,
    get_workflow_context,
    run_full_verification_pipeline,
)
from src.fake_certificate_verification_agent.services.mongo_service import get_workflow_history_from_mongo

router = APIRouter(prefix="/api", tags=["Document Trust Verification"])


class GDriveVerifyRequest(BaseModel):
    drive_url: str = Field(..., description="Google Drive folder or file URL")
    notify_email: Optional[str] = Field(default=None, description="Optional custom notification email address")
    run_async: bool = Field(default=False, description="Set true for background async execution")


WORKFLOW_METADATA_STORE = [
    {
        "workflow_id": "template-document-trust",
        "name": "AI Document Trust & Verification Workflow",
        "display_name": "AI Document Trust & Verification Workflow",
        "version": "1.0.0",
        "author": "CyberVerse AI",
        "description": "Enterprise 3-agent Google Drive document trust and verification workflow template.",
        "category": "Verification",
        "icon": "shield",
        "color": "indigo",
        "estimated_runtime": "3.5 sec",
        "required_integrations": ["Google Drive Service Account", "MongoDB Compass", "Groq LLM"],
        "agents": [
            {
                "agent_id": "identity",
                "name": "Identity Verification Specialist",
                "description": "Verifies government IDs, passports, driver licenses & performs biometric face match.",
                "llm": "Groq",
                "capabilities": ["OCR", "Face Match", "Tamper Detection"],
            },
            {
                "agent_id": "document",
                "name": "Document Verification Specialist",
                "description": "Verifies educational degrees, resumes, offer letters, GST, and trade certificates.",
                "llm": "Groq",
                "capabilities": ["OCR", "Metadata Audit", "QR & Signature Check"],
            },
            {
                "agent_id": "fraud",
                "name": "Fraud Detection Specialist",
                "description": "Cross-compares all outputs for information mismatches, edited PDFs, and assigns Trust & Fraud scores.",
                "llm": "Groq",
                "capabilities": ["Cross-Document AI Reasoning", "Fraud Scoring", "Anomaly Detection"],
            },
        ],
    }
]


from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from src.fake_certificate_verification_agent.services.drive_service import extract_drive_id

@router.post("/verify/gdrive")
@router.post("/verify/gdrive/")
@router.get("/verify/gdrive")
@router.get("/verify/gdrive/")
@router.api_route("/verify/gdrive", methods=["GET", "POST", "OPTIONS"])
@router.api_route("/verify/gdrive/", methods=["GET", "POST", "OPTIONS"])
def start_gdrive_verification(
    payload: Optional[GDriveVerifyRequest] = None,
    drive_url: Optional[str] = None,
    notify_email: Optional[str] = None,
    background_tasks: BackgroundTasks = None
):
    target_url = (payload.drive_url if payload and payload.drive_url else drive_url) or ""
    target_url = target_url.strip()

    notify_target = (payload.notify_email if payload and payload.notify_email else notify_email) or None

    drive_id, drive_type = extract_drive_id(target_url)
    if not drive_id or drive_type == "invalid":
        raise HTTPException(status_code=400, detail={"code": "GD001", "message": "Invalid Google Drive URL format or link"})

    context = create_workflow_job(target_url, notify_email=notify_target)

    run_async = (payload.run_async if payload else False)

    if run_async:
        if background_tasks:
            background_tasks.add_task(run_full_verification_pipeline, context)
        return {
            "workflow_id": context.workflow_id,
            "status": context.status.value,
            "message": "Verification workflow started in background.",
        }
    else:
        # Run synchronously in threadpool worker thread to avoid asyncio event loop collisions
        completed_context = run_full_verification_pipeline(context)
        return completed_context.to_dict()


@router.options("/verify/gdrive")
@router.options("/verify/gdrive/")
def options_gdrive_verification():
    return {}


@router.get("/verify/gdrive/status/{workflow_id}")
def get_verification_status(workflow_id: str):
    context = get_workflow_context(workflow_id)
    if not context:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")

    return context.to_status_dict()


@router.get("/verify/gdrive/report/{workflow_id}")
def get_verification_report(workflow_id: str):
    context = get_workflow_context(workflow_id)
    if not context:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")

    return context.to_dict()


@router.get("/verify/gdrive/history")
def get_verification_history(limit: int = 50):
    history = get_workflow_history_from_mongo(limit=limit)
    return {"count": len(history), "history": history}


@router.get("/workflows")
def list_workflows():
    return {"workflows": WORKFLOW_METADATA_STORE}


@router.get("/workflows/{workflow_id}")
def get_workflow_metadata(workflow_id: str):
    for wf in WORKFLOW_METADATA_STORE:
        if wf["workflow_id"] == workflow_id:
            return wf
    raise HTTPException(status_code=404, detail=f"Workflow template '{workflow_id}' not found")
