import os
import time
from enum import Enum
from typing import List, Dict, Any, Optional


class WorkflowStatus(str, Enum):
    PENDING = "PENDING"
    INITIALIZING = "INITIALIZING"
    DOWNLOADING = "DOWNLOADING"
    DISCOVERING = "DISCOVERING"
    VERIFYING = "VERIFYING"
    ANALYZING = "ANALYZING"
    GENERATING_REPORT = "GENERATING_REPORT"
    SAVING = "SAVING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AgentResult:
    """Standardized result envelope returned by all AI agents."""

    def __init__(
        self,
        agent_id: str,
        status: str = "Completed",
        confidence: float = 0.0,
        processing_time_ms: int = 0,
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        output: Optional[Dict[str, Any]] = None,
    ):
        self.agent_id = agent_id
        self.status = status
        self.confidence = confidence
        self.processing_time_ms = processing_time_ms
        self.warnings = warnings or []
        self.errors = errors or []
        self.output = output or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "confidence": round(self.confidence, 1),
            "processing_time_ms": self.processing_time_ms,
            "warnings": self.warnings,
            "errors": self.errors,
            "output": self.output,
        }


class WorkflowContext:
    """Shared state object passed between workflow steps and agents."""

    def __init__(self, workflow_id: str, drive_url: str, notify_email: Optional[str] = None):
        self.workflow_id = workflow_id
        self.drive_url = drive_url
        self.notify_email = notify_email
        self.downloaded_files: List[Dict[str, Any]] = []
        self.discovered_documents: List[Dict[str, Any]] = []

        self.identity_result: Optional[AgentResult] = None
        self.document_result: Optional[AgentResult] = None
        self.certificate_result: Optional[AgentResult] = None
        self.fraud_result: Optional[AgentResult] = None

        self.report: Dict[str, Any] = {}
        self.status: WorkflowStatus = WorkflowStatus.PENDING
        self.current_step: str = "Initialized"
        self.progress: int = 0

        self.errors: List[Dict[str, Any]] = []
        self.start_time: float = time.time()
        self.end_time: Optional[float] = None

    def update_status(self, status: WorkflowStatus, step_name: str, progress: int):
        self.status = status
        self.current_step = step_name
        self.progress = progress

    def add_error(self, code: str, message: str, step: str = ""):
        self.errors.append({
            "code": code,
            "message": message,
            "step": step or self.current_step,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    def to_status_dict(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.start_time, 2)
        return {
            "workflow_id": self.workflow_id,
            "drive_url": self.drive_url,
            "status": self.status.value,
            "current_step": self.current_step,
            "progress": self.progress,
            "elapsed_seconds": elapsed,
            "errors": self.errors,
            "documents_count": len(self.downloaded_files),
        }

    def to_dict(self) -> Dict[str, Any]:
        elapsed = round((self.end_time or time.time()) - self.start_time, 2)
        return {
            "workflow_id": self.workflow_id,
            "drive_url": self.drive_url,
            "status": self.status.value,
            "current_step": self.current_step,
            "progress": self.progress,
            "elapsed_seconds": elapsed,
            "uploaded_documents": [
                {
                    "name": f.get("filename", os.path.basename(f.get("file_path", ""))),
                    "category": f.get("category", "General"),
                    "file_type": f.get("file_type", "unknown"),
                    "preview": f.get("preview", "")[:200],
                }
                for f in self.discovered_documents or self.downloaded_files
            ],
            "agents": {
                "identity": self.identity_result.to_dict() if self.identity_result else None,
                "document": self.document_result.to_dict() if self.document_result else None,
                "certificate": self.certificate_result.to_dict() if self.certificate_result else None,
                "fraud": self.fraud_result.to_dict() if self.fraud_result else None,
            },
            "report": self.report,
            "errors": self.errors,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time)),
        }
