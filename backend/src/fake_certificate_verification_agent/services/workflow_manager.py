import os
import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from src.fake_certificate_verification_agent.models.workflow_context import WorkflowContext, WorkflowStatus
from src.fake_certificate_verification_agent.services.agent_registry import AgentRegistry
from src.fake_certificate_verification_agent.services.drive_service import download_drive_folder
from src.fake_certificate_verification_agent.services.discovery_service import discover_and_classify_documents
from src.fake_certificate_verification_agent.services.report_generator import build_final_verification_report
from src.fake_certificate_verification_agent.services.mongo_service import save_workflow_run_to_mongo

from src.identity_verification_agent.flow_runner import IdentityVerificationSpecialist
from src.fake_certificate_verification_agent.flow_runner import DocumentVerificationSpecialist
from src.fraud_detection_agent.flow_runner import FraudDetectionSpecialist

logger = logging.getLogger(__name__)

# Global state store for live status polling
ACTIVE_WORKFLOWS: Dict[str, WorkflowContext] = {}

# Instantiate Agent Registry
registry = AgentRegistry()
registry.register(IdentityVerificationSpecialist())
registry.register(DocumentVerificationSpecialist())
registry.register(FraudDetectionSpecialist())


def create_workflow_job(drive_url: str, notify_email: Optional[str] = None) -> WorkflowContext:
    date_str = time.strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:4].upper()
    workflow_id = f"wf_{date_str}_{short_uuid}"

    context = WorkflowContext(workflow_id=workflow_id, drive_url=drive_url, notify_email=notify_email)
    ACTIVE_WORKFLOWS[workflow_id] = context
    return context


def get_workflow_context(workflow_id: str) -> Optional[WorkflowContext]:
    return ACTIVE_WORKFLOWS.get(workflow_id)


def run_full_verification_pipeline(context: WorkflowContext) -> WorkflowContext:
    """Synchronous core pipeline execution running Discovery -> Parallel Agents -> Fraud -> MongoDB."""
    try:
        context.update_status(WorkflowStatus.INITIALIZING, "Initializing System & Credentials", 10)
        time.sleep(0.3)

        context.update_status(WorkflowStatus.DOWNLOADING, "Downloading Google Drive Folder Contents", 25)
        files, err_code = download_drive_folder(context.drive_url)
        if err_code:
            context.add_error(err_code, f"Drive download warning: {err_code}")

        context.downloaded_files = files

        context.update_status(WorkflowStatus.DISCOVERING, "Analyzing Document Types & Generating Previews", 40)
        discovered = discover_and_classify_documents(files)
        context.discovered_documents = discovered

        context.update_status(WorkflowStatus.VERIFYING, "Executing Parallel Identity & Document Verification Agents", 60)

        identity_agent = registry.get("identity")
        document_agent = registry.get("document")

        # Execute Identity and Document verification agents in PARALLEL
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_id = executor.submit(identity_agent.execute, context) if identity_agent else None
            future_doc = executor.submit(document_agent.execute, context) if document_agent else None

            if future_id:
                context.identity_result = future_id.result()
            if future_doc:
                context.document_result = future_doc.result()

        context.update_status(WorkflowStatus.ANALYZING, "Fraud Detection Specialist Cross-Document Reasoning", 75)
        fraud_agent = registry.get("fraud")
        if fraud_agent:
            context.fraud_result = fraud_agent.execute(context)

        context.update_status(WorkflowStatus.GENERATING_REPORT, "Compiling Enterprise Verification Report", 90)
        final_report = build_final_verification_report(context)
        context.report = final_report

        # Automatically dispatch email notification (Verified or Fake) after Final Security Report is generated
        summary_info = final_report.get("summary", {})
        decision = summary_info.get("decision", "Approved")
        status_val = summary_info.get("status", "Verified")
        trust_score = summary_info.get("trust_score", 100)

        recipient = getattr(context, "notify_email", None) or os.getenv("EMAIL_USER", "kavin88701@gmail.com")

        if decision == "Rejected" or status_val in ["Fake", "Suspicious"] or trust_score < 65:
            try:
                from src.utils.email_service import send_report_email
                email_payload = {
                    "report_id": context.workflow_id,
                    "status": f"Fake / {decision}",
                    "risk_level": summary_info.get("risk", "CRITICAL RISK"),
                    "confidence": f"{trust_score}% Trust Score",
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "summary": f"ALERT: Google Drive Folder ({context.drive_url}) was FLAGGED AS FAKE / FORGED during multi-agent evaluation. Status: {status_val}. Trust Score: {trust_score}%.",
                    "recommendation": "Reject certificate and documents immediately. Conduct manual registrar compliance review."
                }
                email_res = send_report_email(recipient_email=recipient, report=email_payload, agent_name="CyberVerse Document Forensics")
                context.report["email_delivery"] = email_res
                logger.info(f"Fake alert email sent to {recipient}: {email_res}")
            except Exception as mail_err:
                logger.error(f"Failed to send fake alert email: {mail_err}")

        else:
            # All 3 agents passed — drive link is SUCCESS → send verified success email to recipient
            try:
                from src.utils.email_service import send_success_email
                recipient = getattr(context, "notify_email", None) or os.getenv("EMAIL_USER", "kavin88701@gmail.com")

                # Build agent summary string from agent results
                agents_run_parts = []
                if context.identity_result:
                    agents_run_parts.append(f"Identity Verification ({context.identity_result.status})")
                if context.document_result:
                    agents_run_parts.append(f"Document Verification ({context.document_result.status})")
                if context.fraud_result:
                    agents_run_parts.append(f"Fraud Detection ({context.fraud_result.status})")
                agents_run_str = " · ".join(agents_run_parts) if agents_run_parts else "Identity · Document · Fraud Detection"

                success_payload = {
                    "report_id": context.workflow_id,
                    "status": "Verified",
                    "confidence": f"{trust_score}% Trust Score",
                    "drive_url": context.drive_url,
                    "agents_run": agents_run_str,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "summary": summary_info.get(
                        "summary",
                        f"All agents have verified the documents from the Google Drive submission. "
                        f"Trust Score: {trust_score}%. Decision: {decision}."
                    ),
                    "recommendation": "Documents are authentic. Safe to proceed with onboarding or approval.",
                }
                email_res = send_success_email(
                    recipient_email=recipient,
                    report=success_payload,
                    agent_name="CyberVerse Document Forensics"
                )
                context.report["email_delivery"] = email_res
                logger.info(f"Success verification email sent to {recipient}: {email_res}")
            except Exception as mail_err:
                logger.error(f"Failed to send success verification email: {mail_err}")

        context.update_status(WorkflowStatus.SAVING, "Persisting Results to MongoDB Compass", 95)
        save_workflow_run_to_mongo(context.to_dict())

        context.end_time = time.time()
        context.update_status(WorkflowStatus.COMPLETED, "Verification Workflow Completed Successfully", 100)

    except Exception as e:
        logger.error(f"Error during workflow execution '{context.workflow_id}': {e}", exc_info=True)
        context.add_error("SYS001", str(e))
        context.update_status(WorkflowStatus.FAILED, f"Execution Failed: {str(e)}", 100)

    return context
