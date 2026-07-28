import os
import logging
import shutil
from datetime import datetime
from typing import Dict, Any

from app.config import settings
from app.db.mongo import get_database, to_object_id

from app.agents.ingestion_agent import IngestionAgent
from app.agents.ocr_parsing_agent import OCRParsingAgent
from app.agents.visual_layout_agent import VisualLayoutAgent
from app.agents.metadata_forensics_agent import MetadataForensicsAgent
from app.agents.tampering_detection_agent import TamperingDetectionAgent
from app.agents.security_element_agent import SecurityElementAgent
from app.agents.authority_registry_agent import AuthorityRegistryAgent
from app.agents.ai_reasoning_agent import AIReasoningAgent
from app.agents.decision_synthesis_agent import DecisionSynthesisAgent

logger = logging.getLogger(__name__)

class MultiAgentOrchestrator:
    """
    Multi-Agent Orchestrator for Fake Certificate Verification.
    Coordinates 9 specialized autonomous agents to perform end-to-end verification.
    """
    def __init__(self):
        self.agent_1_ingestion = IngestionAgent()
        self.agent_2_ocr = OCRParsingAgent()
        self.agent_3_visual = VisualLayoutAgent()
        self.agent_4_metadata = MetadataForensicsAgent()
        self.agent_5_tampering = TamperingDetectionAgent()
        self.agent_6_security = SecurityElementAgent()
        self.agent_7_authority = AuthorityRegistryAgent()
        self.agent_8_ai_reasoning = AIReasoningAgent()
        self.agent_9_decision = DecisionSynthesisAgent()

    async def run_pipeline(self, verification_id: str, db=None) -> dict:
        if db is None:
            db = get_database()

        rec_obj_id = to_object_id(verification_id)
        verification_doc = await db.verification_records.find_one({"_id": rec_obj_id})
        if not verification_doc:
            raise ValueError(f"Verification record {verification_id} not found.")

        cert_doc = await db.certificates.find_one({"_id": to_object_id(verification_doc["certificate_id"])})
        if not cert_doc:
            raise ValueError(f"Certificate {verification_doc['certificate_id']} not found.")

        file_path = cert_doc["storage_path"]
        temp_dir = os.path.join(settings.UPLOAD_DIR, "temp", str(verification_id))
        os.makedirs(temp_dir, exist_ok=True)

        async def update_progress(stage_name: str, pct: int):
            await db.verification_records.update_one(
                {"_id": rec_obj_id},
                {"$set": {"current_stage": stage_name, "stage_progress_pct": pct}}
            )

        context: Dict[str, Any] = {
            "verification_id": str(verification_id),
            "rec_obj_id": rec_obj_id,
            "file_path": file_path,
            "temp_dir": temp_dir,
            "db": db,
            "stage_results": {}
        }

        # --- AGENT 1: Ingestion & Preprocessing ---
        await update_progress("Agent 1: File Validation & Preprocessing", 10)
        res1 = await self.agent_1_ingestion.process(context)
        context["stage_results"]["file_validation"] = res1["validation"]
        context["stage_results"]["preprocessing"] = res1["preprocessing"]
        context["preprocessed_path"] = res1["preprocessed_path"]

        # --- AGENT 2: OCR & Layout Parsing ---
        await update_progress("Agent 2: OCR & Text Extraction", 25)
        res2 = await self.agent_2_ocr.process(context)
        context["stage_results"]["ocr"] = res2["ocr"]
        context["stage_results"]["info_parsing"] = res2["info_parsing"]
        context["extracted_data"] = res2["extracted_data"]
        context["raw_text"] = res2["raw_text"]

        await db.verification_records.update_one(
            {"_id": rec_obj_id},
            {"$set": {"extracted_data": context["extracted_data"]}}
        )

        # --- AGENT 3: Visual & Layout Inspection ---
        await update_progress("Agent 3: Template & Visual Inspection", 42)
        res3 = await self.agent_3_visual.process(context)
        context["stage_results"]["template_matching"] = res3["template_matching"]
        context["stage_results"]["logo_verification"] = res3["logo_verification"]
        context["stage_results"]["seal_verification"] = res3["seal_verification"]

        # --- AGENT 4: Digital Forensics & Metadata ---
        await update_progress("Agent 4: Metadata Forensics", 55)
        res4 = await self.agent_4_metadata.process(context)
        context["stage_results"]["metadata_analysis"] = res4["metadata_analysis"]

        # --- AGENT 5: Image Tampering & Forgery Detection ---
        await update_progress("Agent 5: Image Tampering Detection", 68)
        res5 = await self.agent_5_tampering.process(context)
        context["stage_results"]["tampering_detection"] = res5["tampering_detection"]

        # --- AGENT 6: Security Element & Signature Verification ---
        await update_progress("Agent 6: Security & Signature Verification", 78)
        res6 = await self.agent_6_security.process(context)
        context["stage_results"]["qr_verification"] = res6["qr_verification"]
        context["stage_results"]["signature_verification"] = res6["signature_verification"]

        # --- AGENT 7: Authority & Registry Verification ---
        await update_progress("Agent 7: Authority & Registry Check", 85)
        res7 = await self.agent_7_authority.process(context)
        context["stage_results"]["certificate_number_verification"] = res7["certificate_number_verification"]
        context["stage_results"]["authority_verification"] = res7["authority_verification"]

        # Intermediary scoring for AI reasoning context
        from app.modules import scoring
        score_obj = scoring.calculate_authenticity_score(context["stage_results"])
        context["overall_score"] = score_obj["overall_score"]

        # --- AGENT 8: AI Reasoning & Forensic Anomaly Analysis ---
        await update_progress("Agent 8: AI Forensic Reasoning", 92)
        res8 = await self.agent_8_ai_reasoning.process(context)
        context["ai_reasoning"] = res8["ai_reasoning"]

        # --- AGENT 9: Decision Synthesis & Scoring ---
        await update_progress("Agent 9: Decision Synthesis & Report", 98)
        res9 = await self.agent_9_decision.process(context)

        # Final Database Persistence
        completion_time = datetime.utcnow()
        await db.verification_records.update_one(
            {"_id": rec_obj_id},
            {
                "$set": {
                    "status": "completed",
                    "current_stage": "Completed",
                    "stage_progress_pct": 100,
                    "stage_results": context["stage_results"],
                    "authenticity_score": res9["score_obj"],
                    "classification": res9["classification"],
                    "ai_reasoning": context["ai_reasoning"],
                    "recommendation": res9["recommendation"],
                    "report_pdf_path": res9["report_pdf_path"],
                    "completed_at": completion_time
                }
            }
        )

        # Cleanup temporary files
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

        return await db.verification_records.find_one({"_id": rec_obj_id})
