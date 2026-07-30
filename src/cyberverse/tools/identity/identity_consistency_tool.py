import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class IdentityConsistencyToolInput(BaseModel):
    """Input schema for IdentityConsistencyTool."""
    document_json: Optional[str] = Field(None, description="Raw JSON string or dict output from DocumentVerificationTool.")
    face_json: Optional[str] = Field(None, description="Raw JSON string or dict output from FaceVerificationTool.")
    liveness_json: Optional[str] = Field(None, description="Raw JSON string or dict output from LivenessDetectionTool.")
    combined_json: Optional[str] = Field(None, description="Combined JSON containing document, face, and liveness outputs.")


class IdentityConsistencyTool(BaseTool):
    name: str = "Identity Consistency Tool"
    description: str = (
        "Cross-verifies consistency across Document Verification, Face Matching, and Liveness Detection. "
        "Validates field completeness, facial match decision, liveness classification, and document expiry "
        "to output a 0-100 Consistency Score and verification decision (VERIFIED, PARTIALLY_VERIFIED, FAILED)."
    )
    args_schema: Type[BaseModel] = IdentityConsistencyToolInput

    def _run(
        self,
        document_json: Optional[str] = None,
        face_json: Optional[str] = None,
        liveness_json: Optional[str] = None,
        combined_json: Optional[str] = None
    ) -> str:
        """Execute cross-tool identity consistency audit."""
        try:
            # 1. Parse JSON inputs into structured dictionaries
            doc_data, face_data, live_data = self._parse_inputs(
                document_json, face_json, liveness_json, combined_json
            )

            findings: List[str] = []
            warnings: List[str] = []
            score = 0
            active_checks = 0

            # --- A. Document Authenticity & Field Verification ---
            if doc_data.get("success"):
                active_checks += 1
                doc_score = doc_data.get("authenticity_score", 0)
                fields = doc_data.get("fields", {})
                
                if doc_score >= 80:
                    score += 35
                    findings.append(f"Identity document ({doc_data.get('document_type')}) verified with high authenticity score ({doc_score}/100).")
                elif doc_score >= 50:
                    score += 20
                    findings.append(f"Identity document ({doc_data.get('document_type')}) verified with moderate authenticity ({doc_score}/100).")

                if fields.get("document_number"):
                    findings.append(f"Valid document number format verified ({fields.get('document_number')}).")
                if fields.get("dob"):
                    findings.append(f"Date of birth verified ({fields.get('dob')}).")

                doc_warnings = doc_data.get("warnings", [])
                for w in doc_warnings:
                    warnings.append(f"Document Warning: {w}")

            # --- B. Facial Biometric Match Verification ---
            if face_data.get("success"):
                active_checks += 1
                face_decision = face_data.get("decision", "NO_MATCH")
                sim = face_data.get("similarity", 0.0)

                if face_decision == "MATCH":
                    score += 35
                    findings.append(f"Face verification passed with {sim}% similarity match.")
                elif face_decision == "PARTIAL_MATCH":
                    score += 20
                    findings.append(f"Face verification resulted in partial match ({sim}% similarity).")
                else:
                    score += 0
                    warnings.append(f"Face verification failed (similarity {sim}% < match threshold).")

                for w in face_data.get("warnings", []):
                    warnings.append(f"Face Match Warning: {w}")

            # --- C. Liveness Biometric Verification ---
            if live_data.get("success"):
                active_checks += 1
                live_cls = live_data.get("classification", "UNKNOWN")
                live_score = live_data.get("liveness_score", 0)

                if live_cls == "REAL":
                    score += 30
                    findings.append(f"Liveness detection confirmed REAL biometric sample ({live_score}/100 score).")
                elif live_cls == "UNKNOWN":
                    score += 15
                    warnings.append("Liveness detection was inconclusive (UNKNOWN).")
                else:
                    score += 0
                    warnings.append(f"Liveness detection flagged SPOOF presentation attack (liveness score {live_score}).")

                for w in live_data.get("warnings", []):
                    warnings.append(f"Liveness Warning: {w}")

            # 2. Compute Final Consistency Score & Verification Decision
            final_score = min(100, score)

            if final_score >= 80 and not any("SPOOF" in w or "NO_MATCH" in w for w in warnings):
                decision = "VERIFIED"
            elif final_score >= 50:
                decision = "PARTIALLY_VERIFIED"
            else:
                decision = "FAILED"

            return json.dumps({
                "success": True,
                "decision": decision,
                "consistency_score": final_score,
                "findings": findings,
                "warnings": list(dict.fromkeys(warnings)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing IdentityConsistencyTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "decision": "FAILED",
                "consistency_score": 0,
                "findings": [],
                "warnings": warnings,
                "error": f"Identity consistency audit failed: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        doc_json: Optional[str],
        face_json: Optional[str],
        live_json: Optional[str],
        combined_json: Optional[str]
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Parse JSON inputs into structured dictionaries."""
        doc_data: Dict[str, Any] = {}
        face_data: Dict[str, Any] = {}
        live_data: Dict[str, Any] = {}

        if combined_json:
            try:
                cdata = json.loads(combined_json) if isinstance(combined_json, str) else combined_json
                doc_data = cdata.get("document_verification", {}) or cdata.get("document", {})
                face_data = cdata.get("face_verification", {}) or cdata.get("face", {})
                live_data = cdata.get("liveness_detection", {}) or cdata.get("liveness", {})
            except Exception:
                pass

        if doc_json:
            try:
                doc_data = json.loads(doc_json) if isinstance(doc_json, str) else doc_json
            except Exception:
                pass

        if face_json:
            try:
                face_data = json.loads(face_json) if isinstance(face_json, str) else face_json
            except Exception:
                pass

        if live_json:
            try:
                live_data = json.loads(live_json) if isinstance(live_json, str) else live_json
            except Exception:
                pass

        return doc_data, face_data, live_data
