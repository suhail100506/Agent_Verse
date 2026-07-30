import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class IdentityRiskToolInput(BaseModel):
    """Input schema for IdentityRiskTool."""
    document_json: Optional[str] = Field(None, description="Raw JSON string or dict output from DocumentVerificationTool.")
    face_json: Optional[str] = Field(None, description="Raw JSON string or dict output from FaceVerificationTool.")
    liveness_json: Optional[str] = Field(None, description="Raw JSON string or dict output from LivenessDetectionTool.")
    consistency_json: Optional[str] = Field(None, description="Raw JSON string or dict output from IdentityConsistencyTool.")
    combined_json: Optional[str] = Field(None, description="Combined JSON containing document, face, liveness, and consistency outputs.")


class IdentityRiskTool(BaseTool):
    name: str = "Identity Risk Tool"
    description: str = (
        "Synthesizes document authenticity, facial similarity, liveness detection, and cross-consistency checks "
        "into an enterprise Identity Risk Assessment with verification status (VERIFIED, NEEDS_REVIEW, REJECTED), overall risk rating, "
        "identity score (0-100), confidence percentage, telemetry dashboard, forensic evidence, recommendations, and executive summary."
    )
    args_schema: Type[BaseModel] = IdentityRiskToolInput

    def _run(
        self,
        document_json: Optional[str] = None,
        face_json: Optional[str] = None,
        liveness_json: Optional[str] = None,
        consistency_json: Optional[str] = None,
        combined_json: Optional[str] = None
    ) -> str:
        """Execute enterprise identity risk evaluation."""
        try:
            # 1. Parse JSON inputs into structured dictionaries
            doc_data, face_data, live_data, cons_data = self._parse_inputs(
                document_json, face_json, liveness_json, consistency_json, combined_json
            )

            evidence: List[str] = []
            risk_points = 0
            active_tools_count = 0

            doc_score = doc_data.get("authenticity_score", 0)
            face_sim = face_data.get("similarity", 0.0)
            liveness_cls = live_data.get("classification", "UNKNOWN")
            cons_score = cons_data.get("consistency_score", 0)

            # --- A. Document Authenticity Evaluation ---
            if doc_data.get("success"):
                active_tools_count += 1
                if doc_score >= 80:
                    evidence.append(f"Document Authenticity: High authenticity score ({doc_score}/100).")
                elif doc_score >= 50:
                    risk_points += 15
                    evidence.append(f"Document Authenticity: Moderate authenticity score ({doc_score}/100).")
                else:
                    risk_points += 40
                    evidence.append(f"Document Authenticity: Low authenticity score ({doc_score}/100).")

            # --- B. Facial Match Evaluation ---
            if face_data.get("success"):
                active_tools_count += 1
                decision = face_data.get("decision", "NO_MATCH")
                if decision == "MATCH":
                    evidence.append(f"Face Matching: Confirmed match ({face_sim}% similarity).")
                elif decision == "PARTIAL_MATCH":
                    risk_points += 20
                    evidence.append(f"Face Matching: Partial match ({face_sim}% similarity).")
                else:
                    risk_points += 45
                    evidence.append(f"Face Matching: Facial match failed ({face_sim}% similarity).")

            # --- C. Liveness Evaluation ---
            if live_data.get("success"):
                active_tools_count += 1
                if liveness_cls == "REAL":
                    evidence.append("Liveness Detection: Confirmed REAL biometric sample.")
                elif liveness_cls == "UNKNOWN":
                    risk_points += 15
                    evidence.append("Liveness Detection: Inconclusive liveness result.")
                else:
                    risk_points += 50
                    evidence.append("Liveness Detection: Presentation attack (SPOOF) detected.")

            # --- D. Cross-Consistency Evaluation ---
            if cons_data.get("success"):
                active_tools_count += 1
                cons_decision = cons_data.get("decision", "FAILED")
                if cons_decision == "VERIFIED":
                    evidence.append(f"Identity Consistency: High cross-consistency ({cons_score}/100).")
                elif cons_decision == "PARTIALLY_VERIFIED":
                    risk_points += 15
                    evidence.append(f"Identity Consistency: Partial cross-consistency ({cons_score}/100).")
                else:
                    risk_points += 35
                    evidence.append("Identity Consistency: Cross-verification failed.")

            # 2. Compute Identity Score & Risk Level
            raw_identity_score = int(round((doc_score * 0.3) + (face_sim * 0.35) + (100 if liveness_cls == "REAL" else 0) * 0.15 + (cons_score * 0.2)))
            identity_score = max(0, min(100, raw_identity_score))

            if risk_points >= 60 or identity_score < 40:
                overall_risk = "CRITICAL"
                verification_status = "REJECTED"
            elif risk_points >= 35 or identity_score < 65:
                overall_risk = "HIGH"
                verification_status = "REJECTED"
            elif risk_points >= 15 or identity_score < 80:
                overall_risk = "MEDIUM"
                verification_status = "NEEDS_REVIEW"
            else:
                overall_risk = "LOW"
                verification_status = "VERIFIED"

            confidence = min(99, 75 + (active_tools_count * 6)) if active_tools_count > 0 else 50

            # 3. Formulate Telemetry Dashboard
            dashboard = {
                "document_score": doc_score,
                "face_similarity": round(face_sim, 1),
                "liveness": liveness_cls,
                "consistency": cons_score
            }

            # 4. Formulate Recommendations & Executive Summary
            recommendations = self._generate_recommendations(verification_status, liveness_cls, doc_score)
            exec_summary = self._generate_executive_summary(verification_status, overall_risk, identity_score)

            return json.dumps({
                "success": True,
                "verification_status": verification_status,
                "overall_risk": overall_risk,
                "identity_score": identity_score,
                "confidence": confidence,
                "dashboard": dashboard,
                "evidence": evidence,
                "recommendations": recommendations,
                "executive_summary": exec_summary,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing IdentityRiskTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "verification_status": "REJECTED",
                "overall_risk": "CRITICAL",
                "identity_score": 0,
                "confidence": 0,
                "dashboard": {"document_score": 0, "face_similarity": 0.0, "liveness": "UNKNOWN", "consistency": 0},
                "evidence": [],
                "recommendations": [],
                "executive_summary": "Unable to compute identity risk evaluation due to error.",
                "error": f"Identity risk evaluation error: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        doc_json: Optional[str],
        face_json: Optional[str],
        live_json: Optional[str],
        cons_json: Optional[str],
        combined_json: Optional[str]
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Parse JSON inputs into structured dictionaries."""
        doc_data: Dict[str, Any] = {}
        face_data: Dict[str, Any] = {}
        live_data: Dict[str, Any] = {}
        cons_data: Dict[str, Any] = {}

        if combined_json:
            try:
                cdata = json.loads(combined_json) if isinstance(combined_json, str) else combined_json
                doc_data = cdata.get("document_verification", {}) or cdata.get("document", {})
                face_data = cdata.get("face_verification", {}) or cdata.get("face", {})
                live_data = cdata.get("liveness_detection", {}) or cdata.get("liveness", {})
                cons_data = cdata.get("identity_consistency", {}) or cdata.get("consistency", {})
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

        if cons_json:
            try:
                cons_data = json.loads(cons_json) if isinstance(cons_json, str) else cons_json
            except Exception:
                pass

        return doc_data, face_data, live_data, cons_data

    def _generate_recommendations(self, status: str, liveness: str, doc_score: int) -> List[str]:
        """Generate prioritized identity verification recommendations."""
        recs = []
        if status == "VERIFIED":
            recs.append("Identity verification approved; proceed with user onboarding.")
        elif status == "NEEDS_REVIEW":
            recs.append("Flag transaction for manual compliance officer review.")
            if doc_score < 70:
                recs.append("Request a higher-resolution document upload.")
        else:
            recs.append("Reject identity verification request due to high risk or biometric mismatch.")
            if liveness == "SPOOF":
                recs.append("Block user session due to detected biometric presentation attack.")

        return recs

    def _generate_executive_summary(self, status: str, risk: str, score: int) -> str:
        """Formulate executive summary statement."""
        if status == "VERIFIED":
            return f"Identity verification completed successfully with high confidence. Overall risk is {risk} (Identity Score: {score}/100)."
        elif status == "NEEDS_REVIEW":
            return f"Identity verification requires manual review due to {risk} risk rating (Identity Score: {score}/100)."
        return f"Identity verification failed and was REJECTED due to {risk} risk rating (Identity Score: {score}/100)."
