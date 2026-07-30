import os
import json
import logging
from typing import Type, Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class FraudRiskToolInput(BaseModel):
    """Input schema for FraudRiskTool."""
    transaction_json: Optional[str] = Field(None, description="Raw JSON string or dict output from TransactionAnalysisTool.")
    behavioral_json: Optional[str] = Field(None, description="Raw JSON string or dict output from BehavioralAnalysisTool.")
    device_json: Optional[str] = Field(None, description="Raw JSON string or dict output from DeviceFingerprintTool.")
    takeover_json: Optional[str] = Field(None, description="Raw JSON string or dict output from AccountTakeoverTool.")
    combined_json: Optional[str] = Field(None, description="Combined JSON payload containing outputs from all fraud tools.")


class FraudRiskTool(BaseTool):
    name: str = "Fraud Risk Tool"
    description: str = (
        "Aggregates outputs from Transaction Analysis, Behavioral Analysis, Device Fingerprinting, and Account Takeover tools "
        "into a unified Enterprise Fraud Assessment with overall risk rating (LOW, MEDIUM, HIGH, CRITICAL), composite 0-100 fraud score, "
        "confidence rating, telemetry dashboard, evidence list, recommendations, and executive summary."
    )
    args_schema: Type[BaseModel] = FraudRiskToolInput

    def _run(
        self,
        transaction_json: Optional[str] = None,
        behavioral_json: Optional[str] = None,
        device_json: Optional[str] = None,
        takeover_json: Optional[str] = None,
        combined_json: Optional[str] = None
    ) -> str:
        """Execute enterprise fraud risk aggregation and synthesis."""
        try:
            # 1. Parse JSON inputs into structured dictionaries
            tx_data, beh_data, dev_data, ato_data = self._parse_inputs(
                transaction_json, behavioral_json, device_json, takeover_json, combined_json
            )

            evidence: List[str] = []
            recommendations: List[str] = []
            active_tools_count = 0

            tx_score = tx_data.get("transaction_score", 0)
            beh_score = beh_data.get("behavior_score", 0)
            dev_trust = dev_data.get("device_trust_score", 100)
            ato_prob = ato_data.get("takeover_probability", 0)

            # --- A. Transaction Evidence Extraction ---
            if tx_data.get("success"):
                active_tools_count += 1
                for f in tx_data.get("findings", []):
                    evidence.append(f)

            # --- B. Behavioral Evidence Extraction ---
            if beh_data.get("success"):
                active_tools_count += 1
                for e in beh_data.get("evidence", []):
                    evidence.append(e)

            # --- C. Device Fingerprint Evidence Extraction ---
            if dev_data.get("success"):
                active_tools_count += 1
                for f in dev_data.get("findings", []):
                    evidence.append(f)

            # --- D. Account Takeover Evidence Extraction ---
            if ato_data.get("success"):
                active_tools_count += 1
                for e in ato_data.get("evidence", []):
                    evidence.append(e)

            # 2. Compute Composite Fraud Score & Risk Level
            # Device trust is inverted: risk = (100 - trust_score)
            dev_risk = max(0, 100 - dev_trust)

            raw_fraud_score = int(round(
                (tx_score * 0.30) +
                (beh_score * 0.25) +
                (dev_risk * 0.20) +
                (ato_prob * 0.25)
            ))
            fraud_score = max(0, min(100, raw_fraud_score))

            if fraud_score >= 80 or ato_prob >= 80 or tx_data.get("risk") == "CRITICAL":
                overall_risk = "CRITICAL"
                fraud_detected = True
            elif fraud_score >= 60 or ato_prob >= 60 or tx_data.get("risk") == "HIGH":
                overall_risk = "HIGH"
                fraud_detected = True
            elif fraud_score >= 30:
                overall_risk = "MEDIUM"
                fraud_detected = False
            else:
                overall_risk = "LOW"
                fraud_detected = False

            confidence = min(98, 75 + (active_tools_count * 6)) if active_tools_count > 0 else 50

            # 3. Formulate Telemetry Dashboard
            dashboard = {
                "transaction_score": tx_score,
                "behavior_score": beh_score,
                "device_trust": dev_trust,
                "takeover_probability": ato_prob
            }

            # 4. Formulate Recommendations & Executive Summary
            recommendations = self._generate_recommendations(overall_risk, fraud_detected)
            exec_summary = self._generate_executive_summary(overall_risk, fraud_score, fraud_detected)

            return json.dumps({
                "success": True,
                "overall_risk": overall_risk,
                "fraud_score": fraud_score,
                "confidence": confidence,
                "fraud_detected": fraud_detected,
                "dashboard": dashboard,
                "evidence": list(dict.fromkeys(evidence)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "executive_summary": exec_summary,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing FraudRiskTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "overall_risk": "CRITICAL",
                "fraud_score": 0,
                "confidence": 0,
                "fraud_detected": True,
                "dashboard": {"transaction_score": 0, "behavior_score": 0, "device_trust": 0, "takeover_probability": 0},
                "evidence": [],
                "recommendations": [],
                "executive_summary": "Unable to complete fraud risk assessment due to error.",
                "error": f"Fraud risk aggregation error: {str(e)}"
            }, indent=2)

    def _parse_inputs(
        self,
        tx_json: Optional[str],
        beh_json: Optional[str],
        dev_json: Optional[str],
        ato_json: Optional[str],
        combined_json: Optional[str]
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Parse JSON inputs into structured dictionaries."""
        tx_data: Dict[str, Any] = {}
        beh_data: Dict[str, Any] = {}
        dev_data: Dict[str, Any] = {}
        ato_data: Dict[str, Any] = {}

        if combined_json:
            try:
                cdata = json.loads(combined_json) if isinstance(combined_json, str) else combined_json
                tx_data = cdata.get("transaction_analysis", {}) or cdata.get("transaction", {})
                beh_data = cdata.get("behavioral_analysis", {}) or cdata.get("behavior", {})
                dev_data = cdata.get("device_fingerprint", {}) or cdata.get("device", {})
                ato_data = cdata.get("account_takeover", {}) or cdata.get("takeover", {})
            except Exception:
                pass

        if tx_json:
            try:
                tx_data = json.loads(tx_json) if isinstance(tx_json, str) else tx_json
            except Exception:
                pass

        if beh_json:
            try:
                beh_data = json.loads(beh_json) if isinstance(beh_json, str) else beh_json
            except Exception:
                pass

        if dev_json:
            try:
                dev_data = json.loads(dev_json) if isinstance(dev_json, str) else dev_json
            except Exception:
                pass

        if ato_json:
            try:
                ato_data = json.loads(ato_json) if isinstance(ato_json, str) else ato_json
            except Exception:
                pass

        return tx_data, beh_data, dev_data, ato_data

    def _generate_recommendations(self, risk: str, fraud_detected: bool) -> List[str]:
        """Generate prioritized fraud response recommendations."""
        recs = []
        if risk in {"CRITICAL", "HIGH"}:
            recs.append("Block or hold the transaction immediately.")
            recs.append("Require step-up MFA verification.")
            recs.append("Notify the account owner via registered email/SMS.")
            recs.append("Review recent account activity and active sessions.")
            recs.append("Escalate to the fraud investigation team.")
        elif risk == "MEDIUM":
            recs.append("Flag transaction for step-up authentication challenge.")
            recs.append("Log transaction event for post-settlement fraud audit.")
        else:
            recs.append("No suspicious fraud indicators detected; approve transaction.")

        return recs

    def _generate_executive_summary(self, risk: str, score: int, fraud_detected: bool) -> str:
        """Formulate executive summary statement."""
        if fraud_detected:
            return (
                f"Fraud analysis identified multiple high-confidence indicators of suspicious activity ({risk} risk, "
                f"Fraud Score: {score}/100). Immediate verification and investigation are recommended."
            )
        return f"Fraud assessment completed with {risk} risk rating (Fraud Score: {score}/100). No immediate blocking required."
