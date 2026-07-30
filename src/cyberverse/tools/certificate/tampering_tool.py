import os
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# Import sibling certificate verification tools for auto-execution fallback
from cyberverse.tools.certificate.ocr_tool import OCRTool
from cyberverse.tools.certificate.metadata_tool import MetadataTool
from cyberverse.tools.certificate.qr_tool import QRTool
from cyberverse.tools.certificate.signature_tool import DigitalSignatureTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class TamperingDetectionToolInput(BaseModel):
    """Input schema for TamperingDetectionTool."""
    file_path: str = Field(..., description="Absolute path to the image or PDF certificate file to evaluate for tampering.")
    ocr_json: Optional[str] = Field(None, description="Optional raw JSON string output from OCRTool.")
    metadata_json: Optional[str] = Field(None, description="Optional raw JSON string output from MetadataTool.")
    qr_json: Optional[str] = Field(None, description="Optional raw JSON string output from QRTool.")
    signature_json: Optional[str] = Field(None, description="Optional raw JSON string output from DigitalSignatureTool.")


class TamperingDetectionTool(BaseTool):
    name: str = "Tampering Detection Tool"
    description: str = (
        "Correlates and synthesizes evidence from OCR text extraction, metadata forensics, QR security scans, "
        "and digital signature verification. Computes overall document risk (LOW, MEDIUM, HIGH, CRITICAL), "
        "confidence score, tampering detection flags, detailed evidence statements, and action recommendations."
    )
    args_schema: Type[BaseModel] = TamperingDetectionToolInput

    def _run(
        self,
        file_path: str,
        ocr_json: Optional[str] = None,
        metadata_json: Optional[str] = None,
        qr_json: Optional[str] = None,
        signature_json: Optional[str] = None
    ) -> str:
        """Synthesize certificate verification evidence and compute overall tampering assessment."""
        clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))

        if not os.path.exists(clean_path):
            return json.dumps({
                "overall_risk": "HIGH",
                "confidence": 0,
                "tampering_detected": True,
                "evidence": [f"File not found at path: {clean_path}"],
                "recommendation": "Reject evaluation; target certificate file does not exist."
            }, indent=2)

        try:
            # 1. Execute tools automatically if JSON outputs were not supplied
            ocr_data = self._parse_or_run_tool(ocr_json, OCRTool, clean_path)
            meta_data = self._parse_or_run_tool(metadata_json, MetadataTool, clean_path)
            qr_data = self._parse_or_run_tool(qr_json, QRTool, clean_path)
            
            ext = os.path.splitext(clean_path)[1].lower()
            sig_data = self._parse_or_run_tool(signature_json, DigitalSignatureTool, clean_path) if ext == ".pdf" else None

            # 2. Synthesize Evidence and Risk Signals
            evidence: List[str] = []
            risk_points = 0
            confidence_accumulator = 100

            # Evaluate OCR Evidence
            if ocr_data and ocr_data.get("success"):
                conf = ocr_data.get("confidence", 0.0)
                text = ocr_data.get("extracted_text", "")
                if conf >= 0.70 and len(text) > 20:
                    evidence.append(f"OCR text extracted successfully with high confidence ({int(conf * 100)}%).")
                else:
                    evidence.append(f"OCR extraction returned low confidence ({int(conf * 100)}%) or unreadable text.")
                    risk_points += 15
                    confidence_accumulator -= 10
            else:
                evidence.append("OCR text extraction was unavailable or failed.")
                confidence_accumulator -= 15

            # Evaluate Metadata & Filesystem Anomaly Evidence
            if meta_data and meta_data.get("success"):
                forensic_findings = meta_data.get("forensic_findings", [])
                if forensic_findings:
                    for finding in forensic_findings:
                        sev = finding.get("severity", "LOW")
                        desc = finding.get("finding", "")
                        evidence.append(f"Metadata Anomaly [{sev}]: {desc}")
                        if sev == "CRITICAL":
                            risk_points += 40
                        elif sev == "HIGH":
                            risk_points += 25
                        elif sev == "MEDIUM":
                            risk_points += 15
                        else:
                            risk_points += 5
                else:
                    evidence.append("No filesystem or document metadata anomalies detected.")

            # Evaluate QR Security Evidence
            if qr_data and qr_data.get("success"):
                if qr_data.get("qr_found"):
                    for qres in qr_data.get("results", []):
                        ptype = qres.get("payload_type", "unknown")
                        qr_warns = qres.get("warnings", [])
                        if qres.get("https"):
                            evidence.append(f"QR code payload ({ptype}) uses secure HTTPS protocol ({qres.get('domain')}).")
                        elif qtype := qres.get("domain"):
                            evidence.append(f"QR code payload targets domain: {qtype}.")

                        if qr_warns:
                            for qw in qr_warns:
                                evidence.append(f"QR Security Warning: {qw}")
                                risk_points += 20
                else:
                    evidence.append("No QR code detected in document.")

            # Evaluate Digital Signature Evidence (PDFs)
            if ext == ".pdf":
                if sig_data and sig_data.get("success"):
                    if sig_data.get("signature_present"):
                        if sig_data.get("signature_valid"):
                            evidence.append("Valid digital signature and cryptographically intact PKCS#7 certificate present.")
                            confidence_accumulator += 10
                        else:
                            evidence.append("Digital signature present but failed cryptographic integrity verification!")
                            risk_points += 50
                            tampering_flag = True

                        sig_warns = sig_data.get("warnings", [])
                        for sw in sig_warns:
                            evidence.append(f"Digital Signature Warning: {sw}")
                            risk_points += 15
                    else:
                        evidence.append("Document does not contain a digital signature.")
                else:
                    evidence.append("Digital signature inspection failed or unverified.")

            # 3. Compute Final Risk Level, Confidence, & Tampering Flag
            tampering_detected = risk_points >= 30
            
            if risk_points == 0:
                overall_risk = "LOW"
            elif risk_points < 25:
                overall_risk = "LOW"
            elif risk_points < 50:
                overall_risk = "MEDIUM"
            elif risk_points < 75:
                overall_risk = "HIGH"
            else:
                overall_risk = "CRITICAL"

            final_confidence = max(10, min(99, confidence_accumulator - (risk_points // 2)))

            # Formulate Actionable Recommendation
            if tampering_detected or overall_risk in {"HIGH", "CRITICAL"}:
                recommendation = (
                    f"TAMPERING / ANOMALY WARNING: Document risk assessed as {overall_risk}. "
                    "Security anomalies detected. Escalate for manual SOC forensic verification."
                )
            elif overall_risk == "MEDIUM":
                recommendation = (
                    "MODERATE RISK: Certificate contains minor metadata or QR anomalies. Manual review recommended before approval."
                )
            else:
                recommendation = "PASS: Certificate appears authentic with no significant tampering indicators detected."

            return json.dumps({
                "overall_risk": overall_risk,
                "confidence": final_confidence,
                "tampering_detected": tampering_detected,
                "evidence": evidence,
                "recommendation": recommendation
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing TamperingDetectionTool for {clean_path}: {e}", exc_info=True)
            return json.dumps({
                "overall_risk": "HIGH",
                "confidence": 0,
                "tampering_detected": True,
                "evidence": [f"Tampering evaluation error: {str(e)}"],
                "recommendation": f"Failed to complete tampering evaluation ({str(e)})."
            }, indent=2)

    def _parse_or_run_tool(self, json_str: Optional[str], tool_cls: Type[BaseTool], file_path: str) -> Optional[Dict[str, Any]]:
        """Parse supplied tool JSON string or run the tool directly against the file_path."""
        if json_str and isinstance(json_str, str) and json_str.strip():
            try:
                return json.loads(json_str)
            except Exception:
                pass

        # Execute tool directly if JSON was not supplied
        try:
            tool_instance = tool_cls()
            raw_out = tool_instance._run(file_path)
            return json.loads(raw_out)
        except Exception as e:
            logger.warning(f"Auto-execution of {tool_cls.__name__} failed: {e}")
            return None
