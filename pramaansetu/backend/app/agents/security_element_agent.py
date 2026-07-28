from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import qr_verification, signature_verification

class SecurityElementAgent(BaseVerificationAgent):
    """
    Agent 6: Security Element & Signature Agent
    Decodes QR codes / barcodes, validates encrypted payload integrity, and checks digital/physical signature authenticity.
    """
    def __init__(self):
        super().__init__(
            agent_name="Security Element & Signature Agent",
            agent_id="agent_6_security_element",
            description="Analyzes embedded QR security codes, digital certificates, and physical signature regions."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        file_path = context.get("file_path")
        preprocessed_path = context.get("preprocessed_path", file_path)
        extracted_data = context.get("extracted_data", {})

        # 1. QR Code Verification
        self.log_info("Verifying QR code security payload...")
        qr_res = {}
        try:
            qr_res = qr_verification.verify_qr_code(preprocessed_path, extracted_data)
        except Exception as e:
            self.log_error("QR verification failed", e)
            qr_res = {"status": "absent", "error": str(e), "match": False}

        # 2. Signature Verification
        self.log_info("Verifying digital & physical signatures...")
        sig_res = {}
        try:
            pdf_path = file_path if file_path and file_path.lower().endswith(".pdf") else None
            sig_res = signature_verification.verify_signature(preprocessed_path, pdf_path)
        except Exception as e:
            self.log_error("Signature verification failed", e)
            sig_res = {"present": False, "error": str(e)}

        return {
            "qr_verification": qr_res,
            "signature_verification": sig_res
        }
