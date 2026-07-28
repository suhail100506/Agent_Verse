from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import cert_number_verification, authority_verification

class AuthorityRegistryAgent(BaseVerificationAgent):
    """
    Agent 7: Authority & Registry Verification Agent
    Verifies certificate ID format & checksum algorithms, cross-checks official university database records, and validates accreditation.
    """
    def __init__(self):
        super().__init__(
            agent_name="Authority & Registry Verification Agent",
            agent_id="agent_7_authority_registry",
            description="Validates certificate ID pattern, checksum integrity, and cross-references government/university registries."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        extracted_data = context.get("extracted_data", {})
        db = context.get("db")

        cert_no = extracted_data.get("certificate_number")
        inst = extracted_data.get("institution")

        # 1. Certificate Number Checksum Verification
        self.log_info(f"Validating certificate number pattern & checksum for: {cert_no}")
        cert_no_res = {}
        try:
            cert_no_res = cert_number_verification.verify_certificate_number(cert_no, inst)
        except Exception as e:
            self.log_error("Certificate number verification failed", e)
            cert_no_res = {"valid_format": False, "checksum_passed": False, "error": str(e)}

        # 2. Issuing Authority Cross-Check
        self.log_info(f"Cross-referencing issuing authority: {inst}")
        auth_res = {}
        try:
            auth_res = await authority_verification.verify_issuing_authority(extracted_data, db)
        except Exception as e:
            self.log_error("Authority verification failed", e)
            auth_res = {"method": "unavailable", "verified": None, "error": str(e)}

        return {
            "certificate_number_verification": cert_no_res,
            "authority_verification": auth_res
        }
