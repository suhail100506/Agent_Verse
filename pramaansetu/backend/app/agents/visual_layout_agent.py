from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import template_matching, logo_verification, seal_verification

class VisualLayoutAgent(BaseVerificationAgent):
    """
    Agent 3: Visual & Layout Inspection Agent
    Inspects visual structures including institutional template matching, official logo authenticity, and seal/stamp detection.
    """
    def __init__(self):
        super().__init__(
            agent_name="Visual & Layout Inspection Agent",
            agent_id="agent_3_visual_layout",
            description="Analyzes layout geometry, template similarity, university logo match, and official seal confidence."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        preprocessed_path = context.get("preprocessed_path")
        extracted_data = context.get("extracted_data", {})
        db = context.get("db")

        institution = extracted_data.get("institution")

        # 1. Template Matching
        self.log_info("Performing template library matching...")
        tmpl_res = {}
        try:
            template_list = []
            if db is not None:
                tpl_cursor = db.template_library.find({})
                template_list = await tpl_cursor.to_list(length=50)
            tmpl_res = template_matching.match_template(preprocessed_path, template_list, institution)
        except Exception as e:
            self.log_error("Template matching failed", e)
            tmpl_res = {"institution_matched": None, "similarity_pct": 0, "error": str(e)}

        # 2. Logo Verification
        self.log_info("Verifying institutional logo...")
        logo_res = {}
        try:
            logo_res = logo_verification.verify_logo(preprocessed_path)
        except Exception as e:
            self.log_error("Logo verification failed", e)
            logo_res = {"match_pct": 0, "error": str(e)}

        # 3. Seal Verification
        self.log_info("Verifying seal/stamp integrity...")
        seal_res = {}
        try:
            seal_res = seal_verification.verify_seal(preprocessed_path)
        except Exception as e:
            self.log_error("Seal verification failed", e)
            seal_res = {"confidence_pct": 0, "error": str(e)}

        return {
            "template_matching": tmpl_res,
            "logo_verification": logo_res,
            "seal_verification": seal_res
        }
