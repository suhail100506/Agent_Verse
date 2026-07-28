from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import tampering_detection

class TamperingDetectionAgent(BaseVerificationAgent):
    """
    Agent 5: Image Tampering & Forgery Agent
    Runs Error Level Analysis (ELA), detects copy-paste spliced text, font manipulation, and noise level variations.
    """
    def __init__(self):
        super().__init__(
            agent_name="Image Tampering & Forgery Agent",
            agent_id="agent_5_tampering_detection",
            description="Detects image manipulation, localized editing, ELA compression differences, and spliced regions."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        preprocessed_path = context.get("preprocessed_path")
        temp_dir = context.get("temp_dir")

        self.log_info("Running Error Level Analysis & forgery detection...")

        tamp_res = {}
        try:
            tamp_res = tampering_detection.detect_tampering(preprocessed_path, temp_dir)
        except Exception as e:
            self.log_error("Tampering detection failed", e)
            tamp_res = {"score": 0, "indicators_found": [], "error": str(e)}

        return {
            "tampering_detection": tamp_res
        }
