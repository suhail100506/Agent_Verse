from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import metadata_analysis

class MetadataForensicsAgent(BaseVerificationAgent):
    """
    Agent 4: Digital Forensics & Metadata Agent
    Analyzes EXIF image tags, PDF structural metadata, creation/modification software artifacts, and date consistency.
    """
    def __init__(self):
        super().__init__(
            agent_name="Digital Forensics & Metadata Agent",
            agent_id="agent_4_metadata_forensics",
            description="Examines document EXIF data, editing software traces (Photoshop/Canva), and timestamp anomalies."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        file_path = context.get("file_path")
        self.log_info(f"Analyzing metadata forensics for file: {file_path}")

        meta_res = {}
        try:
            meta_res = metadata_analysis.analyze_metadata(file_path)
        except Exception as e:
            self.log_error("Metadata analysis failed", e)
            meta_res = {"risk_flag": False, "error": str(e)}

        return {
            "metadata_analysis": meta_res
        }
