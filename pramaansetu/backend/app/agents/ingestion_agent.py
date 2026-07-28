from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import upload_validation, preprocessing
from app.config import settings

class IngestionAgent(BaseVerificationAgent):
    """
    Agent 1: Ingestion & Preprocessing Agent
    Handles file format validation, file size checks, image normalization, noise reduction, and contrast enhancement.
    """
    def __init__(self):
        super().__init__(
            agent_name="Ingestion & Preprocessing Agent",
            agent_id="agent_1_ingestion",
            description="Validates uploaded certificate files and applies visual enhancement algorithms."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        file_path = context.get("file_path")
        temp_dir = context.get("temp_dir")
        
        self.log_info(f"Validating file ingestion: {file_path}")
        
        # 1. File Validation
        val_res = upload_validation.validate_file(file_path, settings.MAX_UPLOAD_SIZE_MB)
        
        # 2. Image Preprocessing
        preprocessed_path = file_path
        prep_res = {}
        try:
            prep_res = preprocessing.preprocess_image(file_path, temp_dir)
            preprocessed_path = prep_res.get("preprocessed_path", file_path)
        except Exception as e:
            self.log_error("Preprocessing failed", e)
            prep_res = {"passed": False, "error": str(e)}

        return {
            "validation": val_res,
            "preprocessing": prep_res,
            "preprocessed_path": preprocessed_path
        }
