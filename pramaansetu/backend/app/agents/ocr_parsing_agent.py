from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import ocr, info_extraction

class OCRParsingAgent(BaseVerificationAgent):
    """
    Agent 2: OCR & Layout Parsing Agent
    Extracts raw textual content from preprocessed images/PDFs and parses key certificate entities.
    """
    def __init__(self):
        super().__init__(
            agent_name="OCR & Layout Parsing Agent",
            agent_id="agent_2_ocr_parsing",
            description="Performs OCR text extraction and parses structured certificate fields (Name, Reg No, Institution, Date, CGPA)."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        file_path = context.get("file_path")
        preprocessed_path = context.get("preprocessed_path", file_path)

        self.log_info("Executing OCR text extraction...")
        
        # 1. Run OCR
        ocr_res = {}
        raw_text = ""
        try:
            pdf_path = file_path if file_path and file_path.lower().endswith(".pdf") else None
            ocr_res = ocr.run_ocr(preprocessed_path, pdf_path)
            raw_text = ocr_res.get("raw_text", "")
        except Exception as e:
            self.log_error("OCR extraction failed", e)
            ocr_res = {"passed": False, "error": str(e), "accuracy": 0, "raw_text": ""}

        # 2. Extract Information
        self.log_info("Parsing entity information from extracted text...")
        parse_res = {}
        extracted_data = {}
        try:
            parse_res = info_extraction.parse_information(raw_text)
            extracted_data = parse_res.get("extracted_data", {})
        except Exception as e:
            self.log_error("Entity parsing failed", e)
            parse_res = {"passed": False, "error": str(e)}

        return {
            "ocr": ocr_res,
            "info_parsing": parse_res,
            "extracted_data": extracted_data,
            "raw_text": raw_text
        }
