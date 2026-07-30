import os
import re
import logging
from typing import List, Dict, Any
from src.fake_certificate_verification_agent.services.ocr_service import extract_document_ocr

logger = logging.getLogger(__name__)

IDENTITY_KEYWORDS = [
    "passport", "aadhaar", "pan card", "driving license", "dl ", "employee id",
    "national id", "voter id", "ssn", "visa", "residence permit", "student id", "selfie", "photo id"
]

DOCUMENT_KEYWORDS = [
    "degree", "diploma", "certificate", "resume", "cv", "offer letter", "experience letter",
    "gst", "tax", "trade license", "salary slip", "pay slip", "bank statement", "invoice",
    "agreement", "contract", "insurance", "medical certificate"
]


def discover_and_classify_documents(downloaded_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyzes downloaded files, extracts OCR previews, and classifies each file as Identity or Document."""
    discovered = []

    for file_info in downloaded_files:
        file_path = file_info.get("file_path", "")
        filename = file_info.get("filename", "")
        file_type = file_info.get("file_type", "")

        ocr_res = extract_document_ocr(file_path, file_type)
        raw_text = ocr_res.get("raw_text", "")
        text_lower = (filename + " " + raw_text).lower()

        # Classification logic
        is_identity = any(kw in text_lower for kw in IDENTITY_KEYWORDS)
        category = "Identity Document" if is_identity else "Verification Document"

        # Determine doc sub-type
        doc_type = "Document"
        if "passport" in text_lower:
            doc_type = "Passport"
        elif "aadhaar" in text_lower:
            doc_type = "Aadhaar"
        elif "pan" in text_lower:
            doc_type = "PAN"
        elif "license" in text_lower or "dl" in text_lower:
            doc_type = "Driving License"
        elif "selfie" in text_lower or "photo" in text_lower:
            doc_type = "Selfie Photo"
        elif "degree" in text_lower or "university" in text_lower:
            doc_type = "Degree Certificate"
        elif "offer" in text_lower:
            doc_type = "Offer Letter"
        elif "resume" in text_lower or "cv" in text_lower:
            doc_type = "Resume"

        discovered.append({
            "filename": filename,
            "file_path": file_path,
            "file_type": file_type,
            "category": category,
            "doc_type": doc_type,
            "is_identity": is_identity,
            "preview": ocr_res.get("preview", ""),
            "ocr_data": ocr_res,
        })

    return discovered
