import os
import re
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False


def extract_document_ocr(file_path: str, file_type: str) -> Dict[str, Any]:
    """Extracts raw text, metadata, preview, and structured fields from a document."""
    result = {
        "raw_text": "",
        "preview": "",
        "language": "en",
        "dates": [],
        "id_numbers": [],
        "names": [],
        "issuer": None,
        "metadata": {},
        "ocr_engine": "pypdf",
    }

    if not file_path or not os.path.exists(file_path):
        return result

    raw_text = ""
    metadata = {}

    if file_type == "pdf" and HAS_PYPDF:
        try:
            reader = PdfReader(file_path)
            pages_text = [page.extract_text() for page in reader.pages if page.extract_text()]
            raw_text = "\n".join(pages_text)
            if reader.metadata:
                metadata = {
                    "author": str(reader.metadata.get("/Author", "")),
                    "producer": str(reader.metadata.get("/Producer", "")),
                    "creator": str(reader.metadata.get("/Creator", "")),
                    "creation_date": str(reader.metadata.get("/CreationDate", "")),
                }
        except Exception as e:
            logger.debug(f"PyPDF extraction error for {file_path}: {e}")

    if not raw_text:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_text = f.read()
                result["ocr_engine"] = "text_reader"
        except Exception as e:
            logger.debug(f"Direct text read failed for {file_path}: {e}")

    result["raw_text"] = raw_text.strip()
    result["preview"] = raw_text.strip()[:300]
    result["metadata"] = metadata

    # Regex extractions
    result["dates"] = re.findall(r"\b(?:\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})\b", raw_text)
    result["id_numbers"] = re.findall(r"\b[A-Z0-9]{6,16}\b", raw_text)

    # Issuer detection
    for kw in ["University", "Government", "Ministry", "Department", "Pvt Ltd", "Inc", "Corp", "Authority", "Institute"]:
        match = re.search(r"([A-Za-z0-9\s]+" + kw + r")", raw_text, re.I)
        if match:
            result["issuer"] = match.group(1).strip()
            break

    return result
