import os
import re
import json
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# Optional Presidio Analyzer import with fallback
try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    HAS_PRESIDIO = True
except ImportError:
    HAS_PRESIDIO = False

# Optional PyMuPDF / PIL imports for reading file inputs
try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class PIIDetectionToolInput(BaseModel):
    """Input schema for PIIDetectionTool."""
    file_path: Optional[str] = Field(None, description="Absolute path to a text, image, or PDF document file to scan for PII.")
    text_content: Optional[str] = Field(None, description="Direct text content string to scan for PII entities.")


class PIIDetectionTool(BaseTool):
    name: str = "PII Detection Tool"
    description: str = (
        "Scans documents or text strings for Personally Identifiable Information (PII) "
        "including Person Names, Email Addresses, Phone Numbers, Aadhaar Numbers, PAN Cards, "
        "Passport Numbers, Credit Card Numbers, US SSN, IP Addresses, URLs, Dates, Organizations, and Locations."
    )
    args_schema: Type[BaseModel] = PIIDetectionToolInput

    def _run(self, file_path: Optional[str] = None, text_content: Optional[str] = None) -> str:
        """Execute PII entity detection across text content or file path."""
        warnings: List[str] = []

        # 1. Resolve text source
        raw_text = self._resolve_text_input(file_path, text_content, warnings)

        if not raw_text or not raw_text.strip():
            return json.dumps({
                "success": False,
                "entities": [],
                "summary": {},
                "warnings": warnings,
                "error": "No valid text content or readable file provided for PII scanning."
            }, indent=2)

        try:
            # 2. Extract PII entities using Presidio & Custom Recognizers
            detected_entities = self._detect_pii(raw_text, warnings)

            # 3. Build Entity Count Summary Breakdown
            summary_counts: Dict[str, int] = {}
            for entity in detected_entities:
                etype = entity["type"]
                summary_counts[etype] = summary_counts.get(etype, 0) + 1

            return json.dumps({
                "success": True,
                "entities": detected_entities,
                "summary": summary_counts,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing PIIDetectionTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "entities": [],
                "summary": {},
                "warnings": warnings,
                "error": f"PII Detection error: {str(e)}"
            }, indent=2)

    def _resolve_text_input(self, file_path: Optional[str], text_content: Optional[str], warnings: List[str]) -> str:
        """Extract text from text_content or load from file_path."""
        if text_content and text_content.strip():
            return text_content.strip()

        if file_path and isinstance(file_path, str):
            clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))
            if not os.path.exists(clean_path):
                warnings.append(f"File not found at path: {clean_path}")
                return ""

            ext = os.path.splitext(clean_path)[1].lower()
            if ext in {".txt", ".log", ".csv", ".json", ".md", ".xml", ".html"}:
                try:
                    with open(clean_path, "r", encoding="utf-8", errors="ignore") as f:
                        return f.read()
                except Exception as e:
                    warnings.append(f"File read warning: {str(e)}")

            elif ext == ".pdf" and HAS_FITZ:
                try:
                    doc = fitz.open(clean_path)
                    pdf_text = ""
                    for page in doc:
                        pdf_text += page.get_text() + "\n"
                    if pdf_text.strip():
                        return pdf_text
                except Exception as fitz_err:
                    warnings.append(f"PDF text extraction warning: {str(fitz_err)}")

        return ""

    def _detect_pii(self, text: str, warnings: List[str]) -> List[Dict[str, Any]]:
        """Run Presidio Analyzer Engine and Custom Regex Pattern Recognizers."""
        entities_list: List[Dict[str, Any]] = []
        seen_keys = set()

        # Engine A: Microsoft Presidio (if available)
        if HAS_PRESIDIO:
            try:
                analyzer = AnalyzerEngine()
                results = analyzer.analyze(text=text, language="en")
                for res in results:
                    ent_text = text[res.start:res.end].strip()
                    if ent_text:
                        key = (res.entity_type, res.start, res.end, ent_text)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            entities_list.append({
                                "type": res.entity_type,
                                "text": ent_text,
                                "confidence": round(float(res.score), 2),
                                "start": res.start,
                                "end": res.end
                            })
            except Exception as presidio_err:
                logger.debug(f"Presidio Analyzer warning: {str(presidio_err)}")

        # Engine B: Custom Regex Pattern Recognizers (Aadhaar, PAN, SSN, Credit Cards, Passports, Email, Phone, IP, URL, Person)
        custom_patterns = [
            # 1. Indian Aadhaar Card (12 digits with Verhoeff validation)
            ("IN_AADHAAR", r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b', 0.95, self._validate_aadhaar),
            # 2. Indian PAN Card (10 chars: AAAAA1111A)
            ("IN_PAN", r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', 0.95, None),
            # 3. US Social Security Number (SSN)
            ("US_SSN", r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', 0.90, None),
            # 4. Credit Card Number (13-19 digits with Luhn algorithm validation)
            ("CREDIT_CARD", r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b', 0.95, self._validate_luhn),
            # 5. International Passport Number
            ("PASSPORT", r'\b[A-Z]{1,2}[0-9]{7,8}\b', 0.85, None),
            # 6. Email Address
            ("EMAIL_ADDRESS", r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', 0.99, None),
            # 7. Phone Number
            ("PHONE_NUMBER", r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', 0.85, None),
            # 8. IP Address
            ("IP_ADDRESS", r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 0.90, None),
            # 9. URL
            ("URL", r'\bhttps?://[^\s/$.?#].[^\s]*\b', 0.90, None),
            # 10. Person Name (Prefix matching: Name: <Full Name>)
            ("PERSON", r'(?:Name|Subject|User|Person):\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)', 0.85, None),
        ]

        for item in custom_patterns:
            entity_type, regex_pattern, default_conf, validator_fn = item[0], item[1], item[2], item[3]
            for match in re.finditer(regex_pattern, text):
                if match.groups():
                    matched_text = match.group(1).strip()
                    start, end = match.start(1), match.end(1)
                else:
                    matched_text = match.group(0).strip()
                    start, end = match.start(), match.end()

                if validator_fn and not validator_fn(matched_text):
                    continue

                key = (entity_type, start, end, matched_text)
                if key not in seen_keys:
                    seen_keys.add(key)
                    entities_list.append({
                        "type": entity_type,
                        "text": matched_text,
                        "confidence": default_conf,
                        "start": start,
                        "end": end
                    })

        # Sort entities by start offset
        entities_list.sort(key=lambda x: x["start"])
        return entities_list

    def _validate_luhn(self, card_num: str) -> bool:
        """Validate credit card number using Luhn Algorithm."""
        digits = [int(c) for c in re.sub(r'\D', '', card_num)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def _validate_aadhaar(self, aadhaar_str: str) -> bool:
        """Validate 12-digit Indian Aadhaar number using Verhoeff Checksum Algorithm."""
        clean = re.sub(r'\s', '', aadhaar_str)
        if len(clean) != 12 or not clean.isdigit():
            return False

        # Verhoeff multiplication table
        d = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ]
        # Verhoeff permutation table
        p = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
        ]

        c = 0
        inverted = [int(x) for x in reversed(clean)]
        for i, item in enumerate(inverted):
            c = d[c][p[i % 8][item]]

        return c == 0
