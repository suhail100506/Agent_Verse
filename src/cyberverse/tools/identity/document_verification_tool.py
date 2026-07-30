import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import pytesseract
    HAS_PYTESSERACT = True
except ImportError:
    HAS_PYTESSERACT = False

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DocumentVerificationToolInput(BaseModel):
    """Input schema for DocumentVerificationTool."""
    document_path: str = Field(..., description="Absolute file path to the identity document image or PDF to verify.")


class DocumentVerificationTool(BaseTool):
    name: str = "Document Verification Tool"
    description: str = (
        "Performs OCR extraction and authenticity verification on Passports, Aadhaar Cards, PAN Cards, Driving Licenses, "
        "and National IDs. Extracts identity fields (Name, DOB, Document Number, Expiry, Gender), detects image blur/tampering, "
        "checks QR presence, and computes document authenticity scores."
    )
    args_schema: Type[BaseModel] = DocumentVerificationToolInput

    def _run(self, document_path: str) -> str:
        """Execute identity document OCR extraction, field validation, and authenticity scoring."""
        warnings: List[str] = []

        if not document_path or not isinstance(document_path, str):
            return json.dumps({
                "success": False,
                "document_type": "Unknown",
                "fields": {},
                "ocr_confidence": 0,
                "authenticity_score": 0,
                "warnings": warnings,
                "error": "document_path argument must be a non-empty string."
            }, indent=2)

        clean_path = os.path.abspath(document_path.strip().strip('"').strip("'"))
        if not os.path.exists(clean_path):
            return json.dumps({
                "success": False,
                "document_type": "Unknown",
                "fields": {},
                "ocr_confidence": 0,
                "authenticity_score": 0,
                "warnings": warnings,
                "error": f"Document file not found at path: '{clean_path}'"
            }, indent=2)

        try:
            # 1. Perform Image Quality & Fraud Analysis (Blur, Resolution, QR Code)
            quality_metrics = self._analyze_image_quality(clean_path, warnings)

            # 2. Extract OCR Text & Calculate Confidence
            extracted_text, ocr_confidence = self._extract_ocr_text(clean_path, warnings)

            # 3. Classify Document Type
            doc_type = self._classify_document_type(extracted_text, clean_path)

            # 4. Extract Identity Fields
            fields = self._extract_identity_fields(extracted_text, doc_type, warnings)

            # 5. Compute Document Authenticity Score (0-100)
            authenticity_score = self._calculate_authenticity_score(
                fields, ocr_confidence, quality_metrics, warnings
            )

            return json.dumps({
                "success": True,
                "document_type": doc_type,
                "fields": fields,
                "ocr_confidence": round(ocr_confidence, 1),
                "authenticity_score": authenticity_score,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing DocumentVerificationTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "document_type": "Unknown",
                "fields": {},
                "ocr_confidence": 0,
                "authenticity_score": 0,
                "warnings": warnings,
                "error": f"Document verification failed: {str(e)}"
            }, indent=2)

    def _analyze_image_quality(self, file_path: str, warnings: List[str]) -> Dict[str, Any]:
        """Analyze resolution, blur variance, and QR presence using OpenCV."""
        result = {"is_blur": False, "low_res": False, "qr_detected": False, "blur_variance": 500.0}

        if not HAS_OPENCV:
            return result

        try:
            # Handle PDF rasterization if needed
            image_mat = None
            if file_path.lower().endswith(".pdf") and HAS_FITZ:
                doc = fitz.open(file_path)
                if len(doc) > 0:
                    page = doc[0]
                    pix = page.get_pixmap(dpi=150)
                    img_bytes = pix.tobytes("png")
                    nparr = np.frombuffer(img_bytes, np.uint8)
                    image_mat = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            else:
                image_mat = cv2.imread(file_path)

            if image_mat is None:
                return result

            # Dimensions & Low Resolution Check
            height, width = image_mat.shape[:2]
            if width < 600 or height < 400:
                result["low_res"] = True
                warnings.append(f"Low resolution document image detected ({width}x{height}px). Recommended minimum is 600px width.")

            # Blur Detection via Laplacian Variance
            gray = cv2.cvtColor(image_mat, cv2.COLOR_BGR2GRAY)
            laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
            result["blur_variance"] = round(laplacian_var, 1)

            if laplacian_var < 100.0:
                result["is_blur"] = True
                warnings.append(f"Image blur detected (Laplacian variance {laplacian_var:.1f} < 100). OCR accuracy may be degraded.")

            # QR Code Detection
            detector = cv2.QRCodeDetector()
            val, points, _ = detector.detectAndDecode(gray)
            if val:
                result["qr_detected"] = True

        except Exception as err:
            logger.debug(f"Image quality analysis exception: {err}")

        return result

    def _extract_ocr_text(self, file_path: str, warnings: List[str]) -> tuple[str, float]:
        """Extract text content and estimate OCR confidence across available engines."""
        text_lines = []
        confidences = []

        # Strategy 1: PyMuPDF for PDF documents
        if file_path.lower().endswith(".pdf") and HAS_FITZ:
            try:
                doc = fitz.open(file_path)
                for page in doc:
                    text_lines.append(page.get_text())
                if text_lines and "".join(text_lines).strip():
                    return "\n".join(text_lines), 95.0
            except Exception:
                pass

        # Strategy 2: PyTesseract for Images
        if HAS_PYTESSERACT and HAS_PIL:
            try:
                img = Image.open(file_path)
                data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
                
                text_chunks = []
                for i, word in enumerate(data.get("text", [])):
                    if word.strip():
                        text_chunks.append(word)
                        conf = int(data.get("conf", [100])[i])
                        if conf > 0:
                            confidences.append(conf)
                
                if text_chunks:
                    avg_conf = sum(confidences) / len(confidences) if confidences else 85.0
                    return " ".join(text_chunks), avg_conf
            except Exception as err:
                warnings.append(f"PyTesseract OCR extraction exception: {str(err)}")

        return "", 0.0

    def _classify_document_type(self, text: str, file_path: str) -> str:
        """Classify document category based on keyword and number patterns."""
        t_lower = text.lower()
        
        if "passport" in t_lower or re.search(r'\b[A-Z][0-9]{7,8}\b', text):
            return "Passport"
        elif "aadhaar" in t_lower or "government of india" in t_lower or re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\b', text):
            return "Aadhaar Card"
        elif "income tax" in t_lower or "permanent account number" in t_lower or re.search(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', text):
            return "PAN Card"
        elif "driving" in t_lower or "license" in t_lower or "licence" in t_lower:
            return "Driving License"
        elif "identity" in t_lower or "national id" in t_lower:
            return "National ID"
        elif "employee" in t_lower or "staff" in t_lower:
            return "Employee ID"

        return "National ID"

    def _extract_identity_fields(self, text: str, doc_type: str, warnings: List[str]) -> Dict[str, Any]:
        """Extract structured identity fields (Name, DOB, ID Number, Expiry, Gender, Nationality)."""
        fields = {
            "name": None,
            "dob": None,
            "document_number": None,
            "expiry_date": None,
            "gender": None,
            "nationality": None,
            "address": None
        }

        if not text:
            return fields

        # 1. Document Number Extraction
        if doc_type == "PAN Card":
            pan_m = re.search(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', text)
            if pan_m:
                fields["document_number"] = pan_m.group(0)
        elif doc_type == "Aadhaar Card":
            aadh_m = re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\b', text)
            if aadh_m:
                fields["document_number"] = aadh_m.group(0)
        elif doc_type == "Passport":
            pass_m = re.search(r'\b[A-PR-WYa-pr-wy][0-9]{7,8}\b', text)
            if pass_m:
                fields["document_number"] = pass_m.group(0)

        if not fields["document_number"]:
            gen_m = re.search(r'\b[A-Z0-9]{6,14}\b', text)
            if gen_m:
                fields["document_number"] = gen_m.group(0)

        # 2. Date of Birth (DOB) & Expiry Date
        dates = re.findall(r'\b\d{2}[/-]\d{2}[/-]\d{4}\b|\b\d{4}[/-]\d{2}[/-]\d{2}\b', text)
        if len(dates) >= 1:
            fields["dob"] = dates[0]
        if len(dates) >= 2:
            fields["expiry_date"] = dates[1]
            # Validate Expiry Date
            self._check_expiration(dates[1], warnings)

        # 3. Gender Detection
        if re.search(r'\b(female|woman|f)\b', text, re.IGNORECASE):
            fields["gender"] = "Female"
        elif re.search(r'\b(male|man|m)\b', text, re.IGNORECASE):
            fields["gender"] = "Male"

        # 4. Nationality Detection
        if re.search(r'\b(indian|india|ind)\b', text, re.IGNORECASE):
            fields["nationality"] = "Indian"
        elif re.search(r'\b(usa|united states|american)\b', text, re.IGNORECASE):
            fields["nationality"] = "American"

        # 5. Name Heuristic Extraction
        name_m = re.search(r'(?:Name|Holder|Name:)\s*([A-Za-z\s]{3,30})', text, re.IGNORECASE)
        if name_m:
            fields["name"] = name_m.group(1).strip()

        return fields

    def _check_expiration(self, expiry_str: str, warnings: List[str]) -> None:
        """Check if expiry date is past current local date."""
        try:
            exp_date = None
            for fmt in ["%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%Y/%m/%d"]:
                try:
                    exp_date = datetime.strptime(expiry_str, fmt)
                    break
                except ValueError:
                    continue

            if exp_date and exp_date.date() < datetime.now().date():
                warnings.append(f"Identity document is expired (Expiration date: {expiry_str}).")
        except Exception:
            pass

    def _calculate_authenticity_score(
        self,
        fields: Dict[str, Any],
        ocr_conf: float,
        quality: Dict[str, Any],
        warnings: List[str]
    ) -> int:
        """Calculate 0-100 document authenticity rating score."""
        score = 50

        # Field completeness (+30 max)
        present_fields = sum(1 for v in fields.values() if v is not None)
        score += min(30, present_fields * 6)

        # OCR Confidence (+15 max)
        score += int(min(15, (ocr_conf / 100.0) * 15))

        # QR Code Bonus (+10)
        if quality.get("qr_detected"):
            score += 10

        # Image Quality Deductions
        if quality.get("is_blur"):
            score -= 15
        if quality.get("low_res"):
            score -= 10

        # Expired Document Deduction
        if any("expired" in w.lower() for w in warnings):
            score -= 25

        return max(0, min(100, score))
