import os
import json
from typing import Type, Any
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

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

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import easyocr
    HAS_EASYOCR = True
except ImportError:
    HAS_EASYOCR = False


class OCRToolInput(BaseModel):
    """Input schema for OCRTool."""
    file_path: str = Field(..., description="Absolute path to the image or PDF file to perform OCR text extraction on.")


class OCRTool(BaseTool):
    name: str = "OCR Tool"
    description: str = (
        "Extracts text content and confidence scores from digital certificates, PDF documents, "
        "and image files (PNG, JPG, JPEG, TIFF, BMP, WEBP) using Optical Character Recognition (OCR)."
    )
    args_schema: Type[BaseModel] = OCRToolInput

    def _run(self, file_path: str) -> str:
        """Execute OCR text extraction on the given file path."""
        clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))

        if not os.path.exists(clean_path):
            return json.dumps({
                "success": False,
                "extracted_text": "",
                "confidence": 0.0,
                "error": f"File not found at path: {clean_path}"
            }, indent=2)

        ext = os.path.splitext(clean_path)[1].lower()
        supported_images = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".webp"}

        try:
            if ext == ".pdf":
                return self._process_pdf(clean_path)
            elif ext in supported_images:
                return self._process_image(clean_path)
            else:
                return json.dumps({
                    "success": False,
                    "extracted_text": "",
                    "confidence": 0.0,
                    "error": f"Unsupported file extension '{ext}'. Supported types: PDF, PNG, JPG, JPEG, TIFF, BMP, WEBP."
                }, indent=2)
        except Exception as e:
            return json.dumps({
                "success": False,
                "extracted_text": "",
                "confidence": 0.0,
                "error": f"An error occurred during OCR processing: {str(e)}"
            }, indent=2)

    def _process_image(self, image_path: str) -> str:
        """Extract text from image files."""
        if not HAS_PIL:
            return json.dumps({
                "success": False,
                "extracted_text": "",
                "confidence": 0.0,
                "error": "PIL (Pillow) library is required to process images."
            }, indent=2)

        try:
            image = Image.open(image_path)
        except Exception as e:
            return json.dumps({
                "success": False,
                "extracted_text": "",
                "confidence": 0.0,
                "error": f"Failed to open image file: {str(e)}"
            }, indent=2)

        return self._ocr_pil_image(image)

    def _process_pdf(self, pdf_path: str) -> str:
        """Extract text from PDF files using direct text extraction or page rendering to OCR."""
        # 1. Try PyMuPDF (fitz) for native text extraction or page rendering
        if HAS_FITZ:
            try:
                doc = fitz.open(pdf_path)
                full_text = ""
                for page in doc:
                    full_text += page.get_text() + "\n"

                if full_text.strip():
                    return json.dumps({
                        "success": True,
                        "extracted_text": full_text.strip(),
                        "confidence": 1.0,
                        "error": None
                    }, indent=2)

                # Scanned PDF: render pages to images and run OCR
                if HAS_PIL:
                    ocr_texts = []
                    confidences = []
                    for page in doc:
                        pix = page.get_pixmap(dpi=150)
                        mode = "RGBA" if pix.alpha else "RGB"
                        img = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
                        res = json.loads(self._ocr_pil_image(img))
                        if res.get("success"):
                            ocr_texts.append(res.get("extracted_text", ""))
                            if res.get("confidence") is not None:
                                confidences.append(res.get("confidence"))

                    avg_conf = float(sum(confidences) / len(confidences)) if confidences else 0.8
                    return json.dumps({
                        "success": True,
                        "extracted_text": "\n".join(ocr_texts).strip(),
                        "confidence": round(avg_conf, 2),
                        "error": None
                    }, indent=2)
            except Exception:
                pass

        # 2. Fallback to pypdf for direct text extraction
        if HAS_PYPDF:
            try:
                reader = pypdf.PdfReader(pdf_path)
                pdf_text = ""
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted:
                        pdf_text += extracted + "\n"

                if pdf_text.strip():
                    return json.dumps({
                        "success": True,
                        "extracted_text": pdf_text.strip(),
                        "confidence": 1.0,
                        "error": None
                    }, indent=2)
            except Exception:
                pass

        return json.dumps({
            "success": False,
            "extracted_text": "",
            "confidence": 0.0,
            "error": "Could not extract text from PDF (file may be empty or unreadable)."
        }, indent=2)

    def _preprocess_image(self, image: Any) -> Any:
        """Preprocess PIL Image for enhanced OCR accuracy (scaling, grayscale, contrast)."""
        try:
            from PIL import ImageEnhance, ImageOps
            # Convert to grayscale
            processed = ImageOps.grayscale(image)
            # Scale low-resolution images 2x for clearer character boundaries
            w, h = processed.size
            if w < 1600 or h < 1200:
                processed = processed.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
            # Enhance contrast
            enhancer = ImageEnhance.Contrast(processed)
            processed = enhancer.enhance(1.5)
            return processed
        except Exception:
            return image

    def _ocr_pil_image(self, image: Any) -> str:
        """Run OCR on a PIL Image instance with preprocessing."""
        prep_img = self._preprocess_image(image)

        # 1. Try pytesseract
        if HAS_PYTESSERACT:
            try:
                # Custom configuration: PSM 6 (uniform block of text)
                custom_config = r'--psm 6'
                data = pytesseract.image_to_data(prep_img, config=custom_config, output_type=pytesseract.Output.DICT)
                texts = []
                confs = []
                for text, conf in zip(data.get("text", []), data.get("conf", [])):
                    if text.strip():
                        texts.append(text)
                        try:
                            c = float(conf)
                            if c >= 0:
                                confs.append(c)
                        except (ValueError, TypeError):
                            pass

                extracted = " ".join(texts)
                if not extracted.strip():
                    extracted = pytesseract.image_to_string(prep_img, config=custom_config).strip()

                avg_conf = (sum(confs) / len(confs)) / 100.0 if confs else 0.85
                return json.dumps({
                    "success": True,
                    "extracted_text": extracted,
                    "confidence": round(avg_conf, 2),
                    "error": None
                }, indent=2)
            except Exception:
                pass

        # 2. Fallback to EasyOCR if PyTesseract is unavailable/fails
        if HAS_EASYOCR:
            try:
                import numpy as np
                reader = easyocr.Reader(['en'], gpu=False)
                img_np = np.array(prep_img)
                results = reader.readtext(img_np)
                texts = [res[1] for res in results]
                confs = [res[2] for res in results]

                avg_conf = float(sum(confs) / len(confs)) if confs else 0.8
                return json.dumps({
                    "success": True,
                    "extracted_text": "\n".join(texts),
                    "confidence": round(avg_conf, 2),
                    "error": None
                }, indent=2)
            except Exception:
                pass

        return json.dumps({
            "success": False,
            "extracted_text": "",
            "confidence": 0.0,
            "error": "No OCR engine (PyTesseract or EasyOCR) succeeded in processing the image."
        }, indent=2)
