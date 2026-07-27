import logging
import fitz # PyMuPDF
from PIL import Image

logger = logging.getLogger(__name__)

# Lazy loading EasyOCR / PaddleOCR to avoid high start overhead
easyocr_reader = None

def get_easyocr_reader():
    global easyocr_reader
    if easyocr_reader is None:
        try:
            import easyocr
            easyocr_reader = easyocr.Reader(['en'], gpu=False)
        except Exception as e:
            logger.warning(f"Could not initialize EasyOCR: {e}")
            easyocr_reader = False
    return easyocr_reader

def run_ocr(image_path: str, original_pdf_path: str = None) -> dict:
    """Stage 3: OCR (PaddleOCR / EasyOCR primary with PyMuPDF direct text fallback)"""
    extracted_text_blocks = []
    confidence_scores = []
    engine_used = "PyMuPDF PDF Text"

    # Attempt PDF embedded text extraction if PDF exists
    if original_pdf_path and original_pdf_path.lower().endswith(".pdf"):
        try:
            doc = fitz.open(original_pdf_path)
            full_pdf_text = ""
            for page in doc:
                text = page.get_text("text")
                if text.strip():
                    full_pdf_text += text + "\n"
            doc.close()

            if len(full_pdf_text.strip()) > 30:
                return {
                    "passed": True,
                    "accuracy": 98.0,
                    "raw_text": full_pdf_text.strip(),
                    "text_blocks": [{"text": full_pdf_text.strip(), "confidence": 0.98}],
                    "engine": "PyMuPDF Direct Text Extraction"
                }
        except Exception as e:
            logger.warning(f"PyMuPDF text extraction failed: {e}")

    # Fallback to OCR engines on preprocessed image
    reader = get_easyocr_reader()
    if reader:
        try:
            results = reader.readtext(image_path)
            for (bbox, text, prob) in results:
                if prob > 0.15:
                    extracted_text_blocks.append({
                        "text": text,
                        "confidence": float(prob),
                        "bbox": [[int(pt[0]), int(pt[1])] for pt in bbox]
                    })
                    confidence_scores.append(float(prob))
            engine_used = "EasyOCR"
        except Exception as e:
            logger.warning(f"EasyOCR processing failed: {e}")

    # Final combined text
    raw_text = "\n".join([b["text"] for b in extracted_text_blocks])
    
    if not raw_text and original_pdf_path:
        # Emergency raw text fallback
        try:
            doc = fitz.open(original_pdf_path)
            raw_text = "\n".join([page.get_text() for page in doc])
            confidence_scores = [0.85]
            engine_used = "PyMuPDF Fallback"
        except Exception:
            pass

    avg_accuracy = round(sum(confidence_scores) / len(confidence_scores) * 100, 2) if confidence_scores else 0.0

    return {
        "passed": bool(raw_text.strip()),
        "accuracy": avg_accuracy if raw_text.strip() else 0.0,
        "raw_text": raw_text,
        "text_blocks": extracted_text_blocks,
        "engine": engine_used
    }
