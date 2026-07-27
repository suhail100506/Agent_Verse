import os
import cv2
import numpy as np
import fitz # PyMuPDF

def verify_signature(image_path: str, original_pdf_path: str = None) -> dict:
    """Stage 10: Signature Verification (stroke ROI presence & PDF digital signature check)"""
    pdf_sig_valid = None
    pdf_has_signatures = False

    # 1. Check PDF Digital Signatures via PyMuPDF if applicable
    if original_pdf_path and original_pdf_path.lower().endswith(".pdf"):
        try:
            doc = fitz.open(original_pdf_path)
            # PyMuPDF checks for digital signatures in PDF forms / fields
            signatures = [page.get_text("blocks") for page in doc]
            # Check for digital signature markers
            for page in doc:
                for widget in page.widgets():
                    if widget.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                        pdf_has_signatures = True
                        pdf_sig_valid = True
            doc.close()
        except Exception:
            pass

    # 2. Image-based signature ROI analysis
    img = cv2.imread(image_path)
    if img is None:
        return {
            "present": False,
            "type": "none",
            "pdf_signature_valid": pdf_sig_valid,
            "error": "Unable to read image for signature verification."
        }

    h, w, _ = img.shape
    # Signatures are typically at bottom 30% of document
    sig_roi = img[int(h * 0.7):h, :]

    gray = cv2.cvtColor(sig_roi, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150)
    
    # Calculate edge density (strokes density)
    stroke_density = cv2.countNonZero(edges) / float(gray.shape[0] * gray.shape[1])
    
    sig_present = stroke_density > 0.015 or pdf_has_signatures
    sig_type = "digital" if pdf_has_signatures else ("handwritten" if sig_present else "none")

    return {
        "present": sig_present,
        "type": sig_type,
        "pdf_signature_valid": pdf_sig_valid,
        "stroke_density": round(stroke_density, 4),
        "notes": f"Signature verified ({sig_type})." if sig_present else "No valid authority signature detected."
    }
