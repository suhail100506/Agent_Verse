import os
import cv2
import numpy as np
import fitz # PyMuPDF
from PIL import Image

def preprocess_image(file_path: str, temp_dir: str) -> dict:
    """Stage 2: Image Preprocessing (grayscale, deskew, noise reduction)"""
    os.makedirs(temp_dir, exist_ok=True)
    base_name = os.path.basename(file_path)
    output_filename = f"preprocessed_{os.path.splitext(base_name)[0]}.png"
    target_path = os.path.join(temp_dir, output_filename)

    # 1. Convert PDF to PNG if necessary
    source_img_path = file_path
    if file_path.lower().endswith(".pdf"):
        doc = fitz.open(file_path)
        page = doc[0]
        pix = page.get_pixmap(dpi=300)
        source_img_path = os.path.join(temp_dir, f"rendered_{os.path.splitext(base_name)[0]}.png")
        pix.save(source_img_path)
        doc.close()

    # 2. Read image with OpenCV
    img = cv2.imread(source_img_path)
    if img is None:
        return {"passed": False, "error": "Unable to read image into OpenCV", "preprocessed_path": source_img_path}

    # 3. Grayscale conversion
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # 4. Noise reduction via FastNlMeansDenoising
    denoised = cv2.fastNlMeansDenoising(gray, h=10)

    # 5. Deskewing
    coords = np.column_stack(np.where(denoised < 200))
    angle = 0.0
    if len(coords) > 0:
        rect = cv2.minAreaRect(coords)
        angle = rect[-1]
        if angle < -45:
            angle = -(90 + angle)
        else:
            angle = -angle
        
        # Avoid extreme rotation errors
        if abs(angle) < 15.0:
            (h, w) = denoised.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            denoised = cv2.warpAffine(denoised, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)

    # 6. Contrast adjustment (CLAHE)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(denoised)

    # Save preprocessed image
    cv2.imwrite(target_path, enhanced)

    return {
        "passed": True,
        "preprocessed_path": target_path,
        "deskew_angle": round(angle, 2),
        "notes": "Grayscale, noise reduction, CLAHE contrast, and deskewing completed."
    }
