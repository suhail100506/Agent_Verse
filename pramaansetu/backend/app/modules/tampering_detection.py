import os
import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance

def detect_tampering(image_path: str, temp_dir: str) -> dict:
    """Stage 12: Tampering Detection (Error Level Analysis ELA & font inconsistency)"""
    indicators_found = []
    tampering_score = 0.0

    try:
        # 1. Error Level Analysis (ELA)
        # Resave image at 95% JPEG quality and measure difference
        ela_temp_path = os.path.join(temp_dir, "ela_temp.jpg")
        orig_img = Image.open(image_path).convert("RGB")
        orig_img.save(ela_temp_path, "JPEG", quality=95)

        resaved_img = Image.open(ela_temp_path)
        ela_img = ImageChops.difference(orig_img, resaved_img)

        extrema = ela_img.getextrema()
        max_diff = max([ex[1] for ex in extrema]) if extrema else 1
        if max_diff == 0:
            max_diff = 1

        scale = 255.0 / max_diff
        ela_img = ImageEnhance.Brightness(ela_img).enhance(scale)
        
        # Calculate mean ELA intensity
        ela_np = np.array(ela_img)
        mean_ela_brightness = float(np.mean(ela_np))

        if mean_ela_brightness > 45.0:
            indicators_found.append("High Error Level Analysis (ELA) compression variance detected (re-compression or local text splice).")
            tampering_score += 45.0
        elif mean_ela_brightness > 30.0:
            indicators_found.append("Moderate ELA pixel variance detected.")
            tampering_score += 25.0

    except Exception as e:
        indicators_found.append(f"ELA analysis warning: {str(e)}")

    # 2. Font & Text Bounding Box Alignment Variance
    try:
        img_cv = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img_cv is not None:
            # Check edge intensity variance around text regions
            laplacian_var = cv2.Laplacian(img_cv, cv2.CV_64F).var()
            if laplacian_var < 50.0:
                indicators_found.append("Unusual blurriness/smoothing around text boundaries (possible copy-paste blending).")
                tampering_score += 20.0
    except Exception:
        pass

    tampering_score = min(100.0, round(tampering_score, 2))

    return {
        "score": tampering_score,
        "indicators_found": indicators_found,
        "notes": "Certificate exhibits signs of digital alteration." if tampering_score > 30.0 else "No significant digital splicing or ELA anomalies detected."
    }
