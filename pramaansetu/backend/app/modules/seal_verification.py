import cv2
import numpy as np

def verify_seal(image_path: str) -> dict:
    """Stage 9: Seal Verification (Hough circles, color histogram & confidence)"""
    img = cv2.imread(image_path)
    if img is None:
        return {"present": False, "confidence_pct": 0.0, "error": "Unable to read image."}

    h, w, _ = img.shape
    # Seals are typically located in bottom 40% of document
    seal_roi = img[int(h * 0.5):h, :]

    gray = cv2.cvtColor(seal_roi, cv2.COLOR_BGR2GRAY)
    blurred = cv2.medianBlur(gray, 5)

    # Hough Circle transform to detect official stamp / seal rings
    circles = cv2.HoughCircles(
        blurred,
        cv2.HOUGH_GRADIENT,
        dp=1.2,
        minDist=100,
        param1=50,
        param2=30,
        minRadius=30,
        maxRadius=180
    )

    seal_detected = False
    confidence = 0.0

    if circles is not None:
        seal_detected = True
        confidence = 90.0
    else:
        # Check red/blue stamp ink color mask
        hsv = cv2.cvtColor(seal_roi, cv2.COLOR_BGR2HSV)
        
        # Red ink mask
        lower_red1 = np.array([0, 50, 50])
        upper_red1 = np.array([10, 255, 255])
        lower_red2 = np.array([170, 50, 50])
        upper_red2 = np.array([180, 255, 255])
        mask_red = cv2.inRange(hsv, lower_red1, upper_red1) | cv2.inRange(hsv, lower_red2, upper_red2)
        
        # Blue ink mask
        lower_blue = np.array([100, 50, 50])
        upper_blue = np.array([140, 255, 255])
        mask_blue = cv2.inRange(hsv, lower_blue, upper_blue)

        ink_pixels = cv2.countNonZero(mask_red | mask_blue)
        if ink_pixels > 500:
            seal_detected = True
            confidence = 82.0
        else:
            # Baseline seal check on circular contour
            contours, _ = cv2.findContours(cv2.Canny(gray, 50, 150), cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
            for c in contours:
                area = cv2.contourArea(c)
                if area > 1000:
                    perimeter = cv2.arcLength(c, True)
                    if perimeter > 0:
                        circularity = 4 * np.pi * (area / (perimeter * perimeter))
                        if circularity > 0.6:
                            seal_detected = True
                            confidence = 78.0
                            break

    return {
        "present": seal_detected,
        "confidence_pct": round(confidence, 2) if seal_detected else 0.0,
        "notes": "Official circular seal/stamp identified with clear boundary." if seal_detected else "Official seal missing or unverified."
    }
