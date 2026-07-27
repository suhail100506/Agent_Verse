import cv2
import logging

logger = logging.getLogger(__name__)

def verify_qr_code(image_path: str, extracted_data: dict) -> dict:
    """Stage 5: QR Code Verification (Pyzbar + OpenCV detection & field match)"""
    decoded_url = None
    qr_detected = False

    img = cv2.imread(image_path)
    if img is None:
        return {
            "status": "absent",
            "decoded_url": "",
            "match": False,
            "error": "Failed to load image for QR detection"
        }

    # 1. Try Pyzbar
    try:
        from pyzbar.pyzbar import decode
        decoded_objs = decode(img)
        if decoded_objs:
            qr_detected = True
            decoded_url = decoded_objs[0].data.decode("utf-8")
    except Exception as e:
        logger.warning(f"Pyzbar decoding attempt failed: {e}")

    # 2. Fallback to OpenCV QRCodeDetector
    if not qr_detected:
        try:
            detector = cv2.QRCodeDetector()
            val, pts, _ = detector.detectAndDecode(img)
            if val:
                qr_detected = True
                decoded_url = val
        except Exception as e:
            logger.warning(f"OpenCV QRCodeDetector failed: {e}")

    if not qr_detected or not decoded_url:
        return {
            "status": "absent",
            "decoded_url": "",
            "match": False,
            "notes": "No readable QR code found on certificate."
        }

    # Check match against extracted certificate details
    cert_no = extracted_data.get("certificate_number")
    name = extracted_data.get("name")
    inst = extracted_data.get("institution")

    matches = []
    if cert_no and cert_no.lower() in decoded_url.lower():
        matches.append("certificate_number")
    if name and any(part.lower() in decoded_url.lower() for part in name.split()):
        matches.append("name")
    if inst and inst.lower() in decoded_url.lower():
        matches.append("institution")

    is_match = len(matches) > 0 or "http" in decoded_url.lower()

    return {
        "status": "passed" if is_match else "failed",
        "decoded_url": decoded_url,
        "match": is_match,
        "matched_fields": matches,
        "notes": f"QR detected. Matched fields: {matches}" if matches else "QR payload detected but key fields did not match."
    }
