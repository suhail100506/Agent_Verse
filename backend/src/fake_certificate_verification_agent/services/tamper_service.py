import os
import re
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def inspect_tampering_and_signatures(file_path: str, metadata: Dict[str, Any], raw_text: str) -> Dict[str, Any]:
    """Inspects document for software editing tools (Photoshop, Canva, GIMP), digital signatures, and QR codes."""
    tamper_flags = []
    has_qr = False
    has_signature = False

    producer = str(metadata.get("producer", "")).lower()
    creator = str(metadata.get("creator", "")).lower()
    author = str(metadata.get("author", "")).lower()

    editing_tools = ["photoshop", "canva", "gimp", "paint.net", "illustrator", "inkscape", "pdfedit"]
    for tool in editing_tools:
        if tool in producer or tool in creator or tool in author:
            tamper_flags.append(f"Document modified with graphical editor ({tool})")

    text_lower = raw_text.lower()
    if any(term in text_lower for term in ["digitally signed", "signed by", "pki verified", "signature valid", "signature:"]):
        has_signature = True

    if any(term in text_lower for term in ["qr code", "scan to verify", "verify at http", "verification link", "au-2018"]):
        has_qr = True

    tampering_detected = len(tamper_flags) > 0
    tamper_score = max(0, 100 - (len(tamper_flags) * 35))

    return {
        "tampering_detected": tampering_detected,
        "tamper_score": tamper_score,
        "tamper_flags": tamper_flags,
        "has_qr_code": has_qr,
        "has_digital_signature": has_signature,
    }
