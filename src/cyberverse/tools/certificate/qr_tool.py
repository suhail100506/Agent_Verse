import os
import re
import json
import ipaddress
import logging
from urllib.parse import urlparse, parse_qs
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# Optional imports with graceful fallback flags
try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

try:
    import pyzbar.pyzbar as pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class QRToolInput(BaseModel):
    """Input schema for QRTool."""
    file_path: str = Field(..., description="Absolute path to the image or PDF file to scan for QR codes.")


class QRTool(BaseTool):
    name: str = "QR Code Tool"
    description: str = (
        "Detects, extracts, and decodes QR codes from digital certificates, images, and PDF documents. "
        "Classifies payloads (URL, Email, Phone, UUID, Text), parses URL domain/path/query components, "
        "and performs automated security threat checks (HTTP, long URLs, raw IP addresses, private subnets, malformed links)."
    )
    args_schema: Type[BaseModel] = QRToolInput

    def _run(self, file_path: str) -> str:
        """Execute QR code detection and analysis on the given file path."""
        clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))

        if not os.path.exists(clean_path):
            return json.dumps({
                "success": False,
                "qr_found": False,
                "count": 0,
                "results": [],
                "error": f"File not found at path: {clean_path}"
            }, indent=2)

        ext = os.path.splitext(clean_path)[1].lower()
        supported_images = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".webp"}
        supported_types = supported_images.union({".pdf"})

        if ext not in supported_types:
            return json.dumps({
                "success": False,
                "qr_found": False,
                "count": 0,
                "results": [],
                "error": f"Unsupported file extension '{ext}'. Supported: PDF, PNG, JPG, JPEG, TIFF, BMP, WEBP."
            }, indent=2)

        try:
            # 1. Render/load images for QR scanning
            image_frames = self._load_image_frames(clean_path, ext)
            if not image_frames:
                return json.dumps({
                    "success": False,
                    "qr_found": False,
                    "count": 0,
                    "results": [],
                    "error": "Failed to render image frames from input file."
                }, indent=2)

            # 2. Detect & Decode QR Codes across all frames
            raw_payloads = self._scan_qr_codes(image_frames)

            if not raw_payloads:
                return json.dumps({
                    "success": True,
                    "qr_found": False,
                    "count": 0,
                    "results": [],
                    "error": None
                }, indent=2)

            # 3. Analyze each discovered QR payload
            analyzed_results = [self._analyze_payload(payload) for payload in raw_payloads]

            return json.dumps({
                "success": True,
                "qr_found": True,
                "count": len(analyzed_results),
                "results": analyzed_results,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error scanning QR codes in {clean_path}: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "qr_found": False,
                "count": 0,
                "results": [],
                "error": f"An error occurred during QR code scanning: {str(e)}"
            }, indent=2)

    def _load_image_frames(self, file_path: str, ext: str) -> List[Any]:
        """Convert input file into a list of PIL Images or NumPy arrays for QR detection."""
        frames: List[Any] = []

        if ext == ".pdf":
            if HAS_FITZ:
                try:
                    doc = fitz.open(file_path)
                    for page in doc:
                        pix = page.get_pixmap(dpi=150)
                        mode = "RGBA" if pix.alpha else "RGB"
                        img = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
                        frames.append(img)
                except Exception as fitz_err:
                    logger.warning(f"PyMuPDF rendering error: {fitz_err}")
        else:
            if HAS_PIL:
                try:
                    img = Image.open(file_path)
                    frames.append(img)
                except Exception as pil_err:
                    logger.warning(f"PIL Image open error: {pil_err}")

        return frames

    def _scan_qr_codes(self, frames: List[Any]) -> List[str]:
        """Scan frames using PyZbar and OpenCV to extract unique QR payloads."""
        discovered_payloads: List[str] = []
        seen_set = set()

        for frame in frames:
            # Convert PIL image to OpenCV BGR numpy array if needed
            cv_img = None
            if HAS_PIL and isinstance(frame, Image.Image):
                if HAS_OPENCV:
                    cv_img = cv2.cvtColor(np.array(frame.convert("RGB")), cv2.COLOR_RGB2BGR)

            # Strategy A: PyZbar (High accuracy for multiple QR codes)
            if HAS_PYZBAR:
                try:
                    decoded_objects = pyzbar.decode(frame)
                    for obj in decoded_objects:
                        if obj.type == "QRCODE":
                            payload = obj.data.decode("utf-8", errors="ignore").strip()
                            if payload and payload not in seen_set:
                                seen_set.add(payload)
                                discovered_payloads.append(payload)
                except Exception as pyzbar_err:
                    logger.debug(f"PyZbar scan warning: {pyzbar_err}")

            # Strategy B: OpenCV QRCodeDetector fallback / complement
            if HAS_OPENCV and cv_img is not None:
                try:
                    detector = cv2.QRCodeDetector()
                    # Detect multiple QR codes if supported
                    if hasattr(detector, "detectAndDecodeMulti"):
                        retval, decoded_info, _, _ = detector.detectAndDecodeMulti(cv_img)
                        if retval and decoded_info:
                            for info in decoded_info:
                                info_str = info.strip()
                                if info_str and info_str not in seen_set:
                                    seen_set.add(info_str)
                                    discovered_payloads.append(info_str)
                    else:
                        info, _, _ = detector.detectAndDecode(cv_img)
                        if info:
                            info_str = info.strip()
                            if info_str and info_str not in seen_set:
                                seen_set.add(info_str)
                                discovered_payloads.append(info_str)
                except Exception as cv_err:
                    logger.debug(f"OpenCV QR scan warning: {cv_err}")

        return discovered_payloads

    def _analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Classify payload type, decompose URLs, and run security threat checks."""
        payload_type = self._classify_payload(payload)
        warnings: List[str] = []

        result: Dict[str, Any] = {
            "payload": payload,
            "payload_type": payload_type,
            "domain": None,
            "https": False,
            "path": None,
            "query_params": {},
            "warnings": warnings
        }

        if payload_type == "url":
            self._analyze_url(payload, result, warnings)

        return result

    def _classify_payload(self, payload: str) -> str:
        """Categorize payload string into URL, Email, Phone, UUID, Text, or Unknown."""
        cleaned = payload.strip()

        # 1. URL pattern
        if cleaned.lower().startswith(("http://", "https://", "ftp://")):
            return "url"

        # Regex check for domains without protocol (e.g. www.example.com or example.com/path)
        url_regex = re.compile(
            r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?$'
        )
        if url_regex.match(cleaned):
            return "url"

        # 2. Email pattern
        if cleaned.lower().startswith("mailto:") or re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', cleaned):
            return "email"

        # 3. Phone pattern
        if cleaned.lower().startswith("tel:") or re.match(r'^\+?[0-9\s\-\(\)]{7,15}$', cleaned):
            return "phone"

        # 4. UUID pattern (RFC 4122)
        uuid_regex = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
        if uuid_regex.match(cleaned):
            return "uuid"

        # 5. Generic text
        if len(cleaned) > 0:
            return "text"

        return "unknown"

    def _analyze_url(self, payload: str, result: Dict[str, Any], warnings: List[str]) -> None:
        """Decompose URL and run security vulnerability checks."""
        # Ensure scheme is present for parsing
        url_str = payload
        if not re.match(r'^[a-zA-Z]+://', url_str):
            url_str = "http://" + url_str
            warnings.append("Security Warning: URL omitted protocol scheme (defaulted to http:// for analysis).")

        try:
            parsed = urlparse(url_str)
            domain = parsed.hostname or parsed.netloc or ""
            scheme = parsed.scheme.lower()
            is_https = scheme == "https"

            result["domain"] = domain
            result["https"] = is_https
            result["path"] = parsed.path or "/"
            result["query_params"] = parse_qs(parsed.query)

            # Security Check 1: Insecure HTTP Protocol
            if not is_https:
                warnings.append("Security Warning: Insecure HTTP protocol used instead of HTTPS.")

            # Security Check 2: Suspiciously long URL (>200 chars)
            if len(payload) > 200:
                warnings.append(f"Security Warning: Suspiciously long URL payload ({len(payload)} characters).")

            # Security Check 3: Malformed URL check
            if not domain:
                warnings.append("Security Warning: Malformed URL structure (missing valid domain hostname).")

            # Security Check 4, 5, 6: IP-address, Localhost, & Private IP checks
            if domain:
                self._check_ip_and_domain_security(domain, warnings)

        except Exception as e:
            warnings.append(f"Security Warning: Failed to parse URL structure cleanly ({str(e)}).")

    def _check_ip_and_domain_security(self, domain: str, warnings: List[str]) -> None:
        """Check for IP-address hostnames, Localhost, and Private Subnets."""
        clean_domain = domain.split(":")[0].strip("[]")

        # Check Localhost
        if clean_domain.lower() in {"localhost", "127.0.0.1", "::1"}:
            warnings.append("Security Warning: URL target resolves to localhost / loopback address.")
            return

        # Check if domain is a raw IP address
        try:
            ip_obj = ipaddress.ip_address(clean_domain)
            warnings.append(f"Security Warning: URL uses raw IP address hostname ({clean_domain}).")

            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                warnings.append(f"Security Warning: URL hostname is a private/internal IP address ({clean_domain}).")
        except ValueError:
            # Domain is a standard domain name (not an IP address)
            pass
