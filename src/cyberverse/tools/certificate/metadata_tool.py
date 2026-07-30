import os
import json
import hashlib
import mimetypes
import logging
from datetime import datetime, timezone
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# Optional library imports with fallbacks
try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

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

# Setup module logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class MetadataToolInput(BaseModel):
    """Input schema for MetadataTool."""
    file_path: str = Field(..., description="Absolute path to the image or PDF file to extract metadata from.")


class MetadataTool(BaseTool):
    name: str = "Metadata Tool"
    description: str = (
        "Extracts file metadata including general info (size, MIME type, hashes), "
        "filesystem timestamps (created, modified, accessed), PDF metadata (author, title, producer, version, pages), "
        "and Image properties (resolution, DPI, color mode, EXIF tags)."
    )
    args_schema: Type[BaseModel] = MetadataToolInput

    def _run(self, file_path: str) -> str:
        """Execute metadata extraction for the provided file path."""
        clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))
        warnings: List[str] = []

        if not os.path.exists(clean_path):
            return json.dumps({
                "success": False,
                "general": None,
                "filesystem": None,
                "pdf_metadata": None,
                "image_metadata": None,
                "warnings": warnings,
                "error": f"File not found at path: {clean_path}"
            }, indent=2)

        ext = os.path.splitext(clean_path)[1].lower()
        supported_images = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".webp"}
        supported_types = supported_images.union({".pdf"})

        if ext not in supported_types:
            return json.dumps({
                "success": False,
                "general": None,
                "filesystem": None,
                "pdf_metadata": None,
                "image_metadata": None,
                "warnings": warnings,
                "error": f"Unsupported file extension '{ext}'. Supported: PDF, PNG, JPG, JPEG, TIFF, BMP, WEBP."
            }, indent=2)

        try:
            # 1. Extract General File Info & Hashes
            general_info = self._get_general_info(clean_path)

            # 2. Extract Filesystem Timestamps
            filesystem_info = self._get_filesystem_info(clean_path)

            # 3. Extract Specific Metadata (PDF or Image)
            pdf_meta: Optional[Dict[str, Any]] = None
            image_meta: Optional[Dict[str, Any]] = None

            if ext == ".pdf":
                pdf_meta = self._get_pdf_metadata(clean_path, warnings)
            elif ext in supported_images:
                image_meta = self._get_image_metadata(clean_path, warnings)

            # Perform automated forensic checks
            forensic_findings: List[Dict[str, Any]] = []
            self._run_forensic_checks(general_info, filesystem_info, pdf_meta, image_meta, warnings, forensic_findings)

            return json.dumps({
                "success": True,
                "general": general_info,
                "filesystem": filesystem_info,
                "pdf_metadata": pdf_meta,
                "image_metadata": image_meta,
                "forensic_findings": forensic_findings,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error during metadata extraction for {clean_path}: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "general": None,
                "filesystem": None,
                "pdf_metadata": None,
                "image_metadata": None,
                "warnings": warnings,
                "error": f"Metadata extraction failed: {str(e)}"
            }, indent=2)

    def _get_general_info(self, file_path: str) -> Dict[str, Any]:
        """Compute general file attributes and cryptographic hashes."""
        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()
        size_bytes = os.path.getsize(file_path)
        size_kb = round(size_bytes / 1024.0, 2)

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/pdf" if ext == ".pdf" else "image/unknown"

        # Compute SHA256 & MD5 in 64KB chunks
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)

        return {
            "filename": filename,
            "extension": ext,
            "absolute_path": file_path,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "size_kb": size_kb,
            "sha256": sha256_hash.hexdigest(),
            "md5": md5_hash.hexdigest()
        }

    def _get_filesystem_info(self, file_path: str) -> Dict[str, Any]:
        """Extract filesystem creation, modification, and access timestamps in ISO format."""
        stat_res = os.stat(file_path)

        # Cross-platform creation time lookup
        if hasattr(stat_res, "st_birthtime"):  # macOS / BSD
            creation_ts = stat_res.st_birthtime
        else:  # Windows (st_ctime is creation time) / Linux (st_ctime is metadata change time)
            creation_ts = stat_res.st_ctime

        created_at = datetime.fromtimestamp(creation_ts, tz=timezone.utc).isoformat()
        modified_at = datetime.fromtimestamp(stat_res.st_mtime, tz=timezone.utc).isoformat()
        accessed_at = datetime.fromtimestamp(stat_res.st_atime, tz=timezone.utc).isoformat()

        return {
            "created_at": created_at,
            "modified_at": modified_at,
            "accessed_at": accessed_at
        }

    def _get_pdf_metadata(self, file_path: str, warnings: List[str]) -> Dict[str, Any]:
        """Extract PDF header properties, creation date, producer, version, and page count."""
        pdf_data: Dict[str, Any] = {
            "title": None,
            "author": None,
            "subject": None,
            "creator": None,
            "producer": None,
            "creation_date": None,
            "modification_date": None,
            "pdf_version": None,
            "page_count": 0
        }

        # 1. Try PyMuPDF (fitz)
        if HAS_FITZ:
            try:
                doc = fitz.open(file_path)
                meta = doc.metadata or {}
                pdf_data["title"] = meta.get("title") or None
                pdf_data["author"] = meta.get("author") or None
                pdf_data["subject"] = meta.get("subject") or None
                pdf_data["creator"] = meta.get("creator") or None
                pdf_data["producer"] = meta.get("producer") or None
                pdf_data["creation_date"] = meta.get("creationDate") or None
                pdf_data["modification_date"] = meta.get("modDate") or None
                pdf_data["pdf_version"] = meta.get("format") or (f"1.{doc.pdf_version}" if hasattr(doc, "pdf_version") else None)
                pdf_data["page_count"] = len(doc)
                return pdf_data
            except Exception as e:
                warnings.append(f"PyMuPDF metadata extraction warning: {str(e)}")

        # 2. Fallback to pypdf
        if HAS_PYPDF:
            try:
                reader = pypdf.PdfReader(file_path)
                meta = reader.metadata or {}
                pdf_data["title"] = str(meta.title) if meta.title else None
                pdf_data["author"] = str(meta.author) if meta.author else None
                pdf_data["subject"] = str(meta.subject) if meta.subject else None
                pdf_data["creator"] = str(meta.creator) if meta.creator else None
                pdf_data["producer"] = str(meta.producer) if meta.producer else None
                pdf_data["creation_date"] = str(meta.get("/CreationDate")) if meta.get("/CreationDate") else None
                pdf_data["modification_date"] = str(meta.get("/ModDate")) if meta.get("/ModDate") else None
                pdf_data["page_count"] = len(reader.pages)
                return pdf_data
            except Exception as e:
                warnings.append(f"pypdf metadata extraction warning: {str(e)}")

        warnings.append("No PDF library (PyMuPDF or pypdf) was able to extract PDF metadata.")
        return pdf_data

    def _get_image_metadata(self, file_path: str, warnings: List[str]) -> Dict[str, Any]:
        """Extract Image dimensions, DPI, color mode, and parsed EXIF tags."""
        image_data: Dict[str, Any] = {
            "width": 0,
            "height": 0,
            "dpi": None,
            "color_mode": None,
            "exif": {}
        }

        if not HAS_PIL:
            warnings.append("Pillow (PIL) is not installed; skipping image metadata parsing.")
            return image_data

        try:
            with Image.open(file_path) as img:
                image_data["width"] = img.width
                image_data["height"] = img.height
                image_data["color_mode"] = img.mode

                dpi_val = img.info.get("dpi")
                if dpi_val:
                    image_data["dpi"] = list(dpi_val) if isinstance(dpi_val, (tuple, list)) else [dpi_val, dpi_val]

                # Parse EXIF tags if present
                exif_dict: Dict[str, Any] = {}
                try:
                    raw_exif = img._getexif() if hasattr(img, "_getexif") else None
                    if raw_exif:
                        for tag_id, value in raw_exif.items():
                            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                            # Convert non-serializable EXIF objects to strings/numbers
                            exif_dict[tag_name] = self._make_json_serializable(value)
                except Exception as exif_err:
                    warnings.append(f"EXIF parsing warning: {str(e)}")

                image_data["exif"] = exif_dict
                return image_data

        except Exception as e:
            warnings.append(f"Image metadata parsing error: {str(e)}")

        return image_data

    def _make_json_serializable(self, val: Any) -> Any:
        """Convert raw EXIF values to JSON-serializable types."""
        if isinstance(val, (int, float, str, bool, type(None))):
            return val
        elif isinstance(val, bytes):
            try:
                return val.decode("utf-8", errors="ignore")
            except Exception:
                return val.hex()
        elif isinstance(val, (tuple, list)):
            return [self._make_json_serializable(item) for item in val]
        elif isinstance(val, dict):
            return {str(k): self._make_json_serializable(v) for k, v in val.items()}
        else:
            return str(val)

    def _run_forensic_checks(
        self,
        general: Dict[str, Any],
        filesystem: Dict[str, Any],
        pdf_meta: Optional[Dict[str, Any]],
        image_meta: Optional[Dict[str, Any]],
        warnings: List[str],
        forensic_findings: List[Dict[str, Any]]
    ) -> None:
        """Perform automated forensic checks and populate structured forensic findings array."""
        # 1. Zero byte file check
        if general.get("size_bytes", 0) == 0:
            warnings.append("Forensic Warning: File size is 0 bytes (empty file).")
            forensic_findings.append({
                "id": "FIL001",
                "severity": "HIGH",
                "category": "File Integrity",
                "finding": "File size is 0 bytes (empty file)",
                "recommendation": "Verify file transmission or source file generation; empty files contain no digital certificate data."
            })

        # 2. Filesystem timestamp anomaly check: Creation > Modification
        try:
            created = datetime.fromisoformat(filesystem["created_at"])
            modified = datetime.fromisoformat(filesystem["modified_at"])
            if created > modified:
                warnings.append("Forensic Warning: Creation timestamp is later than modification timestamp (possible timestomping).")
                forensic_findings.append({
                    "id": "FS001",
                    "severity": "MEDIUM",
                    "category": "Filesystem Anomaly",
                    "finding": "Creation timestamp is later than modification timestamp",
                    "recommendation": "Inspect file origin for timestomping tools or artificial creation timestamp manipulation."
                })
        except Exception:
            pass

        # 3. Image specific forensic warnings
        if image_meta is not None:
            if not image_meta.get("dpi"):
                warnings.append("Forensic Warning: No DPI resolution information present in image metadata.")
                forensic_findings.append({
                    "id": "IMG001",
                    "severity": "LOW",
                    "category": "Image Metadata",
                    "finding": "Missing DPI resolution information",
                    "recommendation": "Inspect image structure for possible screenshot or digital canvas crop."
                })
            if not image_meta.get("exif") or len(image_meta.get("exif", {})) == 0:
                warnings.append("Forensic Warning: Missing EXIF metadata tags in image.")
                forensic_findings.append({
                    "id": "IMG002",
                    "severity": "LOW",
                    "category": "Image Metadata",
                    "finding": "Missing EXIF metadata tags",
                    "recommendation": "Verify image source; stripped EXIF tags may indicate resaved, generated, or edited images."
                })

        # 4. PDF specific forensic warnings
        if pdf_meta is not None:
            if not pdf_meta.get("title"):
                warnings.append("Forensic Warning: PDF title metadata field is empty or missing.")
                forensic_findings.append({
                    "id": "PDF001",
                    "severity": "LOW",
                    "category": "PDF Metadata",
                    "finding": "PDF title field is empty or missing",
                    "recommendation": "Inspect document properties for complete authoring metadata."
                })
            if not pdf_meta.get("author"):
                warnings.append("Forensic Warning: PDF author metadata field is empty or missing.")
                forensic_findings.append({
                    "id": "PDF002",
                    "severity": "LOW",
                    "category": "PDF Metadata",
                    "finding": "PDF author field is empty or missing",
                    "recommendation": "Verify document provenance and authoring history."
                })
            if not pdf_meta.get("creation_date"):
                warnings.append("Forensic Warning: PDF creation date header is missing.")
                forensic_findings.append({
                    "id": "PDF003",
                    "severity": "MEDIUM",
                    "category": "PDF Metadata",
                    "finding": "PDF creation date header is missing",
                    "recommendation": "Check if PDF header was modified or stripped by PDF editing software."
                })
            if not pdf_meta.get("producer"):
                warnings.append("Forensic Warning: PDF producer metadata field is missing.")
                forensic_findings.append({
                    "id": "PDF004",
                    "severity": "LOW",
                    "category": "PDF Metadata",
                    "finding": "PDF producer software field is missing",
                    "recommendation": "Inspect PDF header structure for custom or non-standard PDF generators."
                })
