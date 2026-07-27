import hashlib
import os
import fitz # PyMuPDF
from PIL import Image

def validate_file(file_path: str, max_size_mb: int = 15) -> dict:
    """Stage 1: File Validation"""
    if not os.path.exists(file_path):
        return {"passed": False, "error": "File does not exist on disk", "file_hash": None}

    file_size = os.path.getsize(file_path)
    if file_size > max_size_mb * 1024 * 1024:
        return {
            "passed": False,
            "error": f"File size ({file_size / (1024*1024):.2f}MB) exceeds limit of {max_size_mb}MB",
            "file_hash": None
        }

    # Calculate SHA256 Hash
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    hash_str = sha256_hash.hexdigest()

    # Format verification
    ext = os.path.splitext(file_path)[1].lower()
    valid_extensions = [".pdf", ".png", ".jpg", ".jpeg"]
    if ext not in valid_extensions:
        return {"passed": False, "error": f"Unsupported file extension {ext}", "file_hash": hash_str}

    # Integrity check
    try:
        if ext == ".pdf":
            doc = fitz.open(file_path)
            if len(doc) == 0:
                return {"passed": False, "error": "PDF has 0 pages", "file_hash": hash_str}
            doc.close()
        else:
            with Image.open(file_path) as img:
                img.verify()
    except Exception as e:
        return {"passed": False, "error": f"Corrupt file structure: {str(e)}", "file_hash": hash_str}

    return {
        "passed": True,
        "file_size": file_size,
        "file_hash": hash_str,
        "file_type": ext.lstrip("."),
        "notes": "File validation & SHA256 integrity check passed successfully."
    }
