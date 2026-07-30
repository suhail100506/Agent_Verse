import os
from typing import Optional

def load_text_file(file_path: str) -> Optional[str]:
    """Safely load text content from a specified file path."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None
