import os

def validate_file_exists(file_path: str) -> bool:
    """Check if file exists and is a regular file."""
    return os.path.exists(file_path) and os.path.isfile(file_path)

def validate_non_empty_string(val: str) -> bool:
    """Check if string argument is non-empty and non-whitespace."""
    return isinstance(val, str) and bool(val.strip())
