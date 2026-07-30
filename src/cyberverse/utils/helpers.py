def mask_string(val: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Mask string content keeping initial and ending characters exposed."""
    if not val:
        return ""
    length = len(val)
    if length <= (keep_start + keep_end):
        return val[:2] + "..." + val[-2:] if length > 4 else "..."
    return f"{val[:keep_start]}...{val[-keep_end:]}"
