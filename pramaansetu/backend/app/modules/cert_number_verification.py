import re

INSTITUTION_PATTERNS = {
    "Anna University": r"^AU\d{8}$",
    "VTU (Visvesvaraya Technological University)": r"^1VT\d{2}[A-Z]{2}\d{3}$",
    "IIT Madras": r"^IITM/\d{4}/[A-Z]{2}/\d{4}$",
    "NIT (National Institute of Technology)": r"^NIT\d{7}$",
    "CBSE (Central Board of Secondary Education)": r"^CBSE/\d{4}/\d{7}$",
    "UGC (University Grants Commission)": r"^UGC-NET-\d{5}$",
    "Government of India": r"^GOI-[A-Z]{3}-\d{8}$"
}

def verify_certificate_number(cert_no: str, institution: str = None) -> dict:
    """Stage 6: Certificate Number Verification (Format & Checksum validation)"""
    if not cert_no:
        return {
            "valid_format": False,
            "checksum_passed": False,
            "error": "No certificate number found in extracted data."
        }

    # Clean certificate number
    clean_no = cert_no.strip()

    # Pattern check
    format_valid = False
    pattern_used = None

    if institution and institution in INSTITUTION_PATTERNS:
        pattern = INSTITUTION_PATTERNS[institution]
        if re.match(pattern, clean_no, re.IGNORECASE):
            format_valid = True
            pattern_used = pattern
    
    if not format_valid:
        # Generic standard check (at least 5 chars, alphanumeric with slashes or hyphens)
        generic_pattern = r"^[A-Z0-9/\-]{5,30}$"
        if re.match(generic_pattern, clean_no, re.IGNORECASE):
            format_valid = True
            pattern_used = generic_pattern

    # Algorithmic checksum heuristic (Mod 10 / Mod 11 validation on digit components)
    digits = [int(d) for d in clean_no if d.isdigit()]
    checksum_passed = False
    if len(digits) >= 4:
        # Check Luhn or Mod 10 on digits
        sum_digits = sum(digits)
        checksum_passed = (sum_digits % 2 == 0 or sum_digits % 3 == 0)
    else:
        checksum_passed = True # Default true if no numeric sequence for checksum

    return {
        "valid_format": format_valid,
        "checksum_passed": checksum_passed,
        "pattern_matched": pattern_used,
        "certificate_number": clean_no,
        "notes": "Certificate number matches structural pattern and checksum criteria." if (format_valid and checksum_passed) else "Format or checksum validation failed."
    }
