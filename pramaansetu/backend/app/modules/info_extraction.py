import re

def parse_information(raw_text: str) -> dict:
    """Stage 4: Information Parsing (Regex & heuristic extraction)"""
    if not raw_text:
        return {
            "passed": False,
            "extracted_data": {
                "name": None,
                "certificate_number": None,
                "institution": None,
                "course": None,
                "date": None,
                "grade": None
            }
        }

    lines = [line.strip() for line in raw_text.split("\n") if line.strip()]
    
    # 1. Certificate Number
    cert_no = None
    cert_patterns = [
        r"(?:Certificate\s*(?:No|Number)|Serial\s*No|Reg(?:istration)?\s*No|Roll\s*No|Licence\s*No|ID)[:\s]*([A-Z0-9/\-]{5,25})",
        r"\b(AU\d{8}|1VT\d{2}[A-Z]{2}\d{3}|IITM/\d{4}/[A-Z]{2}/\d{4}|NIT\d{7}|CBSE/\d{4}/\d{7}|UGC-NET-\d{5}|GOI-[A-Z]{3}-\d{8})\b",
        r"\b([A-Z]{2,4}[/-]?\d{4,8}[/-]?[A-Z0-9]{2,6})\b"
    ]
    for pattern in cert_patterns:
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            cert_no = match.group(1).strip()
            break

    # 2. Institution Name
    institution = None
    known_institutions = [
        "Anna University", "Visvesvaraya Technological University", "VTU",
        "IIT Madras", "Indian Institute of Technology", "NIT", "National Institute of Technology",
        "CBSE", "Central Board of Secondary Education", "UGC", "University Grants Commission",
        "Government of India", "Delhi University", "Mumbai University"
    ]
    for inst in known_institutions:
        if re.search(r"\b" + re.escape(inst) + r"\b", raw_text, re.IGNORECASE):
            institution = inst
            break

    if not institution:
        for line in lines[:5]:
            if any(kw in line.lower() for kw in ["university", "institute", "board", "college", "government"]):
                institution = line
                break

    # 3. Name Parsing
    name = None
    name_match = re.search(r"(?:This\s+is\s+to\s+certify\s+that|Certifies\s+that|Awarded\s+to|Name[:\s]*)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})", raw_text)
    if name_match:
        name = name_match.group(1).strip()
    else:
        for line in lines:
            if line.isupper() and len(line.split()) in [2, 3, 4] and not any(kw in line.lower() for kw in ["university", "certificate", "degree", "bachelor", "master"]):
                name = line.title()
                break

    # 4. Course / Degree
    course = None
    course_patterns = [
        r"(Bachelor\s+of\s+[\w\s]+|Master\s+of\s+[\w\s]+|Doctor\s+of\s+[\w\s]+|B\.Tech|M\.Tech|B\.E\.|M\.E\.|B\.Sc|M\.Sc|Ph\.D|Diploma\s+in\s+[\w\s]+)",
        r"(Computer\s+Science(?:\s+and\s+Engineering)?|Mechanical\s+Engineering|Electrical\s+Engineering|Civil\s+Engineering|Information\s+Technology)"
    ]
    for pattern in course_patterns:
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            course = match.group(1).strip()
            break

    # 5. Date of Issue
    date_issue = None
    date_match = re.search(r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b", raw_text, re.IGNORECASE)
    if date_match:
        date_issue = date_match.group(1).strip()

    # 6. Grade / CGPA
    grade = None
    grade_match = re.search(r"(?:CGPA|GPA|Grade|Marks|Class)[:\s]*([0-9.]+|First\s+Class(?:\s+with\s+Distinction)?|Second\s+Class|Grade\s+[A-S]\+?)", raw_text, re.IGNORECASE)
    if grade_match:
        grade = grade_match.group(1).strip()

    extracted = {
        "name": name,
        "certificate_number": cert_no,
        "institution": institution,
        "course": course,
        "date": date_issue,
        "grade": grade
    }

    found_count = sum(1 for v in extracted.values() if v is not None)

    return {
        "passed": found_count >= 2,
        "extracted_data": extracted,
        "fields_found_count": found_count
    }
