import os
import fitz # PyMuPDF
from PIL import Image, ExifTags

KNOWN_TAMPERING_SOFTWARE = [
    "photoshop", "gimp", "canva", "illustrator", "inkscape",
    "pdf2image", "paint.net", "coreldraw", "pdfescape", "sejda"
]

def analyze_metadata(file_path: str) -> dict:
    """Stage 11: Metadata Analysis (Author, Software, Creation & Mod dates, Editing Risk Flags)"""
    author = ""
    software = ""
    creation_date = ""
    modification_date = ""
    risk_flag = False
    risk_reasons = []

    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".pdf":
        try:
            doc = fitz.open(file_path)
            meta = doc.metadata
            author = meta.get("author", "") or ""
            producer = meta.get("producer", "") or ""
            creator = meta.get("creator", "") or ""
            creation_date = meta.get("creationDate", "") or ""
            modification_date = meta.get("modDate", "") or ""
            software = f"{creator} | {producer}".strip(" |")

            # Risk check on software
            soft_lower = software.lower()
            for sw in KNOWN_TAMPERING_SOFTWARE:
                if sw in soft_lower:
                    risk_flag = True
                    risk_reasons.append(f"Edited with graphics software: {sw}")

            # Risk check on creation vs modification
            if creation_date and modification_date and creation_date != modification_date:
                risk_reasons.append("Modification date differs from creation date.")

            doc.close()
        except Exception as e:
            risk_reasons.append(f"Failed to extract PDF metadata: {str(e)}")

    else: # Image file
        try:
            with Image.open(file_path) as img:
                exif_data = img._getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        if tag == "Software":
                            software = str(value)
                            if any(sw in software.lower() for sw in KNOWN_TAMPERING_SOFTWARE):
                                risk_flag = True
                                risk_reasons.append(f"EXIF Software tag contains: {software}")
                        elif tag == "DateTimeOriginal":
                            creation_date = str(value)
                        elif tag == "DateTime":
                            modification_date = str(value)
                        elif tag == "Artist" or tag == "XPAuthor":
                            author = str(value)
        except Exception:
            pass

    return {
        "author": author,
        "software": software,
        "creation_date": creation_date,
        "modification_date": modification_date,
        "risk_flag": risk_flag,
        "risk_reasons": risk_reasons,
        "notes": "Metadata analyzed. " + ("; ".join(risk_reasons) if risk_reasons else "No suspicious graphics editing flags detected.")
    }
