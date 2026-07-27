from datetime import datetime

SEED_TEMPLATES = [
    {
        "institution_name": "Anna University",
        "reference_logo_path": "templates_library/anna_univ_logo.png",
        "reference_seal_path": "templates_library/anna_univ_seal.png",
        "layout_coordinates": {
            "logo_bbox": [50, 40, 150, 140],
            "seal_bbox": [650, 750, 800, 900],
            "signature_bbox": [600, 850, 800, 950],
            "cert_number_bbox": [700, 50, 900, 90]
        },
        "font_signature": "Times-Bold, Arial",
        "cert_number_pattern": r"^AU\d{8}$"
    },
    {
        "institution_name": "VTU (Visvesvaraya Technological University)",
        "reference_logo_path": "templates_library/vtu_logo.png",
        "reference_seal_path": "templates_library/vtu_seal.png",
        "layout_coordinates": {
            "logo_bbox": [60, 50, 160, 150],
            "seal_bbox": [600, 700, 750, 850],
            "signature_bbox": [580, 800, 780, 920],
            "cert_number_bbox": [650, 60, 850, 100]
        },
        "font_signature": "Calibri, Helvetica",
        "cert_number_pattern": r"^1VT\d{2}[A-Z]{2}\d{3}$"
    },
    {
        "institution_name": "IIT Madras",
        "reference_logo_path": "templates_library/iit_madras_logo.png",
        "reference_seal_path": "templates_library/iit_madras_seal.png",
        "layout_coordinates": {
            "logo_bbox": [40, 30, 180, 170],
            "seal_bbox": [700, 700, 850, 850],
            "signature_bbox": [650, 820, 850, 950],
            "cert_number_bbox": [750, 40, 920, 80]
        },
        "font_signature": "Georgia, Times New Roman",
        "cert_number_pattern": r"^IITM/\d{4}/[A-Z]{2}/\d{4}$"
    },
    {
        "institution_name": "NIT (National Institute of Technology)",
        "reference_logo_path": "templates_library/nit_logo.png",
        "reference_seal_path": "templates_library/nit_seal.png",
        "layout_coordinates": {
            "logo_bbox": [50, 50, 150, 150],
            "seal_bbox": [650, 720, 800, 870],
            "signature_bbox": [600, 830, 800, 940],
            "cert_number_bbox": [700, 50, 900, 90]
        },
        "font_signature": "Arial, Georgia",
        "cert_number_pattern": r"^NIT\d{7}$"
    },
    {
        "institution_name": "CBSE (Central Board of Secondary Education)",
        "reference_logo_path": "templates_library/cbse_logo.png",
        "reference_seal_path": "templates_library/cbse_seal.png",
        "layout_coordinates": {
            "logo_bbox": [400, 40, 500, 140],
            "seal_bbox": [680, 750, 820, 890],
            "signature_bbox": [620, 840, 820, 960],
            "cert_number_bbox": [50, 50, 250, 90]
        },
        "font_signature": "Verdana, Arial",
        "cert_number_pattern": r"^CBSE/\d{4}/\d{7}$"
    },
    {
        "institution_name": "UGC (University Grants Commission)",
        "reference_logo_path": "templates_library/ugc_logo.png",
        "reference_seal_path": "templates_library/ugc_seal.png",
        "layout_coordinates": {
            "logo_bbox": [420, 30, 520, 130],
            "seal_bbox": [700, 720, 840, 860],
            "signature_bbox": [650, 830, 850, 950],
            "cert_number_bbox": [50, 60, 280, 100]
        },
        "font_signature": "Times-Bold, Georgia",
        "cert_number_pattern": r"^UGC-NET-\d{5}$"
    },
    {
        "institution_name": "Government of India",
        "reference_logo_path": "templates_library/goi_logo.png",
        "reference_seal_path": "templates_library/goi_seal.png",
        "layout_coordinates": {
            "logo_bbox": [430, 20, 530, 120],
            "seal_bbox": [710, 710, 850, 850],
            "signature_bbox": [660, 820, 860, 940],
            "cert_number_bbox": [60, 40, 300, 80]
        },
        "font_signature": "Times New Roman, Arial",
        "cert_number_pattern": r"^GOI-[A-Z]{3}-\d{8}$"
    }
]

async def seed_template_library(db):
    for tpl in SEED_TEMPLATES:
        existing = await db.template_library.find_one({"institution_name": tpl["institution_name"]})
        if not existing:
            doc = {**tpl, "updated_at": datetime.utcnow()}
            await db.template_library.insert_one(doc)
