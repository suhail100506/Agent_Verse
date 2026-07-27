import os
from PIL import Image, ImageDraw, ImageFont

def generate_sample_anna_univ_cert(output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Create white canvas
    img = Image.new('RGB', (1000, 1300), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Draw border
    draw.rectangle([(20, 20), (980, 1280)], outline=(11, 19, 43), width=5)
    draw.rectangle([(30, 30), (970, 1270)], outline=(255, 159, 28), width=2)

    # Institution Name Header
    draw.text((350, 80), "ANNA UNIVERSITY", fill=(11, 19, 43))
    draw.text((410, 120), "CHENNAI - 600 025", fill=(60, 60, 60))

    # Certificate Title
    draw.text((380, 220), "DEGREE CERTIFICATE", fill=(11, 19, 43))

    # Certification Body Text
    body_text = (
        "This is to certify that\n\n"
        "SATHISH KUMAR R\n\n"
        "has qualified for the Degree of\n\n"
        "BACHELOR OF ENGINEERING\n\n"
        "in COMPUTER SCIENCE AND ENGINEERING\n\n"
        "with FIRST CLASS WITH DISTINCTION at the Examination held in MAY 2024."
    )
    draw.multiline_text((220, 320), body_text, fill=(30, 30, 30), align="center", spacing=15)

    # Certificate Details
    draw.text((80, 850), "Certificate No: AU12345678", fill=(11, 19, 43))
    draw.text((80, 890), "Date of Issue: 15-JUN-2024", fill=(30, 30, 30))
    draw.text((80, 930), "CGPA: 8.95 / 10.0", fill=(30, 30, 30))

    # Emblem / Logo representation
    draw.ellipse([(450, 1000), (550, 1100)], outline=(11, 19, 43), width=3)
    draw.text((465, 1040), "SEAL", fill=(11, 19, 43))

    # Signature line
    draw.line([(700, 1080), (900, 1080)], fill=(30, 30, 30), width=2)
    draw.text((740, 1090), "REGISTRAR", fill=(11, 19, 43))

    img.save(output_path)
    print(f"Sample certificate image created at: {output_path}")

if __name__ == "__main__":
    generate_sample_anna_univ_cert("backend/uploads/sample_anna_univ_cert.png")
