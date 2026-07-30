import os
import sys
import json

# Ensure src is on sys.path
workspace_dir = r"d:\Downloads\cybercrew"
sys.path.insert(0, os.path.join(workspace_dir, "src"))

from dotenv import load_dotenv
load_dotenv(os.path.join(workspace_dir, ".env"))

from PIL import Image, ImageDraw, ImageFont
from cyberverse.crew import CyberverseCrew
from cyberverse.tools.ocr_tool import OCRTool


def create_sample_certificate(filepath: str) -> str:
    """Generate a clean synthetic certificate image for integration testing."""
    width, height = 800, 500
    image = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)

    # Draw border
    draw.rectangle([20, 20, width - 20, height - 20], outline=(0, 51, 102), width=5)
    draw.rectangle([30, 30, width - 30, height - 30], outline=(204, 153, 0), width=2)

    certificate_lines = [
        "DIGITAL SSL/TLS CERTIFICATE OF AUTHENTICITY",
        "---------------------------------------------------",
        "Subject: ACME Enterprise Solutions Inc.",
        "Issuer: GlobalSign RSA OV SSL CA 2026",
        "Valid From: 2025-01-15 00:00:00 UTC",
        "Valid To: 2026-01-15 23:59:59 UTC",
        "Serial Number: 7F:3A:90:B2:81:4C:9E",
        "Signature Algorithm: sha256WithRSAEncryption",
        "Public Key: RSA 2048 bits",
        "Status: VERIFIED GENUINE CERTIFICATE",
    ]

    y_offset = 60
    for line in certificate_lines:
        draw.text((60, y_offset), line, fill=(0, 0, 0))
        y_offset += 38

    image.save(filepath)
    return filepath


def run_integration_test():
    scratch_dir = os.path.join(workspace_dir, "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    sample_path = os.path.abspath(os.path.join(scratch_dir, "sample_certificate.png"))

    print("=== Step 1: Generating Sample Certificate Image ===")
    create_sample_certificate(sample_path)
    print(f"Sample certificate saved at: {sample_path}")

    print("\n=== Step 2: Directly Executing OCRTool ===")
    ocr_tool = OCRTool()
    ocr_json_output = ocr_tool._run(sample_path)
    print("OCRTool Raw Output JSON:")
    print(ocr_json_output)

    ocr_result = json.loads(ocr_json_output)
    assert ocr_result.get("success") is True, "OCR Tool execution failed!"
    print(f"\nOCR Extracted Text:\n{ocr_result.get('extracted_text')}")
    print(f"OCR Confidence: {ocr_result.get('confidence')}")

    print("\n=== Step 3: Executing Certificate Verification Specialist Agent ===")
    crew = CyberverseCrew()
    agent = crew.certificate_verification_specialist()

    prompt = (
        f"Inspect and verify the uploaded digital certificate located at file path: '{sample_path}'. "
        f"Use the OCR Tool to extract text from the file, analyze the subject, issuer, serial number, "
        f"validity period, and signature algorithm, and output a structured security report."
    )

    print(f"Kickoff Prompt:\n{prompt}\n")
    agent_output = agent.kickoff(prompt)

    print("\n=== Step 4: Final Agent Response ===")
    print(agent_output.raw)


if __name__ == "__main__":
    run_integration_test()
