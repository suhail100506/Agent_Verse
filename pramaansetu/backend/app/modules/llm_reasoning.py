import json
import logging
from app.config import settings

logger = logging.getLogger(__name__)

EXACT_SYSTEM_PROMPT = """You are an expert forensic document examiner analyzing a certificate verification pipeline's output.

You will receive structured JSON containing OCR text, QR results, logo match %, seal confidence,
template similarity, metadata flags, and tampering indicators.

Your task:
1. State clearly why the certificate appears genuine (cite specific evidence fields).
2. State clearly why the certificate appears suspicious (cite specific evidence fields).
3. Never hallucinate — every claim must reference a field in the provided JSON.
4. If evidence is insufficient or contradictory, say so explicitly and recommend manual review.
5. Output plain text, 3-6 sentences, no markdown."""

async def generate_ai_reasoning(stage_results: dict, extracted_data: dict, overall_score: float) -> str:
    """Stage 14: AI Reasoning (Gemini 2.5 Flash with exact forensic system prompt)"""
    context_payload = {
        "extracted_data": extracted_data,
        "stage_results": stage_results,
        "overall_score": overall_score
    }

    prompt_text = f"{EXACT_SYSTEM_PROMPT}\n\nPipeline Output JSON:\n{json.dumps(context_payload, indent=2, default=str)}"

    if settings.GEMINI_API_KEY:
        try:
            # Try google-genai client
            from google import genai
            client = genai.Client(api_key=settings.GEMINI_API_KEY)
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt_text
            )
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            logger.warning(f"Google GenAI API call failed: {e}. Attempting fallback...")
            try:
                import google.generativeai as genai_legacy
                genai_legacy.configure(api_key=settings.GEMINI_API_KEY)
                model = genai_legacy.GenerativeModel('gemini-1.5-flash')
                res = model.generate_content(prompt_text)
                if res and res.text:
                    return res.text.strip()
            except Exception as e2:
                logger.warning(f"Legacy Gemini API call failed: {e2}")

    # Rule-Based Forensic Fallback (when API key absent or network offline)
    ocr_acc = stage_results.get("ocr", {}).get("accuracy", 0)
    qr_match = stage_results.get("qr_verification", {}).get("match", False)
    tpl_sim = stage_results.get("template_matching", {}).get("similarity_pct", 0)
    logo_match = stage_results.get("logo_verification", {}).get("match_pct", 0)
    seal_conf = stage_results.get("seal_verification", {}).get("confidence_pct", 0)
    tamp_score = stage_results.get("tampering_detection", {}).get("score", 0)
    meta_risk = stage_results.get("metadata_analysis", {}).get("risk_flag", False)

    genuine_points = []
    suspicious_points = []

    if ocr_acc > 80:
        genuine_points.append(f"OCR accuracy is high at {ocr_acc}% with clear field parsing")
    if qr_match:
        genuine_points.append("QR code verification matched certificate payload")
    if tpl_sim > 70:
        genuine_points.append(f"template similarity scored {tpl_sim}% matching standard layout")
    if logo_match > 70:
        genuine_points.append(f"logo verification confirmed emblem with {logo_match}% match")
    if seal_conf > 70:
        genuine_points.append(f"seal confidence is strong at {seal_conf}%")

    if tamp_score > 30:
        suspicious_points.append(f"tampering detection found ELA indicators scoring {tamp_score}")
    if meta_risk:
        suspicious_points.append("metadata analysis flagged suspicious editing software or date modification")
    if not qr_match and stage_results.get("qr_verification", {}).get("status") == "failed":
        suspicious_points.append("QR code was detected but payload failed field match")

    gen_str = f"The certificate appears genuine because " + ", and ".join(genuine_points) + "." if genuine_points else "The certificate presents standard structural formatting."
    sus_str = f" However, it appears suspicious because " + ", and ".join(suspicious_points) + "." if suspicious_points else " No critical forensic anomalies were detected in image metadata or surface analysis."

    return f"{gen_str}{sus_str} Overall verification score is {overall_score:.1f}%."
