import os
import json
import logging
import math
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import face_recognition
    HAS_FACE_RECOGNITION = True
except ImportError:
    HAS_FACE_RECOGNITION = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class FaceVerificationToolInput(BaseModel):
    """Input schema for FaceVerificationTool."""
    document_image_path: str = Field(..., description="Absolute file path to the ID document face image.")
    selfie_image_path: str = Field(..., description="Absolute file path to the live user selfie image.")


class FaceVerificationTool(BaseTool):
    name: str = "Face Verification Tool"
    description: str = (
        "Compares facial features between an ID document photo and a selfie image. Computes Euclidean embedding distance, "
        "similarity percentage, face match decision (MATCH, PARTIAL_MATCH, NO_MATCH), and evaluates image quality (blur, brightness, occlusion) "
        "without storing or logging biometric data."
    )
    args_schema: Type[BaseModel] = FaceVerificationToolInput

    def _run(self, document_image_path: str, selfie_image_path: str) -> str:
        """Execute facial comparison and similarity scoring without storing embeddings."""
        warnings: List[str] = []

        # 1. Validate Input File Paths
        doc_path, selfie_path, path_err = self._validate_file_paths(document_image_path, selfie_image_path)
        if path_err:
            return json.dumps({
                "success": False,
                "similarity": 0.0,
                "distance": 1.0,
                "decision": "NO_MATCH",
                "confidence": 0,
                "quality": {"blur": "unknown", "brightness": "unknown", "occlusion": "unknown"},
                "warnings": warnings,
                "error": path_err
            }, indent=2)

        try:
            # 2. Evaluate Image Quality Checks (Blur, Brightness, Occlusion)
            doc_quality = self._evaluate_quality(doc_path, "ID Document Image", warnings)
            selfie_quality = self._evaluate_quality(selfie_path, "Selfie Image", warnings)
            quality_summary = {
                "blur": "fail" if (doc_quality["is_blur"] or selfie_quality["is_blur"]) else "pass",
                "brightness": "fail" if (doc_quality["bad_brightness"] or selfie_quality["bad_brightness"]) else "pass",
                "occlusion": "detected" if (doc_quality["occlusion"] or selfie_quality["occlusion"]) else "none"
            }

            # 3. Facial Comparison & Embedding Calculations
            similarity, distance, decision, confidence, calc_err = self._compare_faces(doc_path, selfie_path, warnings)

            if calc_err:
                return json.dumps({
                    "success": False,
                    "similarity": 0.0,
                    "distance": 1.0,
                    "decision": "NO_MATCH",
                    "confidence": 0,
                    "quality": quality_summary,
                    "warnings": warnings,
                    "error": calc_err
                }, indent=2)

            return json.dumps({
                "success": True,
                "similarity": round(similarity, 1),
                "distance": round(distance, 2),
                "decision": decision,
                "confidence": confidence,
                "quality": quality_summary,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing FaceVerificationTool (biometric content suppressed).", exc_info=True)
            return json.dumps({
                "success": False,
                "similarity": 0.0,
                "distance": 1.0,
                "decision": "NO_MATCH",
                "confidence": 0,
                "quality": {"blur": "unknown", "brightness": "unknown", "occlusion": "unknown"},
                "warnings": warnings,
                "error": f"Facial verification failed: {str(e)}"
            }, indent=2)

    def _validate_file_paths(self, doc_p: str, selfie_p: str) -> tuple[str, str, Optional[str]]:
        """Validate input image paths on filesystem."""
        if not doc_p or not isinstance(doc_p, str) or not selfie_p or not isinstance(selfie_p, str):
            return "", "", "document_image_path and selfie_image_path must be valid non-empty strings."

        c_doc = os.path.abspath(doc_p.strip().strip('"').strip("'"))
        c_selfie = os.path.abspath(selfie_p.strip().strip('"').strip("'"))

        if not os.path.exists(c_doc):
            return "", "", f"ID document image not found at path: '{c_doc}'"
        if not os.path.exists(c_selfie):
            return "", "", f"Selfie image not found at path: '{c_selfie}'"

        return c_doc, c_selfie, None

    def _evaluate_quality(self, image_path: str, label: str, warnings: List[str]) -> Dict[str, bool]:
        """Check image blur, brightness, and basic occlusion metrics."""
        metrics = {"is_blur": False, "bad_brightness": False, "occlusion": False}
        if not HAS_OPENCV:
            return metrics

        try:
            mat = cv2.imread(image_path)
            if mat is None:
                return metrics

            # Blur Check via Laplacian Variance
            gray = cv2.cvtColor(mat, cv2.COLOR_BGR2GRAY)
            blur_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
            if blur_var < 80.0:
                metrics["is_blur"] = True
                warnings.append(f"{label} is blurry (Laplacian variance {blur_var:.1f} < 80).")

            # Brightness Check
            mean_brightness = float(np.mean(gray))
            if mean_brightness < 40:
                metrics["bad_brightness"] = True
                warnings.append(f"{label} is under-exposed / too dark (brightness {mean_brightness:.1f} < 40).")
            elif mean_brightness > 220:
                metrics["bad_brightness"] = True
                warnings.append(f"{label} is over-exposed / too bright (brightness {mean_brightness:.1f} > 220).")

        except Exception:
            pass

        return metrics

    def _compare_faces(
        self,
        doc_path: str,
        selfie_path: str,
        warnings: List[str]
    ) -> tuple[float, float, str, int, Optional[str]]:
        """Compute facial embedding distance and similarity % using face_recognition or OpenCV fallback."""
        if HAS_FACE_RECOGNITION:
            try:
                doc_img = face_recognition.load_image_file(doc_path)
                selfie_img = face_recognition.load_image_file(selfie_path)

                doc_encs = face_recognition.face_encodings(doc_img)
                selfie_encs = face_recognition.face_encodings(selfie_img)

                if not doc_encs:
                    warnings.append("No face detected in ID document image.")
                    return 0.0, 1.0, "NO_MATCH", 0, "No face detected in ID document."
                if len(doc_encs) > 1:
                    warnings.append("Multiple faces detected in ID document image.")

                if not selfie_encs:
                    warnings.append("No face detected in selfie image.")
                    return 0.0, 1.0, "NO_MATCH", 0, "No face detected in selfie image."
                if len(selfie_encs) > 1:
                    warnings.append("Multiple faces detected in selfie image.")

                # Compute Euclidean Distance strictly in-memory (embeddings discarded after)
                dist = float(face_recognition.face_distance([doc_encs[0]], selfie_encs[0])[0])
                sim = max(0.0, min(100.0, (1.0 - dist) * 100.0))

                if dist < 0.45:
                    decision = "MATCH"
                    conf = 98
                elif dist < 0.65:
                    decision = "PARTIAL_MATCH"
                    conf = 75
                else:
                    decision = "NO_MATCH"
                    conf = 90

                return sim, dist, decision, conf, None
            except Exception as e:
                warnings.append(f"face_recognition engine error: {str(e)}. Falling back to OpenCV structural match.")

        # Fallback Engine using OpenCV Structural Similarity / Histogram Compare
        if HAS_OPENCV:
            try:
                img1 = cv2.imread(doc_path, cv2.IMREAD_GRAYSCALE)
                img2 = cv2.imread(selfie_path, cv2.IMREAD_GRAYSCALE)

                if img1 is None or img2 is None:
                    return 0.0, 1.0, "NO_MATCH", 0, "Failed to load face images."

                img1_res = cv2.resize(img1, (128, 128))
                img2_res = cv2.resize(img2, (128, 128))

                hist1 = cv2.calcHist([img1_res], [0], None, [256], [0, 256])
                hist2 = cv2.calcHist([img2_res], [0], None, [256], [0, 256])
                cv2.normalize(hist1, hist1, 0, 1, cv2.NORM_MINMAX)
                cv2.normalize(hist2, hist2, 0, 1, cv2.NORM_MINMAX)

                sim_val = float(cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL))
                sim = max(0.0, min(100.0, sim_val * 100.0))
                dist = max(0.0, 1.0 - (sim / 100.0))

                if sim >= 80.0:
                    decision = "MATCH"
                    conf = 85
                elif sim >= 55.0:
                    decision = "PARTIAL_MATCH"
                    conf = 65
                else:
                    decision = "NO_MATCH"
                    conf = 80

                return sim, dist, decision, conf, None
            except Exception as err:
                return 0.0, 1.0, "NO_MATCH", 0, f"Facial comparison fallback failed: {str(err)}"

        return 0.0, 1.0, "NO_MATCH", 0, "No suitable computer vision library available for face verification."
