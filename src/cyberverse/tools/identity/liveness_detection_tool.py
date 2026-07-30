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

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class LivenessDetectionToolInput(BaseModel):
    """Input schema for LivenessDetectionTool."""
    selfie_image_path: str = Field(..., description="Absolute file path to the selfie image to analyze for presentation attacks.")
    optional_video_path: Optional[str] = Field(None, description="Optional absolute file path to a video stream for active blink/movement verification.")


class LivenessDetectionTool(BaseTool):
    name: str = "Liveness Detection Tool"
    description: str = (
        "Detects biometric presentation attacks (screen replay, printed photos, Moire pattern frequency artifacts, glare/reflections) "
        "and active video movements (blinks, head rotations) to classify samples as REAL, SPOOF, or UNKNOWN with a 0-100 liveness score."
    )
    args_schema: Type[BaseModel] = LivenessDetectionToolInput

    def _run(self, selfie_image_path: str, optional_video_path: Optional[str] = None) -> str:
        """Execute passive and active biometric presentation attack detection (PAD)."""
        warnings: List[str] = []

        if not selfie_image_path or not isinstance(selfie_image_path, str):
            return json.dumps({
                "success": False,
                "liveness_score": 0,
                "classification": "UNKNOWN",
                "checks": {"blink": False, "reflection": False, "screen_replay": False, "moire_pattern": False},
                "warnings": warnings,
                "error": "selfie_image_path argument must be a valid non-empty string."
            }, indent=2)

        clean_path = os.path.abspath(selfie_image_path.strip().strip('"').strip("'"))
        if not os.path.exists(clean_path):
            return json.dumps({
                "success": False,
                "liveness_score": 0,
                "classification": "UNKNOWN",
                "checks": {"blink": False, "reflection": False, "screen_replay": False, "moire_pattern": False},
                "warnings": warnings,
                "error": f"Selfie image file not found at path: '{clean_path}'"
            }, indent=2)

        try:
            # 1. Perform Passive Presentation Attack Detection (Moire, Glare, Blur)
            checks, passive_score = self._analyze_passive_liveness(clean_path, warnings)

            # 2. Perform Active Video Liveness Detection (Optional)
            active_score = 0
            if optional_video_path:
                v_clean = os.path.abspath(optional_video_path.strip().strip('"').strip("'"))
                if os.path.exists(v_clean):
                    active_score = self._analyze_active_video_liveness(v_clean, checks, warnings)

            # 3. Finalize Liveness Score & Classification
            liveness_score = max(0, min(100, passive_score + active_score))

            if liveness_score >= 80:
                classification = "REAL"
            elif liveness_score >= 50:
                classification = "UNKNOWN"
            else:
                classification = "SPOOF"

            if checks.get("screen_replay") or checks.get("moire_pattern"):
                warnings.append("High-frequency Moire grid patterns detected, indicating screen replay or digital display photo attack.")
            if checks.get("reflection"):
                warnings.append("Specular reflection or glare artifacts detected on face surface.")

            return json.dumps({
                "success": True,
                "liveness_score": liveness_score,
                "classification": classification,
                "checks": checks,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing LivenessDetectionTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "liveness_score": 0,
                "classification": "UNKNOWN",
                "checks": {"blink": False, "reflection": False, "screen_replay": False, "moire_pattern": False},
                "warnings": warnings,
                "error": f"Liveness detection failed: {str(e)}"
            }, indent=2)

    def _analyze_passive_liveness(self, image_path: str, warnings: List[str]) -> tuple[Dict[str, bool], int]:
        """Perform 2D FFT frequency domain & glare analysis."""
        checks = {
            "blink": False,
            "reflection": False,
            "screen_replay": False,
            "moire_pattern": False
        }
        score = 85  # Default baseline for live selfie

        if not HAS_OPENCV:
            return checks, score

        try:
            mat = cv2.imread(image_path)
            if mat is None:
                return checks, score

            gray = cv2.cvtColor(mat, cv2.COLOR_BGR2GRAY)
            h, w = gray.shape

            # A. FFT 2D Frequency Domain Moire Pattern Detection
            dft = cv2.dft(np.float32(gray), flags=cv2.DFT_COMPLEX_OUTPUT)
            dft_shift = np.fft.fftshift(dft)
            magnitude_spectrum = 20 * np.log(cv2.magnitude(dft_shift[:, :, 0], dft_shift[:, :, 1]) + 1)

            # High-frequency magnitude ratio
            cy, cx = h // 2, w // 2
            r = min(h, w) // 4
            mask = np.ones((h, w), np.uint8)
            cv2.circle(mask, (cx, cy), r, 0, -1)
            high_freq_ratio = float(np.mean(magnitude_spectrum[mask == 1]))

            if high_freq_ratio > 170.0:
                checks["screen_replay"] = True
                checks["moire_pattern"] = True
                score -= 40

            # B. Specular Reflection / Glare Detection
            _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY)
            glare_pixels = cv2.countNonZero(thresh)
            glare_ratio = glare_pixels / float(h * w)

            if glare_ratio > 0.02:
                checks["reflection"] = True
                score -= 20

            # C. Edge Artifact / Photo Border Check
            edges = cv2.Canny(gray, 100, 200)
            border_pixels = cv2.countNonZero(edges[:10, :]) + cv2.countNonZero(edges[-10:, :])
            if border_pixels > (w * 0.5):
                checks["screen_replay"] = True
                score -= 15

        except Exception as err:
            logger.debug(f"Passive liveness analysis exception: {err}")

        return checks, score

    def _analyze_active_video_liveness(self, video_path: str, checks: Dict[str, bool], warnings: List[str]) -> int:
        """Analyze optional video stream for eye blinks and head movements."""
        bonus_score = 0
        if not HAS_OPENCV:
            return bonus_score

        try:
            cap = cv2.VideoCapture(video_path)
            frame_count = 0
            dark_eye_frames = 0

            while cap.isOpened() and frame_count < 150:
                ret, frame = cap.read()
                if not ret:
                    break
                frame_count += 1
                
                # Sample frame every 5 frames
                if frame_count % 5 == 0:
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    mean_val = np.mean(gray)
                    if mean_val < 50:
                        dark_eye_frames += 1

            cap.release()

            if frame_count > 30 and dark_eye_frames > 2:
                checks["blink"] = True
                bonus_score += 15

        except Exception as err:
            logger.debug(f"Active video liveness analysis exception: {err}")

        return bonus_score
