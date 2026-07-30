import os
import json
import unittest
from cyberverse.tools.identity.document_verification_tool import DocumentVerificationTool
from cyberverse.tools.identity.face_verification_tool import FaceVerificationTool
from cyberverse.tools.identity.liveness_detection_tool import LivenessDetectionTool
from cyberverse.tools.identity.identity_consistency_tool import IdentityConsistencyTool
from cyberverse.tools.identity.identity_risk_tool import IdentityRiskTool

class TestIdentityVerificationEndToEnd(unittest.TestCase):
    def setUp(self):
        self.doc_tool = DocumentVerificationTool()
        self.face_tool = FaceVerificationTool()
        self.liveness_tool = LivenessDetectionTool()
        self.consistency_tool = IdentityConsistencyTool()
        self.risk_tool = IdentityRiskTool()

    def test_end_to_end_identity_verification_workflow(self):
        """End-to-End integration test for Identity Verification Specialist workflow."""
        # Create temporary valid test image
        from PIL import Image, ImageDraw
        test_img_path = "test_face.png"
        img = Image.new('RGB', (640, 480), color=(200, 200, 200))
        d = ImageDraw.Draw(img)
        d.ellipse([270, 190, 370, 290], fill=(150, 100, 80)) # Mock face
        img.save(test_img_path)

        try:
            print("\n=== STEP 1: Executing DocumentVerificationTool ===")
            doc_res_str = self.doc_tool._run(document_path=test_img_path)
            doc_res = json.loads(doc_res_str)
            self.assertTrue(doc_res["success"])
            print(f"Document Type: {doc_res['document_type']}, Authenticity Score: {doc_res['authenticity_score']}/100")

            print("\n=== STEP 2: Executing FaceVerificationTool ===")
            face_res_str = self.face_tool._run(document_image_path=test_img_path, selfie_image_path=test_img_path)
            face_res = json.loads(face_res_str)
            self.assertTrue(face_res["success"])
            print(f"Face Decision: {face_res['decision']}, Similarity: {face_res['similarity']}%, Distance: {face_res['distance']}")

            print("\n=== STEP 3: Executing LivenessDetectionTool ===")
            liveness_res_str = self.liveness_tool._run(selfie_image_path=test_img_path)
            liveness_res = json.loads(liveness_res_str)
            self.assertTrue(liveness_res["success"])
            print(f"Liveness Classification: {liveness_res['classification']}, Score: {liveness_res['liveness_score']}/100")

            print("\n=== STEP 4: Executing IdentityConsistencyTool ===")
            consistency_res_str = self.consistency_tool._run(
                document_json=doc_res_str,
                face_json=face_res_str,
                liveness_json=liveness_res_str
            )
            consistency_res = json.loads(consistency_res_str)
            self.assertTrue(consistency_res["success"])
            print(f"Consistency Decision: {consistency_res['decision']}, Score: {consistency_res['consistency_score']}/100")

            print("\n=== STEP 5: Executing IdentityRiskTool Synthesis ===")
            risk_res_str = self.risk_tool._run(
                document_json=doc_res_str,
                face_json=face_res_str,
                liveness_json=liveness_res_str,
                consistency_json=consistency_res_str
            )
            risk_res = json.loads(risk_res_str)
            self.assertTrue(risk_res["success"])
            print(f"Verification Status: {risk_res['verification_status']}")
            print(f"Overall Risk: {risk_res['overall_risk']}")
            print(f"Identity Score: {risk_res['identity_score']}/100")

            print("\n========================================================")
            print("FINAL ENTERPRISE IDENTITY VERIFICATION REPORT JSON")
            print("========================================================")
            final_report = {
                "specialist": "Identity Verification Specialist",
                "verification_status": risk_res["verification_status"],
                "overall_risk": risk_res["overall_risk"],
                "identity_score": risk_res["identity_score"],
                "confidence": risk_res["confidence"],
                "dashboard": risk_res["dashboard"],
                "evidence": risk_res["evidence"],
                "recommendations": risk_res["recommendations"],
                "executive_summary": risk_res["executive_summary"]
            }
            print(json.dumps(final_report, indent=2))
        finally:
            if os.path.exists(test_img_path):
                os.remove(test_img_path)

if __name__ == "__main__":
    unittest.main()
