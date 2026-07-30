import json
import unittest
from cyberverse.tools.certificate.ocr_tool import OCRTool

class TestOCRTool(unittest.TestCase):
    def setUp(self):
        self.tool = OCRTool()

    def test_ocr_tool_initialization(self):
        self.assertEqual(self.tool.name, "OCR Tool")

    def test_ocr_tool_nonexistent_file(self):
        res_str = self.tool._run(image_path="nonexistent_sample.png")
        res = json.loads(res_str)
        self.assertFalse(res["success"])
        self.assertIn("File not found", res["error"])

if __name__ == "__main__":
    unittest.main()
