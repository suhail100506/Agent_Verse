import json
import unittest
from cyberverse.tools.certificate.metadata_tool import MetadataTool

class TestMetadataTool(unittest.TestCase):
    def setUp(self):
        self.tool = MetadataTool()

    def test_metadata_tool_initialization(self):
        self.assertEqual(self.tool.name, "Metadata Tool")

    def test_metadata_tool_nonexistent_file(self):
        res_str = self.tool._run(file_path="nonexistent_sample.png")
        res = json.loads(res_str)
        self.assertFalse(res["success"])
        self.assertIn("File not found", res["error"])

if __name__ == "__main__":
    unittest.main()
