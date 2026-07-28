import sys
import os
import unittest
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.agents import (
    BaseVerificationAgent,
    IngestionAgent,
    OCRParsingAgent,
    VisualLayoutAgent,
    MetadataForensicsAgent,
    TamperingDetectionAgent,
    SecurityElementAgent,
    AuthorityRegistryAgent,
    AIReasoningAgent,
    DecisionSynthesisAgent,
    MultiAgentOrchestrator
)

class TestMultiAgentArchitecture(unittest.TestCase):

    def test_agent_instantiation(self):
        agents = [
            IngestionAgent(),
            OCRParsingAgent(),
            VisualLayoutAgent(),
            MetadataForensicsAgent(),
            TamperingDetectionAgent(),
            SecurityElementAgent(),
            AuthorityRegistryAgent(),
            AIReasoningAgent(),
            DecisionSynthesisAgent()
        ]
        
        self.assertEqual(len(agents), 9)
        for idx, agent in enumerate(agents, start=1):
            self.assertIsInstance(agent, BaseVerificationAgent)
            self.assertTrue(agent.agent_id.startswith(f"agent_{idx}_"))

    def test_orchestrator_initialization(self):
        orchestrator = MultiAgentOrchestrator()
        self.assertIsNotNone(orchestrator.agent_1_ingestion)
        self.assertIsNotNone(orchestrator.agent_2_ocr)
        self.assertIsNotNone(orchestrator.agent_3_visual)
        self.assertIsNotNone(orchestrator.agent_4_metadata)
        self.assertIsNotNone(orchestrator.agent_5_tampering)
        self.assertIsNotNone(orchestrator.agent_6_security)
        self.assertIsNotNone(orchestrator.agent_7_authority)
        self.assertIsNotNone(orchestrator.agent_8_ai_reasoning)
        self.assertIsNotNone(orchestrator.agent_9_decision)

    def test_agent_process_mock_flow(self):
        async def run_test():
            ingestion = IngestionAgent()
            ctx = {"file_path": "nonexistent.jpg", "temp_dir": "./temp"}
            res = await ingestion.process(ctx)
            self.assertIn("validation", res)
            self.assertIn("preprocessing", res)
        
        asyncio.run(run_test())

if __name__ == "__main__":
    unittest.main()
