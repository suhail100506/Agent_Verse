from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import llm_reasoning

class AIReasoningAgent(BaseVerificationAgent):
    """
    Agent 8: AI Reasoning & Forensic Anomaly Agent
    Synthesizes findings across all verification agents using deep LLM reasoning to explain anomalies and generate expert conclusions.
    """
    def __init__(self):
        super().__init__(
            agent_name="AI Reasoning & Forensic Anomaly Agent",
            agent_id="agent_8_ai_reasoning",
            description="Aggregates multi-agent signals and generates LLM-powered forensic audit narrative."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        stage_results = context.get("stage_results", {})
        extracted_data = context.get("extracted_data", {})
        overall_score = context.get("overall_score", 0.0)

        self.log_info("Generating LLM forensic reasoning analysis...")

        ai_reasoning_text = ""
        try:
            ai_reasoning_text = await llm_reasoning.generate_ai_reasoning(stage_results, extracted_data, overall_score)
        except Exception as e:
            self.log_error("AI reasoning generation failed", e)
            ai_reasoning_text = f"Forensic reasoning agent encountered an error: {str(e)}"

        return {
            "ai_reasoning": ai_reasoning_text
        }
