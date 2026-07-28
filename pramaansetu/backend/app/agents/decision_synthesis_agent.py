from typing import Dict, Any
from app.agents.base_agent import BaseVerificationAgent
from app.modules import scoring, classification, recommendation, report_generation
from app.config import settings

class DecisionSynthesisAgent(BaseVerificationAgent):
    """
    Agent 9: Decision Synthesis & Scoring Agent
    Calculates weighted authenticity scores, determines classification status, generates actionable advice, and creates the PDF report.
    """
    def __init__(self):
        super().__init__(
            agent_name="Decision Synthesis & Scoring Agent",
            agent_id="agent_9_decision_synthesis",
            description="Aggregates agent evidence, computes final authenticity score, classifies risk, and generates PDF verification report."
        )

    async def process(self, context: Dict[str, Any]) -> Dict[str, Any]:
        stage_results = context.get("stage_results", {})
        extracted_data = context.get("extracted_data", {})
        ai_reasoning = context.get("ai_reasoning", "")
        rec_obj_id = context.get("rec_obj_id")

        self.log_info("Calculating authenticity score metrics...")
        score_obj = scoring.calculate_authenticity_score(stage_results)
        overall_score = score_obj["overall_score"]

        self.log_info(f"Classifying status for overall score: {overall_score}")
        final_classification = classification.classify_certificate(overall_score, stage_results)

        self.log_info(f"Generating recommendation for status: {final_classification}")
        final_recommendation = recommendation.generate_recommendation(final_classification, stage_results)

        self.log_info("Compiling PDF verification report...")
        part_doc = {
            "_id": str(rec_obj_id),
            "classification": final_classification,
            "authenticity_score": score_obj,
            "extracted_data": extracted_data,
            "ai_reasoning": ai_reasoning,
            "recommendation": final_recommendation,
            "stage_results": stage_results
        }

        report_pdf_path = ""
        try:
            report_pdf_path = report_generation.generate_pdf_report(part_doc, settings.REPORT_DIR)
        except Exception as e:
            self.log_error("Report PDF generation failed", e)

        return {
            "score_obj": score_obj,
            "overall_score": overall_score,
            "classification": final_classification,
            "recommendation": final_recommendation,
            "report_pdf_path": report_pdf_path
        }
