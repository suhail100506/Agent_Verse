import os
import json
import logging
import re
from crewai import Agent, Task, Crew, Process
from src.incident_response_agent.models import IncidentResponse

logger = logging.getLogger(__name__)

async def run_incident_analysis(incident_context: dict) -> IncidentResponse:
    """Run CrewAI task to generate a full incident response based on inputs asynchronously."""
    
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")
    os.environ["GEMINI_API_KEY"] = gemini_api_key
    
    model_name = os.getenv("GEMINI_MODEL", "gemini/gemini-flash-latest")
    
    ir_analyst = Agent(
        role='Senior SOC Analyst and Incident Response Engineer',
        goal='Analyze incoming security findings and generate a structured incident response plan.',
        backstory=(
            'You are a highly experienced Cybersecurity Architect and Incident Response Engineer. '
            'You specialize in evaluating phishing and malware indicators, classifying threats, '
            'mapping to MITRE ATT&CK, and proposing concrete containment and recovery actions.'
        ),
        verbose=False,
        allow_delegation=False,
        llm=model_name
    )
    
    context_str = json.dumps(incident_context, indent=2)
    
    ir_task = Task(
        description=(
            "Analyze the following security findings.\n\n"
            f"Findings:\n{context_str}\n\n"
            "Based on these findings, you must:\n"
            "1. Classify the incident (e.g., Phishing, Business Email Compromise, Malware Infection, etc.).\n"
            "2. Determine the severity (Informational, Low, Medium, High, Critical).\n"
            "3. Assess the business impact (User Impact, Financial Risk, Data Exposure, Operational Impact).\n"
            "4. Map the attack to relevant MITRE ATT&CK techniques.\n"
            "5. Provide immediate containment actions.\n"
            "6. Provide recovery recommendations.\n"
            "7. Write a concise executive summary (max 5 lines).\n\n"
            "Output MUST be a valid raw JSON object exactly matching the schema. No markdown fences."
        ),
        expected_output=(
            "A valid JSON object matching this structure exactly:\n"
            "{\n"
            '  "success": true,\n'
            '  "agent": "Incident Response Agent",\n'
            '  "incident_type": "Business Email Compromise",\n'
            '  "severity": "Critical",\n'
            '  "business_impact": "High financial and data exposure risk.",\n'
            '  "mitre_attack": [{"id": "T1566", "name": "Phishing"}],\n'
            '  "containment": ["Quarantine email", "Block sender"],\n'
            '  "recovery": ["Reset credentials"],\n'
            '  "executive_summary": "A high-risk phishing email... containment recommended.",\n'
            '  "confidence": 0.95\n'
            "}"
        ),
        agent=ir_analyst
    )
    
    crew = Crew(
        agents=[ir_analyst],
        tasks=[ir_task],
        process=Process.sequential,
        verbose=False
    )
    
    result_raw = await crew.kickoff_async()
    
    try:
        clean_result = str(result_raw)
        json_match = re.search(r'\{[\s\S]*\}', clean_result)
        
        if not json_match:
            raise ValueError("No JSON object found in output.")
            
        json_str = json_match.group(0)
        result_json = json.loads(json_str)
        return IncidentResponse(**result_json)
    except Exception as e:
        logger.error(f"Failed to parse AI output: {e}. Raw: {result_raw}")
        return IncidentResponse(
            success=False,
            agent="Incident Response Agent",
            incident_type="Unknown",
            severity="Informational",
            business_impact="Could not parse impact due to AI error.",
            mitre_attack=[],
            containment=["Isolate host while manual review occurs"],
            recovery=["Review logs manually"],
            executive_summary=f"Analysis failed: {str(e)}",
            confidence=0.0
        )
