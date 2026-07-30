from typing import Dict, Any
from src.incident_response_agent.models import IncidentRequest, IncidentResponse
from src.incident_response_agent.crew import run_incident_analysis
from src.incident_response_agent.database import save_incident_report

async def process_incident(request: IncidentRequest) -> Dict[str, Any]:
    """
    Coordinates parsing the input, invoking CrewAI, saving to the database,
    and returning the final response asynchronously.
    """
    
    # Construct context from the request
    context = {}
    if request.phishing_result:
        context["phishing_result"] = request.phishing_result
    if request.malware_result:
        context["malware_result"] = request.malware_result
    if request.other_findings:
        context["other_findings"] = request.other_findings
        
    if not context:
        context["info"] = "No specific findings provided. Please analyze general threat landscape."
        
    # Pre-compute some base scores to help Gemini classify
    phishing_score = request.phishing_result.get("risk_score", 0) if request.phishing_result else 0
    malware_score = request.malware_result.get("threat_score", 0) if request.malware_result else 0
    max_score = max(phishing_score, malware_score)
    
    context["computed_threat_score"] = max_score
    if max_score > 90:
        context["suggested_severity"] = "Critical"
    elif max_score > 70:
        context["suggested_severity"] = "High"
    elif max_score > 40:
        context["suggested_severity"] = "Medium"
    elif max_score > 10:
        context["suggested_severity"] = "Low"
    else:
        context["suggested_severity"] = "Informational"

    # Run the CrewAI Agent
    ai_result: IncidentResponse = await run_incident_analysis(context)
    
    # Save the output to database
    report_dict = ai_result.model_dump()
    final_report = await save_incident_report(report_dict)
    
    return final_report
