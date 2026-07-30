import os
import json
import re
from crewai import Agent, Task, Crew, Process
from src.phishing_detection_agent.models import AIAnalysisResult
from typing import Dict, Any

def run_ai_analysis(sender: str, subject: str, body: str, urls: list[str]) -> AIAnalysisResult:
    """Run CrewAI task to analyze the email content for phishing intent."""
    
    # Ensure API key is set
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")
    os.environ["GEMINI_API_KEY"] = gemini_api_key
    
    model_name = os.getenv("GEMINI_MODEL", "gemini/gemini-1.5-flash")
    
    phishing_analyst = Agent(
        role='Cybersecurity Phishing Analyst',
        goal='Determine if the provided email information represents a phishing attempt, and extract key indicators.',
        backstory='Expert cybersecurity analyst specializing in identifying social engineering, business email compromise, credential theft, and financial scams via email.',
        verbose=True,
        allow_delegation=False,
        llm=model_name
    )
    
    email_content = f"""
    Sender: {sender}
    Subject: {subject}
    Body: {body}
    URLs Detected: {urls}
    """
    
    analyze_task = Task(
        description=(
            "Analyze the following email content to determine if it is a phishing attempt.\n\n"
            f"{email_content}\n\n"
            "Identify the attack type (e.g., Credential Theft, Social Engineering, Business Email Compromise, Invoice Scam, CEO Fraud, Financial Scam, or None).\n"
            "Evaluate the confidence level of your assessment (0-100).\n"
            "Provide an explanation of your reasoning and recommendations for the user.\n"
            "Output MUST be a valid raw JSON object matching the requested schema. Do not include markdown formatting like ```json."
        ),
        expected_output=(
            "A valid JSON object with the following structure:\n"
            "{\n"
            '  "attack_type": "Credential Theft",\n'
            '  "explanation": "Detailed explanation of why this is a phishing attempt.",\n'
            '  "confidence": 95,\n'
            '  "recommendations": ["Do not click the link", "Report email"],\n'
            '  "risk_summary": "High risk of credential harvesting."\n'
            "}"
        ),
        agent=phishing_analyst
    )
    
    crew = Crew(
        agents=[phishing_analyst],
        tasks=[analyze_task],
        process=Process.sequential,
        verbose=False
    )
    
    result_raw = crew.kickoff()
    
    try:
        clean_result = str(result_raw)
        
        # Use regex to find the JSON object to bypass any conversational text
        json_match = re.search(r'\{[\s\S]*\}', clean_result)
        
        if not json_match:
            raise ValueError(f"No JSON object found in output.")
            
        json_str = json_match.group(0)
        result_json = json.loads(json_str)
        return AIAnalysisResult(**result_json)
    except Exception as e:
        # Fallback if parsing fails
        return AIAnalysisResult(
            attack_type="Unknown",
            explanation=f"Failed to parse AI output: {e}. Raw output: {result_raw}",
            confidence=0,
            recommendations=["Manual review required"],
            risk_summary="Analysis error"
        )
