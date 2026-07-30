from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict

class MitreTechnique(BaseModel):
    id: str = Field(description="MITRE ATT&CK Technique ID, e.g., T1566")
    name: str = Field(description="MITRE ATT&CK Technique Name")

class IncidentResponse(BaseModel):
    success: bool = Field(default=True, description="Indicates if the response generation was successful")
    agent: str = Field(default="Incident Response Agent", description="Agent name")
    incident_type: str = Field(description="Classification of the incident (e.g., Business Email Compromise, Malware Infection)")
    severity: str = Field(description="Severity assessment: Informational, Low, Medium, High, Critical")
    business_impact: str = Field(description="Short explanation of business impact")
    mitre_attack: List[MitreTechnique] = Field(description="List of mapped MITRE ATT&CK techniques")
    containment: List[str] = Field(description="Immediate containment actions")
    recovery: List[str] = Field(description="Recovery recommendations")
    executive_summary: str = Field(description="Concise SOC summary suitable for a dashboard (max 5 lines)")
    confidence: Optional[float] = Field(default=1.0, description="Confidence score from 0 to 1")
    
class IncidentRequest(BaseModel):
    phishing_result: Optional[Dict[str, Any]] = None
    malware_result: Optional[Dict[str, Any]] = None
    other_findings: Optional[Dict[str, Any]] = None
