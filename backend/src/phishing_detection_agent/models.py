from typing import List, Optional
from pydantic import BaseModel, Field

class PhishingAnalyzeRequest(BaseModel):
    sender: str = Field(..., description="The sender's email address")
    subject: str = Field(..., description="The subject of the email")
    body: str = Field(..., description="The text content of the email body")
    headers: Optional[str] = Field(default=None, description="Raw email headers")
    urls: List[str] = Field(default_factory=list, description="List of URLs extracted from the email")

class PhishingAnalyzeResponse(BaseModel):
    success: bool
    agent: str = "Phishing Detection Agent"
    risk_score: int
    risk_level: str
    attack_type: str
    confidence: int
    findings: List[str]
    recommendations: List[str]
    next_step: str = "Malware Analysis Agent"

class AIAnalysisResult(BaseModel):
    attack_type: str
    explanation: str
    confidence: int
    recommendations: List[str]
    risk_summary: str
