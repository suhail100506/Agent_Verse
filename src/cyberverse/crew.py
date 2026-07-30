import os


from crewai import LLM
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from cyberverse.tools.certificate.ocr_tool import OCRTool
from cyberverse.tools.certificate.metadata_tool import MetadataTool
from cyberverse.tools.certificate.qr_tool import QRTool
from cyberverse.tools.certificate.signature_tool import DigitalSignatureTool
from cyberverse.tools.certificate.tampering_tool import TamperingDetectionTool
from cyberverse.tools.privacy.pii_detection_tool import PIIDetectionTool
from cyberverse.tools.privacy.secret_scanner_tool import SecretScannerTool
from cyberverse.tools.privacy.compliance_tool import ComplianceTool
from cyberverse.tools.privacy.privacy_risk_tool import PrivacyRiskTool
from cyberverse.tools.malware.file_hash_tool import FileHashTool
from cyberverse.tools.malware.yara_scanner_tool import YARAScannerTool
from cyberverse.tools.malware.pe_analyzer_tool import PEAnalyzerTool
from cyberverse.tools.malware.virus_total_tool import VirusTotalTool
from cyberverse.tools.malware.malware_risk_tool import MalwareRiskTool
from cyberverse.tools.threat.ip_reputation_tool import IPReputationTool
from cyberverse.tools.threat.url_reputation_tool import URLReputationTool
from cyberverse.tools.threat.dns_analysis_tool import DNSAnalysisTool
from cyberverse.tools.threat.ioc_analysis_tool import IOCAnalysisTool
from cyberverse.tools.threat.threat_risk_tool import ThreatRiskTool
from cyberverse.tools.identity.document_verification_tool import DocumentVerificationTool
from cyberverse.tools.identity.face_verification_tool import FaceVerificationTool
from cyberverse.tools.identity.liveness_detection_tool import LivenessDetectionTool
from cyberverse.tools.identity.identity_consistency_tool import IdentityConsistencyTool
from cyberverse.tools.identity.identity_risk_tool import IdentityRiskTool
from cyberverse.tools.fraud.transaction_analysis_tool import TransactionAnalysisTool
from cyberverse.tools.fraud.behavioral_analysis_tool import BehavioralAnalysisTool
from cyberverse.tools.fraud.device_fingerprint_tool import DeviceFingerprintTool
from cyberverse.tools.fraud.account_takeover_tool import AccountTakeoverTool
from cyberverse.tools.fraud.fraud_risk_tool import FraudRiskTool
from cyberverse.tools.phishing.email_header_analysis_tool import EmailHeaderAnalysisTool
from cyberverse.tools.phishing.url_inspection_tool import URLInspectionTool
from cyberverse.tools.phishing.domain_reputation_tool import DomainReputationTool
from cyberverse.tools.phishing.content_analysis_tool import ContentAnalysisTool
from cyberverse.tools.phishing.phishing_risk_tool import PhishingRiskTool
from cyberverse.tools.password.password_strength_tool import PasswordStrengthTool
from cyberverse.tools.password.password_policy_tool import PasswordPolicyTool
from cyberverse.tools.password.password_leak_tool import PasswordLeakTool
from cyberverse.tools.password.mfa_assessment_tool import MFAAssessmentTool
from cyberverse.tools.password.password_risk_tool import PasswordRiskTool
from cyberverse.tools.incident.incident_classification_tool import IncidentClassificationTool
from cyberverse.tools.incident.mitre_mapping_tool import MITREMappingTool
from cyberverse.tools.incident.forensic_evidence_tool import ForensicEvidenceTool
from cyberverse.tools.incident.containment_plan_tool import ContainmentPlanTool
from cyberverse.tools.incident.incident_response_tool import IncidentResponseTool








def _get_llm() -> LLM:
    """Helper to return configured LLM. Prefers Groq if GROQ_API_KEY is available."""
    if os.environ.get("GROQ_API_KEY"):
        model_name = os.environ.get("MODEL", "groq/llama-3.3-70b-versatile")
        return LLM(model=model_name)
    model_name = os.environ.get("MODEL", "openai/gpt-4o-mini")
    return LLM(model=model_name)


@CrewBase
class CyberverseCrew:
    """Cyberverse crew"""

    
    @agent
    def cyberverse_orchestrator(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["cyberverse_orchestrator"],
            
            
            tools=[],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def certificate_verification_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["certificate_verification_specialist"],
            
            
            tools=[
                OCRTool(),
                MetadataTool(),
                QRTool(),
                DigitalSignatureTool(),
                TamperingDetectionTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def privacy_compliance_analyst(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["privacy_compliance_analyst"],
            
            
            tools=[
                PIIDetectionTool(),
                SecretScannerTool(),
                ComplianceTool(),
                PrivacyRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def malware_analysis_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["malware_analysis_specialist"],
            
            
            tools=[
                FileHashTool(),
                YARAScannerTool(),
                PEAnalyzerTool(),
                VirusTotalTool(),
                MalwareRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def threat_detection_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["threat_detection_specialist"],
            
            
            tools=[
                IPReputationTool(),
                URLReputationTool(),
                DNSAnalysisTool(),
                IOCAnalysisTool(),
                ThreatRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def phishing_detection_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["phishing_detection_specialist"],
            
            
            tools=[
                EmailHeaderAnalysisTool(),
                URLInspectionTool(),
                DomainReputationTool(),
                ContentAnalysisTool(),
                PhishingRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def password_security_advisor(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["password_security_advisor"],
            
            
            tools=[
                PasswordStrengthTool(),
                PasswordPolicyTool(),
                PasswordLeakTool(),
                MFAAssessmentTool(),
                PasswordRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def identity_verification_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["identity_verification_specialist"],
            
            
            tools=[
                DocumentVerificationTool(),
                FaceVerificationTool(),
                LivenessDetectionTool(),
                IdentityConsistencyTool(),
                IdentityRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def fraud_detection_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["fraud_detection_specialist"],
            
            
            tools=[
                TransactionAnalysisTool(),
                BehavioralAnalysisTool(),
                DeviceFingerprintTool(),
                AccountTakeoverTool(),
                FraudRiskTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    
    @agent
    def incident_response_specialist(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["incident_response_specialist"],
            
            
            tools=[
                IncidentClassificationTool(),
                MITREMappingTool(),
                ForensicEvidenceTool(),
                ContainmentPlanTool(),
                IncidentResponseTool(),
            ],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=_get_llm(),
            
        )
        
    

    
    @task
    def orchestrate_security_analysis(self) -> Task:
        return Task(
            config=self.tasks_config["orchestrate_security_analysis"],
            markdown=False,
            
            
        )
    
    @task
    def verify_certificates(self) -> Task:
        return Task(
            config=self.tasks_config["verify_certificates"],
            markdown=False,
            
            
        )
    
    @task
    def assess_privacy_compliance(self) -> Task:
        return Task(
            config=self.tasks_config["assess_privacy_compliance"],
            markdown=False,
            
            
        )
    
    @task
    def analyze_for_malware(self) -> Task:
        return Task(
            config=self.tasks_config["analyze_for_malware"],
            markdown=False,
            
            
        )
    
    @task
    def advise_on_password_security(self) -> Task:
        return Task(
            config=self.tasks_config["advise_on_password_security"],
            markdown=False,
            
            
        )
    
    @task
    def detect_threats(self) -> Task:
        return Task(
            config=self.tasks_config["detect_threats"],
            markdown=False,
            
            
        )
    
    @task
    def detect_phishing_attempts(self) -> Task:
        return Task(
            config=self.tasks_config["detect_phishing_attempts"],
            markdown=False,
            
            
        )
    
    @task
    def verify_identities(self) -> Task:
        return Task(
            config=self.tasks_config["verify_identities"],
            markdown=False,
            
            
        )
    
    @task
    def detect_fraud(self) -> Task:
        return Task(
            config=self.tasks_config["detect_fraud"],
            markdown=False,
            
            
        )
    
    @task
    def generate_incident_response_plan(self) -> Task:
        return Task(
            config=self.tasks_config["generate_incident_response_plan"],
            markdown=False,
            
            
        )
    

    @crew
    def crew(self) -> Crew:
        """Creates the Cyberverse crew"""

        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,

            chat_llm=LLM(model="openai/gpt-4o-mini"),
        )


