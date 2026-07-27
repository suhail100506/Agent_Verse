from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any, List
from datetime import datetime

# --- Auth & User Models ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    role: str = "applicant" # applicant | verifier | admin

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class UserOut(BaseModel):
    id: str
    email: str
    role: str
    created_at: datetime

# --- Certificate Models ---
class CertificateOut(BaseModel):
    id: str
    uploaded_by: str
    original_filename: str
    storage_path: str
    file_hash_sha256: str
    file_type: str
    uploaded_at: datetime

# --- Verification Pipeline Models ---
class ExtractedData(BaseModel):
    name: Optional[str] = None
    certificate_number: Optional[str] = None
    institution: Optional[str] = None
    course: Optional[str] = None
    date: Optional[str] = None
    grade: Optional[str] = None

class AuthenticityScore(BaseModel):
    ocr_score: Optional[float] = None
    qr_score: Optional[float] = None
    cert_number_score: Optional[float] = None
    template_score: Optional[float] = None
    logo_score: Optional[float] = None
    seal_score: Optional[float] = None
    signature_score: Optional[float] = None
    metadata_score: Optional[float] = None
    tampering_score: Optional[float] = None
    authority_score: Optional[float] = None
    overall_score: float = 0.0

class VerificationRecordOut(BaseModel):
    id: str
    certificate_id: str
    previous_verification_id: Optional[str] = None
    pipeline_version: str = "1.0"
    status: str # processing | completed | failed
    current_stage: Optional[str] = None
    stage_progress_pct: Optional[int] = 0
    extracted_data: ExtractedData = Field(default_factory=ExtractedData)
    stage_results: Dict[str, Any] = Field(default_factory=dict)
    authenticity_score: AuthenticityScore = Field(default_factory=AuthenticityScore)
    classification: str = "Processing"
    ai_reasoning: Optional[str] = ""
    recommendation: Optional[str] = ""
    report_pdf_path: Optional[str] = ""
    created_at: datetime
    completed_at: Optional[datetime] = None
    duplicate_alert: Optional[Dict[str, Any]] = None

# --- Template Library Models ---
class TemplateOut(BaseModel):
    id: str
    institution_name: str
    reference_logo_path: str
    reference_seal_path: str
    layout_coordinates: Dict[str, Any]
    font_signature: Optional[str] = ""
    updated_at: datetime
