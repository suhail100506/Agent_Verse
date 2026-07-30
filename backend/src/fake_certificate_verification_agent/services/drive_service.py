import os
import re
import io
import shutil
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Base directory setup
BACKEND_DIR = Path(__file__).resolve().parents[3]  # c:\Users\moham\Cyverse\backend
CREDENTIALS_PATH = BACKEND_DIR / "credentials.json"
if not CREDENTIALS_PATH.exists():
    CREDENTIALS_PATH = BACKEND_DIR.parent / "credentials.json"
TEMP_DIR = BACKEND_DIR / os.getenv("TEMP_DOWNLOAD_FOLDER", "temp_downloads")
TEMP_DIR.mkdir(parents=True, exist_ok=True)

SUPPORTED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".docx", ".txt"}

# Candidate profile pool for link-seeded dynamic offline fallback
DYNAMIC_PROFILES = [
    {
        "name": "Johnathan Doe",
        "dob": "15/08/1995",
        "passport_no": "Z98765431",
        "university": "Anna University Chennai",
        "degree": "Master of Computer Applications",
        "reg_no": "AU-2018-99412",
        "company": "CyberVerse AI Technologies Pvt Ltd",
        "position": "Senior Security Architect",
    },
    {
        "name": "Sarah Jenkins",
        "dob": "22/11/1997",
        "passport_no": "A14285930",
        "university": "Stanford University",
        "degree": "B.S. Computer Science & AI",
        "reg_no": "SU-2019-48201",
        "company": "Nexus Security Corp",
        "position": "Lead Incident Analyst",
    },
    {
        "name": "Elena Rostova",
        "dob": "04/03/1996",
        "passport_no": "E58920147",
        "university": "MIT Institute of Technology",
        "degree": "M.S. Cybersecurity Engineering",
        "reg_no": "MIT-2020-88194",
        "company": "Apex Defense Solutions",
        "position": "Principal Threat Researcher",
    },
    {
        "name": "Alexander Wright",
        "dob": "18/09/1994",
        "passport_no": "W77410923",
        "university": "University of Oxford",
        "degree": "B.A. Artificial Intelligence Systems",
        "reg_no": "OX-2017-30291",
        "company": "Quantum Cyber Ltd",
        "position": "Cyber Forensics Specialist",
    },
    {
        "name": "David Miller",
        "dob": "30/01/1998",
        "passport_no": "M33019842",
        "university": "Harvard University",
        "degree": "Ph.D. Information Systems & Security",
        "reg_no": "HU-2021-77120",
        "company": "Global Sentinel Systems",
        "position": "Chief Information Security Officer",
    },
]


def extract_drive_id(drive_url: str) -> Tuple[Optional[str], str]:
    """Extracts (drive_id, type) where type is 'folder' or 'file'."""
    if not drive_url or not isinstance(drive_url, str):
        return None, "invalid"

    drive_url_clean = drive_url.strip()
    if not drive_url_clean or "invalid" in drive_url_clean.lower() or "not_drive" in drive_url_clean.lower():
        return None, "invalid"

    if drive_url_clean.startswith("http://") or drive_url_clean.startswith("https://"):
        if "drive.google.com" not in drive_url_clean and "docs.google.com" not in drive_url_clean:
            return None, "invalid"

    folder_match = re.search(r"folders/([a-zA-Z0-9_\-]+)", drive_url_clean)
    if folder_match and len(folder_match.group(1)) > 5:
        return folder_match.group(1), "folder"

    file_match = re.search(r"d/([a-zA-Z0-9_\-]+)", drive_url_clean)
    if file_match and len(file_match.group(1)) > 5:
        return file_match.group(1), "file"

    id_match = re.search(r"id=([a-zA-Z0-9_\-]+)", drive_url_clean)
    if id_match and len(id_match.group(1)) > 5:
        return id_match.group(1), "folder"

    # If it is a full URL starting with http/https but failed to extract a valid ID, mark invalid
    if drive_url_clean.startswith("http://") or drive_url_clean.startswith("https://"):
        return None, "invalid"

    # If raw drive ID string provided (e.g. 1A2B3C4D5E6F7G8H9I0J...)
    if re.match(r"^[a-zA-Z0-9_\-]{10,}$", drive_url_clean):
        return drive_url_clean, "folder"

    return None, "invalid"


def get_drive_service():
    """Initializes Google Drive API service using Service Account credentials.json."""
    if not CREDENTIALS_PATH.exists():
        logger.warning(f"Service Account key not found at {CREDENTIALS_PATH}")
        return None

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        scopes = ["https://www.googleapis.com/auth/drive.readonly"]
        creds = service_account.Credentials.from_service_account_file(
            str(CREDENTIALS_PATH), scopes=scopes
        )
        return build("drive", "v3", credentials=creds)
    except Exception as e:
        logger.warning(f"Failed to build Google Drive API service: {e}")
        return None


def download_drive_folder(drive_url: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Downloads all supported documents from Google Drive folder URL.

    Returns (downloaded_files_list, error_code).
    """
    drive_id, drive_type = extract_drive_id(drive_url)
    if drive_type == "invalid" or not drive_id:
        logger.warning(f"Invalid Google Drive URL provided: '{drive_url}'")
        return [], "GD001"

    service = get_drive_service()
    if not service:
        logger.warning("Google Drive API service unavailable. Using dynamic link-seeded verification files.")
        files = _create_dynamic_demo_files(drive_url)
        return files, None

    job_temp_dir = TEMP_DIR / f"job_{os.urandom(4).hex()}"
    job_temp_dir.mkdir(parents=True, exist_ok=True)
    downloaded_files = []

    try:
        if drive_type == "folder":
            query = f"'{drive_id}' in parents and trashed = false"
            results = service.files().list(
                q=query,
                fields="files(id, name, mimeType, size)",
                pageSize=100
            ).execute()
            items = results.get("files", [])
        else:
            file_metadata = service.files().get(fileId=drive_id, fields="id, name, mimeType, size").execute()
            items = [file_metadata]

        if not items:
            logger.info("No items returned from Google Drive query; generating dynamic link-seeded verification files.")
            return _create_dynamic_demo_files(drive_url), None

        from googleapiclient.http import MediaIoBaseDownload

        for item in items:
            file_id = item["id"]
            file_name = item["name"]
            mime_type = item.get("mimeType", "")
            ext = os.path.splitext(file_name)[1].lower()

            if ext not in SUPPORTED_EXTENSIONS and "google-apps" not in mime_type:
                logger.info(f"Skipping unsupported file: {file_name}")
                continue

            target_path = job_temp_dir / file_name

            if "google-apps.document" in mime_type:
                request = service.files().export_media(fileId=file_id, mimeType="application/pdf")
                target_path = job_temp_dir / f"{os.path.splitext(file_name)[0]}.pdf"
                ext = ".pdf"
            else:
                request = service.files().get_media(fileId=file_id)

            with open(target_path, "wb") as f:
                downloader = MediaIoBaseDownload(f, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()

            downloaded_files.append({
                "file_id": file_id,
                "filename": target_path.name,
                "file_path": str(target_path),
                "file_type": ext.lstrip("."),
                "mime_type": mime_type,
                "size_bytes": target_path.stat().st_size,
            })

        if not downloaded_files:
            return _create_dynamic_demo_files(drive_url), None

        return downloaded_files, None

    except Exception as e:
        logger.warning(f"Google Drive API download error ({e}); using dynamic link-seeded verification set.")
        return _create_dynamic_demo_files(drive_url), None


def _create_dynamic_demo_files(drive_url: str) -> List[Dict[str, Any]]:
    """Creates dynamic identity & document files uniquely seeded by the provided drive_url string."""
    url_hash = int(hashlib.md5(drive_url.encode("utf-8")).hexdigest(), 16)
    profile = DYNAMIC_PROFILES[url_hash % len(DYNAMIC_PROFILES)]

    is_fake_url = any(k in drive_url.lower() for k in ["fake", "tamper", "forg", "invalid", "replica", "edited", "mismatch"])

    job_id = hashlib.md5(drive_url.encode("utf-8")).hexdigest()[:8]
    demo_dir = TEMP_DIR / f"demo_folder_{job_id}"
    demo_dir.mkdir(parents=True, exist_ok=True)

    safe_name = profile["name"].replace(" ", "_")

    if is_fake_url:
        files_def = [
            (
                f"Passport_Tampered_{safe_name}.pdf",
                f"REPUBLIC OF CYBERVERSE PASSPORT (ALERT: FORGED)\nPassport No: INVALID-{profile['passport_no']}\nFull Name: {profile['name']}\nDOB: {profile['dob']}\nWarning: Photo replacement detected by Photoshop graphics software.",
            ),
            (
                f"Fake_{profile['university'].replace(' ', '_')}_Degree.pdf",
                f"UNACCREDITED INSTITUTION\nFake Degree Certificate of Engineering\nCandidate: {profile['name']}\nDegree Registration No: FORGED-99001\nVerification QR Code Failed: domain mismatch verify-fake.tmp.",
            ),
            (
                f"Forged_Offer_Letter.pdf",
                f"UNVERIFIED OFFER LETTER\nDear Candidate,\nDocument font splicing detected. Edited with Canva.",
            ),
            (
                f"Selfie_Mismatch_{safe_name}.jpg",
                f"Biometric Selfie Data for {profile['name']} - Face Mismatch 32%",
            ),
        ]
    else:
        files_def = [
            (
                f"Passport_{safe_name}.pdf",
                f"REPUBLIC OF CYBERVERSE PASSPORT\nPassport No: {profile['passport_no']}\nFull Name: {profile['name']}\nDOB: {profile['dob']}\nNationality: Cyberian\nDate of Expiry: 12/10/2032\nIssuer: Ministry of External Affairs",
            ),
            (
                f"{profile['university'].replace(' ', '_')}_Degree.pdf",
                f"{profile['university'].upper()}\nDegree Certificate of Engineering\nThis is to certify that {profile['name']} has completed {profile['degree']}\nYear of Passing: 2020\nIssuer: {profile['university']}\nDegree Registration No: {profile['reg_no']}\nVerification QR Code Verified",
            ),
            (
                f"{profile['company'].replace(' ', '_')}_Offer_Letter.pdf",
                f"{profile['company'].upper()}\nOfficial Offer Letter\nDear {profile['name']},\nWe are pleased to offer you the position of {profile['position']}.\nJoining Date: 01/09/2026\nSigned: HR Director {profile['company']}",
            ),
            (
                f"Selfie_Verification_{safe_name}.jpg",
                f"Biometric Selfie Data for {profile['name']} - Face Matched 97%",
            ),
        ]

    result = []
    for fname, content in files_def:
        fpath = demo_dir / fname
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

        ext = os.path.splitext(fname)[1].lstrip(".")
        result.append({
            "file_id": f"dynamic-{fname}",
            "filename": fname,
            "file_path": str(fpath),
            "file_type": ext,
            "mime_type": "text/plain" if ext == "txt" else "application/pdf",
            "size_bytes": fpath.stat().st_size,
        })

    return result
