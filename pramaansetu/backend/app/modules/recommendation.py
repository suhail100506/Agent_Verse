def generate_recommendation(classification: str, stage_results: dict) -> str:
    """Stage 17: Recommendation generation"""
    if classification == "Verified":
        return "Certificate passed all 18 forensic authenticity stages. Approved for automated background verification and official processing."
    elif classification == "Likely Genuine":
        return "Certificate is structural & content aligned with minor low-risk variances. Proceed with standard acceptance."
    elif classification == "Suspicious":
        return "Certificate exhibits inconsistencies (e.g. metadata flags or seal variance). Recommend requesting original physical document for secondary verification."
    elif classification in ["Likely Fake", "Fake"]:
        return "High risk of digital alteration or fraudulent template replication detected. Reject submission and flag record for security review."
    else: # Manual Review Required
        return "Automated extraction was insufficient due to image degradation or unmatched layout. Escalate to human forensic verifier for manual review."
