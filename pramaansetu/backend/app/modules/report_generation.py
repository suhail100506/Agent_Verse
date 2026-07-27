import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(verification_doc: dict, output_dir: str) -> str:
    """Stage 18: Final Report Generation (ReportLab PDF compilation)"""
    os.makedirs(output_dir, exist_ok=True)
    report_id = str(verification_doc.get("_id", "VERIF-REF"))
    pdf_filename = f"PramaanSetu_Report_{report_id}.pdf"
    file_path = os.path.join(output_dir, pdf_filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0B132B')
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#4A5568')
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1C2541'),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#2D3748')
    )

    story = []

    # Header Title
    story.append(Paragraph("PramaanSetu — Certificate Authenticity Forensic Report", title_style))
    story.append(Paragraph(f"Audit Record ID: {report_id} | Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0B132B'), spaceAfter=12))

    # Summary Box Table
    classification = verification_doc.get("classification", "Processing")
    score_obj = verification_doc.get("authenticity_score", {})
    overall_score = score_obj.get("overall_score", 0.0)

    # Classification color selection
    badge_color = colors.HexColor('#10B981') # Green for Verified
    if classification in ["Suspicious", "Likely Genuine"]:
        badge_color = colors.HexColor('#F59E0B') # Amber
    elif classification in ["Fake", "Likely Fake"]:
        badge_color = colors.HexColor('#EF4444') # Red
    elif classification == "Manual Review Required":
        badge_color = colors.HexColor('#6B7280') # Gray

    summary_data = [
        [
            Paragraph("<b>Verdict Classification</b>", body_style),
            Paragraph(f"<font color='{badge_color.hexval()}'><b>{classification.upper()}</b></font>", title_style)
        ],
        [
            Paragraph("<b>Overall Authenticity Score</b>", body_style),
            Paragraph(f"<b>{overall_score:.1f} / 100</b>", title_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[200, 340])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Extracted Candidate Data Table
    story.append(Paragraph("1. Extracted Certificate Information", section_heading))
    ext_data = verification_doc.get("extracted_data", {})
    
    extracted_table_data = [
        [Paragraph("<b>Field</b>", body_style), Paragraph("<b>Extracted Value</b>", body_style)],
        [Paragraph("Candidate Name", body_style), Paragraph(ext_data.get("name") or "N/A", body_style)],
        [Paragraph("Certificate Number", body_style), Paragraph(ext_data.get("certificate_number") or "N/A", body_style)],
        [Paragraph("Issuing Institution", body_style), Paragraph(ext_data.get("institution") or "N/A", body_style)],
        [Paragraph("Course / Degree", body_style), Paragraph(ext_data.get("course") or "N/A", body_style)],
        [Paragraph("Date of Issue", body_style), Paragraph(ext_data.get("date") or "N/A", body_style)],
        [Paragraph("Grade / CGPA", body_style), Paragraph(ext_data.get("grade") or "N/A", body_style)],
    ]
    
    ext_table = Table(extracted_table_data, colWidths=[180, 360])
    ext_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1C2541')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ext_table)
    story.append(Spacer(1, 14))

    # Forensic AI Reasoning
    story.append(Paragraph("2. Forensic Analysis & Reasoning (Gemini 2.5 Flash)", section_heading))
    ai_reasoning = verification_doc.get("ai_reasoning", "Analysis incomplete.")
    story.append(Paragraph(ai_reasoning, body_style))
    story.append(Spacer(1, 10))

    # Actionable Recommendation
    story.append(Paragraph("3. Actionable Recommendation", section_heading))
    rec = verification_doc.get("recommendation", "")
    story.append(Paragraph(f"<b>Recommendation:</b> {rec}", body_style))
    story.append(Spacer(1, 14))

    # 18-Stage Breakdown Table
    story.append(Paragraph("4. 18-Stage Forensic Pipeline Audit Matrix", section_heading))
    stage_results = verification_doc.get("stage_results", {})
    
    stage_matrix_data = [
        [Paragraph("<b>Stage</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Key Findings / Metrics</b>", body_style)]
    ]

    for stage_name, res in stage_results.items():
        st_title = stage_name.replace("_", " ").title()
        if isinstance(res, dict):
            st_status = "Passed" if res.get("passed", True) and not res.get("error") else ("Failed" if res.get("error") else "Checked")
            notes = res.get("notes") or res.get("details") or res.get("error") or "Completed"
        else:
            st_status = "Done"
            notes = str(res)

        stage_matrix_data.append([
            Paragraph(st_title, body_style),
            Paragraph(f"<b>{st_status}</b>", body_style),
            Paragraph(str(notes)[:120], body_style)
        ])

    matrix_table = Table(stage_matrix_data, colWidths=[150, 70, 320])
    matrix_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0B132B')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(matrix_table)

    # Footer notice
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CBD5E1'), spaceAfter=8))
    story.append(Paragraph("PramaanSetu Append-Only Audit Integrity System — Document reference immutable.", subtitle_style))

    doc.build(story)
    return file_path
