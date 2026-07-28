import json
from typing import Dict, Any

def generate_report_html(report: Dict[str, Any]) -> str:
    """Renders a printable executive SOC Security Report HTML layout for PDF/HTML export."""
    title = report.get("user_query") or report.get("summary") or "CyberVerse Security Audit Report"
    report_id = report.get("orchestration_id") or report.get("report_id") or "CYBER-9901"
    status = (report.get("status") or "Verified").upper()
    score = report.get("overall_score", 95)
    created_at = report.get("created_at", "2026-07-28")
    
    sub_report = report.get("sub_agent_report", report)
    checks = sub_report.get("checks", {})

    status_color = "#10b981" if status in ["VERIFIED", "SAFE", "PASSED"] else ("#ef4444" if status in ["FAKE", "SUSPICIOUS", "CRITICAL RISK", "MALICIOUS"] else "#f59e0b")

    checks_html = ""
    for idx, (k, v) in enumerate(checks.items(), 1):
        c_title = k.replace("_", " ").upper()
        checks_html += f"""
        <tr style="border-bottom: 1px solid #e5e7eb;">
          <td style="padding: 12px; font-weight: bold; width: 30%; color: #1e293b;">{idx}. {c_title}</td>
          <td style="padding: 12px; color: #475569; font-family: monospace;">{v}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberVerse Executive Security Report - {report_id}</title>
  <style>
    body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }}
    .report-card {{ max-width: 900px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #06b6d4; padding-bottom: 20px; margin-bottom: 30px; }}
    .brand-title {{ font-size: 28px; font-weight: 800; color: #0f172a; margin: 0; }}
    .brand-title span {{ color: #06b6d4; }}
    .badge {{ font-size: 16px; font-weight: 800; padding: 6px 16px; border-radius: 20px; color: #ffffff; background: {status_color}; text-transform: uppercase; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
    .meta-box {{ background: #f1f5f9; padding: 15px; border-radius: 8px; border-left: 4px solid #06b6d4; }}
    .meta-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: bold; display: block; }}
    .meta-val {{ font-size: 16px; font-weight: bold; color: #0f172a; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }}
    th {{ background: #0f172a; color: #ffffff; padding: 12px; text-align: left; font-size: 12px; text-transform: uppercase; }}
    .summary-box {{ background: #eff6ff; border: 1px solid #bfdbfe; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    .footer {{ font-size: 11px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 20px; margin-top: 40px; }}
  </style>
</head>
<body>
  <div class="report-card">
    <div class="header">
      <div>
        <h1 class="brand-title">CyberVerse<span>.AI</span></h1>
        <p style="margin: 4px 0 0 0; color: #64748b; font-size: 13px;">Executive Security Audit & Forensics Report</p>
      </div>
      <div class="badge">{status}</div>
    </div>

    <div class="grid">
      <div class="meta-box"><span class="meta-label">Report ID</span><span class="meta-val">{report_id}</span></div>
      <div class="meta-box"><span class="meta-label">Score</span><span class="meta-val">{score} / 100</span></div>
      <div class="meta-box"><span class="meta-label">Audit Date</span><span class="meta-val">{created_at[:10]}</span></div>
      <div class="meta-box"><span class="meta-label">Email Alert</span><span class="meta-val">{str(report.get('email_delivery_status', 'N/A')).title()}</span></div>
    </div>

    <div class="summary-box">
      <h3 style="margin: 0 0 8px 0; color: #1e3a8a;">Executive Summary</h3>
      <p style="margin: 0; line-height: 1.6; color: #1e40af;">{report.get('summary') or sub_report.get('summary')}</p>
    </div>

    <h3 style="color: #0f172a;">9-Layer Security Verification Breakdown</h3>
    <table>
      <thead>
        <tr>
          <th>Verification Check</th>
          <th>Forensic Diagnostic Finding</th>
        </tr>
      </thead>
      <tbody>
        {checks_html}
      </tbody>
    </table>

    <div style="background: #f8fafc; border: 1px solid #cbd5e1; padding: 20px; border-radius: 8px;">
      <h4 style="margin: 0 0 6px 0; color: #0f172a;">SOC Recommendation</h4>
      <p style="margin: 0 0 12px 0; color: #334155;">{report.get('recommendation') or sub_report.get('recommendation')}</p>
      <h4 style="margin: 0 0 6px 0; color: #0f172a;">Required Next Action</h4>
      <p style="margin: 0; color: #334155;">{report.get('next_action') or sub_report.get('next_action')}</p>
    </div>

    <div class="footer">
      Generated automatically by CyberVerse AI Multi-Agent Platform • Confirmed by Master Orchestrator • AgentVerse Hackathon
    </div>
  </div>
</body>
</html>
"""
    return html
