import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { fetchHealth, fetchReports, type ReportSummary } from '../api'
import RiskGauge from '../components/RiskGauge'

const SPECIALIST_LABELS: Record<string, string> = {
  certificate_verification_specialist: 'Certificate Verification',
  privacy_compliance_analyst: 'Privacy Compliance',
  malware_analysis_specialist: 'Malware Analysis',
  threat_detection_specialist: 'Threat Detection',
  identity_verification_specialist: 'Identity Verification',
  fraud_detection_specialist: 'Fraud Detection',
  phishing_detection_specialist: 'Phishing Detection',
  password_security_advisor: 'Password Security',
  incident_response_specialist: 'Incident Response',
}

function RiskBadge({ risk }: { risk: string }) {
  return <span className={`risk-badge risk-${risk}`}>{risk}</span>
}

export default function Dashboard() {
  const [health, setHealth] = useState<any>(null)
  const [reports, setReports] = useState<ReportSummary[]>([])
  const [_loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([fetchHealth(), fetchReports(5)])
      .then(([h, r]) => { setHealth(h); setReports(r.reports ?? []) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const latest = reports[0]

  return (
    <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Hero */}
      <div style={{ textAlign: 'center', padding: '2rem 0 1rem' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 900, letterSpacing: '-0.03em', lineHeight: 1.1 }}>
          <span className="gradient-text">CyberVerse</span>
          <span style={{ color: '#e2e8f0' }}> Enterprise Platform</span>
        </h1>
        <p style={{ color: '#64748b', fontSize: '1rem', marginTop: '0.75rem', maxWidth: 500, margin: '0.75rem auto 0' }}>
          9-specialist multi-agent cybersecurity intelligence platform
        </p>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        {[
          { label: 'Specialists', value: health?.specialists_available ?? 9, color: '#6366f1', icon: '⚡' },
          { label: 'Reports Stored', value: health?.reports_stored ?? 0, color: '#8b5cf6', icon: '📋' },
          { label: 'Platform Status', value: health ? 'Online' : '—', color: '#10b981', icon: '✅' },
          { label: 'Latest Risk', value: latest?.overall_risk ?? '—', color: '#f59e0b', icon: '🔍' },
        ].map(({ label, value, color, icon }) => (
          <div key={label} className="glass stat-card" style={{ gap: '0.5rem' }}>
            <span style={{ fontSize: '1.5rem' }}>{icon}</span>
            <div className="stat-value" style={{ color }}>{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {/* Main content */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Latest report gauge */}
        <div className="glass" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Latest Analysis</h2>
            {latest && <Link to={`/reports/${latest.report_id}`} style={{ fontSize: '0.75rem', color: '#6366f1', textDecoration: 'none', fontWeight: 600 }}>View Report →</Link>}
          </div>
          {latest ? (
            <>
              <RiskGauge score={latest.overall_score} risk={latest.overall_risk} size={200} />
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.8rem', color: '#64748b' }}>{latest.label ?? 'Unnamed Analysis'}</div>
                <div style={{ fontSize: '0.7rem', color: '#475569', marginTop: 4 }}>
                  {new Date(latest.created_at).toLocaleString()}
                </div>
              </div>
            </>
          ) : (
            <div style={{ textAlign: 'center', color: '#64748b', padding: '2rem' }}>
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>⬡</div>
              <div>No reports yet.</div>
              <Link to="/analyze" className="btn-primary" style={{ display: 'inline-block', marginTop: '1rem', textDecoration: 'none' }}>Run First Analysis</Link>
            </div>
          )}
        </div>

        {/* Specialist overview */}
        <div className="glass" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <h2 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.5rem' }}>Specialist Suite</h2>
          {Object.entries(SPECIALIST_LABELS).map(([key, name]) => (
            <div key={key} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '0.625rem 0.875rem', borderRadius: 8, fontSize: '0.8rem',
              background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.08)',
            }}>
              <span style={{ color: '#cbd5e1' }}>{name}</span>
              <span style={{ fontSize: '0.65rem', fontWeight: 700, color: '#10b981', letterSpacing: '0.06em', textTransform: 'uppercase' }}>✓ Active</span>
            </div>
          ))}
        </div>
      </div>

      {/* Recent reports table */}
      {reports.length > 0 && (
        <div className="glass" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid rgba(99,102,241,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>Recent Reports</h2>
            <Link to="/reports" style={{ fontSize: '0.75rem', color: '#6366f1', textDecoration: 'none', fontWeight: 600 }}>View All →</Link>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Risk</th>
                  <th>Score</th>
                  <th>Specialists</th>
                  <th>Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.report_id}>
                    <td style={{ color: '#e2e8f0', fontWeight: 500 }}>{r.label ?? <span style={{ color: '#475569' }}>Unnamed</span>}</td>
                    <td><RiskBadge risk={r.overall_risk} /></td>
                    <td style={{ fontWeight: 700, color: '#e2e8f0' }}>{r.overall_score}</td>
                    <td style={{ color: '#94a3b8' }}>{r.specialists_run}</td>
                    <td style={{ color: '#64748b', fontSize: '0.75rem' }}>{new Date(r.created_at).toLocaleString()}</td>
                    <td><Link to={`/reports/${r.report_id}`} style={{ color: '#6366f1', textDecoration: 'none', fontSize: '0.75rem', fontWeight: 600 }}>View →</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', paddingBottom: '1rem' }}>
        <Link to="/analyze" className="btn-primary" style={{ textDecoration: 'none', fontSize: '0.9rem', padding: '0.75rem 2rem' }}>
          ⚡ New Security Analysis
        </Link>
        <Link to="/reports" className="btn-ghost" style={{ textDecoration: 'none', fontSize: '0.9rem', padding: '0.75rem 2rem' }}>
          View All Reports
        </Link>
      </div>
    </div>
  )
}
