import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from 'recharts'
import { fetchReport, type OrchestratorReport } from '../api'
import RiskGauge from '../components/RiskGauge'
import SpecialistCard from '../components/SpecialistCard'
import EvidenceTable from '../components/EvidenceTable'
import RecommendationList from '../components/RecommendationList'
import ExecutiveSummary from '../components/ExecutiveSummary'

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#f97316', LOW: '#10b981', UNKNOWN: '#64748b',
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
      <h2 style={{ fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#64748b' }}>
        {title}
      </h2>
      {children}
    </div>
  )
}

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>()
  const [report, setReport] = useState<OrchestratorReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    fetchReport(id)
      .then(setReport)
      .catch(() => setError('Report not found.'))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
      <span className="spinner" style={{ width: 32, height: 32 }} />
    </div>
  )

  if (error || !report) return (
    <div style={{ textAlign: 'center', color: '#64748b', padding: '4rem' }}>
      <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>⚠</div>
      <div>{error || 'Report not found.'}</div>
      <Link to="/reports" className="btn-primary" style={{ display: 'inline-block', marginTop: '1rem', textDecoration: 'none' }}>← Back to Reports</Link>
    </div>
  )

  const { platform_risk: pr, specialist_results: sr } = report

  // Radar chart data
  const radarData = sr.filter(s => s.success).map(s => ({
    name: s.display_name.replace(' Specialist', '').replace(' Analyst', '').replace(' Advisor', ''),
    score: s.score,
  }))

  // Bar chart data
  const barData = sr.filter(s => s.success).map(s => ({
    name: s.display_name.split(' ')[0],
    score: s.score,
    risk: s.risk_level,
  }))

  return (
    <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <Link to="/reports" style={{ fontSize: '0.75rem', color: '#6366f1', textDecoration: 'none', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '0.25rem', marginBottom: '0.75rem' }}>
            ← Back to Reports
          </Link>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#e2e8f0' }}>
            {report.label ?? 'Security Analysis Report'}
          </h1>
          <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.375rem' }}>
            {new Date(report.created_at).toLocaleString()}
            {' · '}ID: <span style={{ fontFamily: 'monospace' }}>{report.report_id.slice(0, 8)}…</span>
            {' · '}{report.total_duration_ms}ms total
          </p>
        </div>
        <span className={`risk-badge risk-${pr.overall_risk}`} style={{ fontSize: '0.875rem', padding: '0.375rem 1rem' }}>
          {pr.overall_risk}
        </span>
      </div>

      {/* Executive summary */}
      <ExecutiveSummary
        summary={report.executive_summary}
        risk={pr.overall_risk}
        score={pr.overall_score}
        confidence={pr.confidence}
      />

      {/* Overview row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.5rem' }}>
        {/* Gauge */}
        <div className="glass" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
          <RiskGauge score={pr.overall_score} risk={pr.overall_risk} size={180} label="Platform Score" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', width: '100%' }}>
            {[
              { label: 'Critical', value: pr.critical_count, color: '#ef4444' },
              { label: 'High', value: pr.high_count, color: '#f59e0b' },
              { label: 'Medium', value: pr.medium_count, color: '#f97316' },
              { label: 'Low', value: pr.low_count, color: '#10b981' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ textAlign: 'center', padding: '0.75rem', borderRadius: 10, background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.08)' }}>
                <div style={{ fontWeight: 800, fontSize: '1.25rem', color }}>{value}</div>
                <div style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Radar */}
        <div className="glass" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontWeight: 700, fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Score Radar</h3>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(99,102,241,0.15)" />
              <PolarAngleAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 9 }} />
              <Radar name="Score" dataKey="score" stroke="#6366f1" fill="#6366f1" fillOpacity={0.25} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Bar chart */}
        <div className="glass" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontWeight: 700, fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Score Breakdown</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} layout="vertical" barSize={12}>
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 9 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#64748b', fontSize: 9 }} width={60} />
              <Tooltip
                contentStyle={{ background: '#0d1424', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Bar dataKey="score" radius={[0, 6, 6, 0]}>
                {barData.map((entry, i) => (
                  <Cell key={i} fill={RISK_COLORS[entry.risk] ?? '#6366f1'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Specialist cards */}
      <Section title="Specialist Results">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
          {sr.map(result => (
            <SpecialistCard key={result.specialist} result={result} />
          ))}
        </div>
      </Section>

      {/* Evidence + Recommendations */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <Section title="Evidence & Findings">
          <EvidenceTable findings={report.all_findings} />
        </Section>
        <Section title="Recommendations">
          <RecommendationList recommendations={report.all_recommendations} />
        </Section>
      </div>
    </div>
  )
}
