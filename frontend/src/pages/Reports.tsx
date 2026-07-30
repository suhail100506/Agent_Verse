import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { fetchReports, type ReportSummary } from '../api'

function RiskBadge({ risk }: { risk: string }) {
  return <span className={`risk-badge risk-${risk}`}>{risk}</span>
}

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [offset, setOffset] = useState(0)
  const limit = 20

  const load = (off: number) => {
    setLoading(true)
    fetchReports(limit, off)
      .then(d => { setReports(d.reports ?? []); setTotal(d.total ?? 0) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(offset) }, [offset])

  return (
    <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
            <span className="gradient-text">Security Reports</span>
          </h1>
          <p style={{ color: '#64748b', fontSize: '0.875rem', marginTop: '0.375rem' }}>
            {total} report{total !== 1 ? 's' : ''} stored
          </p>
        </div>
        <Link to="/analyze" className="btn-primary" style={{ textDecoration: 'none' }}>
          ⚡ New Analysis
        </Link>
      </div>

      {/* Table */}
      <div className="glass" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>
            <span className="spinner" style={{ width: 24, height: 24 }} />
          </div>
        ) : reports.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>📋</div>
            <div>No reports yet.</div>
            <Link to="/analyze" className="btn-primary" style={{ display: 'inline-block', marginTop: '1rem', textDecoration: 'none' }}>
              Run First Analysis
            </Link>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Overall Risk</th>
                  <th>Score</th>
                  <th>Specialists</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.report_id}>
                    <td style={{ fontWeight: 600, color: '#e2e8f0', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.label ?? <span style={{ color: '#475569', fontStyle: 'italic' }}>Unnamed</span>}
                    </td>
                    <td><RiskBadge risk={r.overall_risk} /></td>
                    <td>
                      <span style={{ fontWeight: 800, fontSize: '1rem', color: '#e2e8f0' }}>{r.overall_score}</span>
                      <span style={{ color: '#64748b', fontSize: '0.75rem' }}>/100</span>
                    </td>
                    <td style={{ color: '#94a3b8' }}>{r.specialists_run}</td>
                    <td>
                      <span style={{
                        fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: 99,
                        background: r.status === 'completed' ? 'rgba(16,185,129,0.1)' : 'rgba(99,102,241,0.1)',
                        color: r.status === 'completed' ? '#6ee7b7' : '#a5b4fc',
                        border: `1px solid ${r.status === 'completed' ? 'rgba(16,185,129,0.3)' : 'rgba(99,102,241,0.3)'}`,
                      }}>{r.status}</span>
                    </td>
                    <td style={{ color: '#64748b', fontSize: '0.75rem' }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td>
                      <Link to={`/reports/${r.report_id}`} style={{ color: '#6366f1', textDecoration: 'none', fontSize: '0.8rem', fontWeight: 600 }}>
                        View →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {total > limit && (
          <div style={{ padding: '1rem 1.5rem', borderTop: '1px solid rgba(99,102,241,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Showing {offset + 1}–{Math.min(offset + limit, total)} of {total}
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn-ghost" disabled={offset === 0} onClick={() => setOffset(o => Math.max(0, o - limit))} style={{ padding: '0.375rem 0.75rem', fontSize: '0.8rem' }}>← Prev</button>
              <button className="btn-ghost" disabled={offset + limit >= total} onClick={() => setOffset(o => o + limit)} style={{ padding: '0.375rem 0.75rem', fontSize: '0.8rem' }}>Next →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
