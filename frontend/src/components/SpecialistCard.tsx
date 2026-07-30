import type { SpecialistResult } from '../api'

const RISK_DOT: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#f97316', LOW: '#10b981', UNKNOWN: '#64748b',
}

interface Props { result: SpecialistResult }

export default function SpecialistCard({ result }: Props) {
  const dot = RISK_DOT[result.risk_level] ?? RISK_DOT.UNKNOWN
  const pct = result.score

  return (
    <div className="glass-sm" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>{result.display_name}</div>
          {result.error && (
            <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: 2 }}>⚠ {result.error.slice(0, 60)}</div>
          )}
        </div>
        <span className={`risk-badge risk-${result.risk_level}`}>{result.risk_level}</span>
      </div>

      {/* Score bar */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
          <span style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Score</span>
          <span style={{ fontSize: '0.8rem', fontWeight: 800, color: dot }}>{pct}</span>
        </div>
        <div style={{ height: 5, borderRadius: 99, background: 'rgba(99,102,241,0.1)', overflow: 'hidden' }}>
          <div style={{
            height: '100%', borderRadius: 99, width: `${pct}%`,
            background: `linear-gradient(90deg, ${dot}88, ${dot})`,
            boxShadow: `0 0 8px ${dot}55`,
            transition: 'width 0.8s ease',
          }} />
        </div>
      </div>

      {/* Confidence + duration */}
      <div style={{ display: 'flex', gap: '1rem', fontSize: '0.7rem', color: '#64748b' }}>
        <span>Confidence: <strong style={{ color: '#94a3b8' }}>{result.confidence}%</strong></span>
        <span>Time: <strong style={{ color: '#94a3b8' }}>{result.duration_ms}ms</strong></span>
      </div>

      {/* Top finding */}
      {result.findings[0] && (
        <div style={{
          fontSize: '0.7rem', color: '#94a3b8', padding: '0.5rem 0.75rem',
          background: 'rgba(99,102,241,0.06)', borderRadius: 8, borderLeft: '2px solid rgba(99,102,241,0.4)',
        }}>
          {result.findings[0]}
        </div>
      )}
    </div>
  )
}
