interface Props {
  summary: string
  risk: string
  score: number
  confidence: number
}

const BG: Record<string, string> = {
  CRITICAL: 'rgba(239,68,68,0.08)',
  HIGH: 'rgba(245,158,11,0.08)',
  MEDIUM: 'rgba(249,115,22,0.08)',
  LOW: 'rgba(16,185,129,0.08)',
  UNKNOWN: 'rgba(100,116,139,0.08)',
}
const BORDER: Record<string, string> = {
  CRITICAL: 'rgba(239,68,68,0.3)',
  HIGH: 'rgba(245,158,11,0.3)',
  MEDIUM: 'rgba(249,115,22,0.25)',
  LOW: 'rgba(16,185,129,0.25)',
  UNKNOWN: 'rgba(100,116,139,0.2)',
}

export default function ExecutiveSummary({ summary, risk, score, confidence }: Props) {
  return (
    <div style={{
      padding: '1.5rem 2rem',
      background: BG[risk] ?? BG.UNKNOWN,
      border: `1px solid ${BORDER[risk] ?? BORDER.UNKNOWN}`,
      borderRadius: 16,
      display: 'flex', flexDirection: 'column', gap: '1rem',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <span style={{ fontSize: '1.25rem' }}>
          {risk === 'CRITICAL' ? '🚨' : risk === 'HIGH' ? '⚠️' : risk === 'MEDIUM' ? '⚡' : '✅'}
        </span>
        <div>
          <div style={{ fontWeight: 800, fontSize: '1rem', color: '#e2e8f0' }}>Executive Summary</div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 1 }}>
            Platform Score: <strong style={{ color: '#e2e8f0' }}>{score}/100</strong>
            {' · '}Confidence: <strong style={{ color: '#e2e8f0' }}>{confidence}%</strong>
          </div>
        </div>
      </div>
      <p style={{ fontSize: '0.875rem', lineHeight: 1.7, color: '#cbd5e1', margin: 0 }}>
        {summary}
      </p>
    </div>
  )
}
