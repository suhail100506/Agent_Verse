interface Props {
  recommendations: string[]
  title?: string
}

const PRIORITY_ICON = ['🔴', '🟠', '🟡', '🟢', '🔵']

export default function RecommendationList({ recommendations, title = 'Recommendations' }: Props) {
  if (!recommendations.length) {
    return (
      <div className="glass" style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
        No recommendations.
      </div>
    )
  }

  return (
    <div className="glass" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid rgba(99,102,241,0.1)' }}>
        <h3 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>{title}</h3>
        <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>Priority-ordered action items</p>
      </div>
      <ul style={{ listStyle: 'none', padding: '0.75rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {recommendations.map((rec, i) => (
          <li key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
            padding: '0.75rem 1rem', borderRadius: 10,
            background: 'rgba(99,102,241,0.04)',
            border: '1px solid rgba(99,102,241,0.08)',
            fontSize: '0.825rem', lineHeight: 1.5, color: '#cbd5e1',
            animation: `fadeInUp 0.3s ease ${i * 0.04}s both`,
          }}>
            <span style={{ fontSize: '1rem', flexShrink: 0, marginTop: 1 }}>
              {PRIORITY_ICON[Math.min(i, 4)]}
            </span>
            <span>{rec}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
