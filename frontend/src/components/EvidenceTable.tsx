interface Props {
  findings: string[]
  title?: string
}

export default function EvidenceTable({ findings, title = 'Evidence & Findings' }: Props) {
  if (!findings.length) {
    return (
      <div className="glass" style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
        No findings recorded.
      </div>
    )
  }

  return (
    <div className="glass" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid rgba(99,102,241,0.1)' }}>
        <h3 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>{title}</h3>
        <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>{findings.length} item{findings.length !== 1 ? 's' : ''}</p>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th style={{ width: 48 }}>#</th>
              <th>Finding</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={i}>
                <td style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.75rem' }}>{String(i + 1).padStart(2, '0')}</td>
                <td style={{ color: '#cbd5e1', lineHeight: 1.5 }}>{f}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
