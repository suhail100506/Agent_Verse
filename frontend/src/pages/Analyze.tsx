import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchSpecialists, runAnalysis, type SpecialistInfo, type OrchestratorReport } from '../api'

const INPUT_FIELDS = [
  { key: 'password', label: 'Password', placeholder: 'e.g. P@ssw0rd!123', type: 'text' },
  { key: 'file_path', label: 'File Path', placeholder: 'e.g. /path/to/file.exe', type: 'text' },
  { key: 'ip_address', label: 'IP Address', placeholder: 'e.g. 192.168.1.100', type: 'text' },
  { key: 'url', label: 'URL', placeholder: 'e.g. https://example.com', type: 'text' },
  { key: 'email_subject', label: 'Email Subject', placeholder: 'e.g. Verify your account now', type: 'text' },
  { key: 'domain', label: 'Domain', placeholder: 'e.g. suspicious-site.xyz', type: 'text' },
  { key: 'label', label: 'Analysis Label', placeholder: 'e.g. Production Audit Q3 2026', type: 'text' },
]

export default function Analyze() {
  const navigate = useNavigate()
  const [specialists, setSpecialists] = useState<SpecialistInfo[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [inputs, setInputs] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchSpecialists()
      .then(s => { setSpecialists(s); setSelected(new Set(s.map(x => x.key))) })
      .catch(() => setError('Could not load specialists. Is the API running?'))
  }, [])

  const toggle = (key: string) => {
    const next = new Set(selected)
    next.has(key) ? next.delete(key) : next.add(key)
    setSelected(next)
  }

  const selectAll = () => setSelected(new Set(specialists.map(s => s.key)))
  const clearAll = () => setSelected(new Set())

  const handleInput = (key: string, val: string) =>
    setInputs(prev => ({ ...prev, [key]: val }))

  const handleSubmit = async () => {
    setLoading(true)
    setError('')
    try {
      const { label, ...rest } = inputs
      const report: OrchestratorReport = await runAnalysis(
        Array.from(selected),
        rest,
        label || undefined,
      )
      navigate(`/reports/${report.report_id}`)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Analysis failed.')
      setLoading(false)
    }
  }

  return (
    <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '2rem', maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
          <span className="gradient-text">New Security Analysis</span>
        </h1>
        <p style={{ color: '#64748b', fontSize: '0.875rem', marginTop: '0.5rem' }}>
          Select specialists and provide target data. Empty fields are gracefully skipped.
        </p>
      </div>

      {error && (
        <div style={{ padding: '1rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 10, color: '#fca5a5', fontSize: '0.875rem' }}>
          ⚠ {error}
        </div>
      )}

      {/* Specialists */}
      <div className="glass" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>Select Specialists</h2>
            <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>{selected.size} of {specialists.length} selected</p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn-ghost" onClick={selectAll} style={{ fontSize: '0.75rem', padding: '0.375rem 0.875rem' }}>All</button>
            <button className="btn-ghost" onClick={clearAll} style={{ fontSize: '0.75rem', padding: '0.375rem 0.875rem' }}>None</button>
          </div>
        </div>
        <div className="checkbox-grid">
          {specialists.map(s => (
            <label key={s.key} className={`checkbox-item${selected.has(s.key) ? ' checked' : ''}`}>
              <input type="checkbox" checked={selected.has(s.key)} onChange={() => toggle(s.key)} />
              <span style={{ fontSize: '0.8rem', color: '#cbd5e1', fontWeight: 500 }}>{s.display_name}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Inputs */}
      <div className="glass" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <h2 style={{ fontWeight: 700, fontSize: '0.875rem', color: '#e2e8f0' }}>Target Data</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          {INPUT_FIELDS.map(({ key, label, placeholder, type }) => (
            <div key={key} style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', letterSpacing: '0.03em' }}>{label}</label>
              <input
                className="input"
                type={type}
                placeholder={placeholder}
                value={inputs[key] ?? ''}
                onChange={e => handleInput(key, e.target.value)}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Submit */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', alignItems: 'center' }}>
        {loading && (
          <span style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className="spinner" /> Running {selected.size} specialist{selected.size !== 1 ? 's' : ''}…
          </span>
        )}
        <button
          className="btn-primary"
          disabled={loading || selected.size === 0}
          onClick={handleSubmit}
          id="btn-run-analysis"
          style={{ fontSize: '0.9rem', padding: '0.75rem 2rem' }}
        >
          {loading ? 'Analyzing…' : '⚡ Run Analysis'}
        </button>
      </div>
    </div>
  )
}
