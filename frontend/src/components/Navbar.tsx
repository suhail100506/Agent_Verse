import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Orchestration Flow', icon: '⚡' },
  { to: '/agent-testing', label: '14 Agent Boxes', icon: '🤖' },
  { to: '/dashboard', label: 'Dashboard', icon: '⬡' },
  { to: '/analyze', label: 'Analyze', icon: '⟳' },
  { to: '/reports', label: 'Reports', icon: '≡' },
]

export default function Navbar() {
  return (
    <nav style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 2rem', height: '54px',
      background: 'rgba(5,11,24,0.95)', backdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(99,102,241,0.15)',
      position: 'sticky', top: 0, zIndex: 50,
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '0.9rem', fontWeight: 800, color: 'white',
          boxShadow: '0 0 15px rgba(99,102,241,0.4)',
        }}>⚡</div>
        <span style={{ fontWeight: 800, fontSize: '1.05rem', letterSpacing: '-0.01em' }}>
          <span className="gradient-text">Cyber</span>
          <span style={{ color: '#e2e8f0' }}>Verse</span>
        </span>
        <span style={{
          fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.12em',
          textTransform: 'uppercase', color: '#6366f1',
          background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)',
          borderRadius: 6, padding: '2px 6px', marginLeft: 4,
        }}>Enterprise</span>
      </div>

      {/* Nav links */}
      <div style={{ display: 'flex', gap: '0.25rem' }}>
        {links.map(({ to, label, icon }) => (
          <NavLink key={to} to={to} end={to === '/'} style={({ isActive }) => ({
            display: 'flex', alignItems: 'center', gap: '0.5rem',
            padding: '0.45rem 0.875rem', borderRadius: 8,
            fontWeight: 600, fontSize: '0.8rem', textDecoration: 'none',
            color: isActive ? 'white' : '#64748b',
            background: isActive ? 'rgba(99,102,241,0.15)' : 'transparent',
            border: `1px solid ${isActive ? 'rgba(99,102,241,0.35)' : 'transparent'}`,
            transition: 'all 0.15s',
          })}>
            <span style={{ fontSize: '0.9rem' }}>{icon}</span>
            {label}
          </NavLink>
        ))}
      </div>

      {/* Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', display: 'inline-block', boxShadow: '0 0 8px #10b981' }} />
        Platform Operational
      </div>
    </nav>
  )
}
