// RiskGauge.tsx — Animated SVG risk gauge

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#f97316',
  LOW: '#10b981',
  UNKNOWN: '#64748b',
}

interface Props {
  score: number
  risk: string
  size?: number
  label?: string
}

export default function RiskGauge({ score, risk, size = 180, label = 'Risk Score' }: Props) {
  const color = RISK_COLORS[risk] ?? RISK_COLORS.UNKNOWN
  const radius = (size - 20) / 2
  const circumference = Math.PI * radius // half circle
  const progress = (score / 100) * circumference
  const strokeWidth = size * 0.07

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
      <div style={{ position: 'relative', width: size, height: size / 2 + 20 }}>
        <svg width={size} height={size / 2 + 20} style={{ overflow: 'visible' }}>
          {/* Track */}
          <path
            d={`M ${10} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2}`}
            fill="none"
            stroke="rgba(99,102,241,0.1)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Progress */}
          <path
            d={`M ${10} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2}`}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dasharray 1s ease' }}
          />
          {/* Score text */}
          <text x={size / 2} y={size / 2 - 4} textAnchor="middle" fill="white"
            fontSize={size * 0.18} fontWeight="800" fontFamily="Inter">
            {score}
          </text>
          <text x={size / 2} y={size / 2 + 18} textAnchor="middle" fill={color}
            fontSize={size * 0.075} fontWeight="700" fontFamily="Inter" letterSpacing="2">
            {risk}
          </text>
        </svg>
      </div>
      <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 500, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
        {label}
      </span>
    </div>
  )
}
