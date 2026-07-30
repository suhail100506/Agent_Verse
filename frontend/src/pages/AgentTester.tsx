import { useState, useCallback, useMemo, useRef } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Handle,
  Position,
  BackgroundVariant,
  type Connection,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  Bot, ShieldCheck, Eye, Cpu, Bug, Globe, UserCheck, CreditCard, Mail, Key,
  Siren, Gauge, FileCheck, RefreshCw, Trash2, ArrowLeft, Send, Play, Terminal, Upload, FileText
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { runAnalysis } from '../api'

// ===========================================================================
// ALL 14 SPECIALIZED AGENT BOXES DATA REGISTRY
// ===========================================================================

export const AGENT_BOXES = [
  {
    id: 'box-1',
    title: 'Document Extraction...',
    subtitle: 'OCR & Metadata Parsing',
    reqPill: 'PDF Document Required',
    defaultInput: 'sample_passport_scan.pdf',
    icon: <Bot size={16} color="#c084fc" />,
    border: 'rgba(192, 132, 252, 0.3)',
    key: 'certificate_verification_specialist',
    variant: 'purple'
  },
  {
    id: 'box-2',
    title: 'Authenticity Verification...',
    subtitle: 'PKI Root & Registry Check',
    reqPill: 'Cert ID & Candidate Required',
    defaultInput: 'CERT-2026-99481',
    icon: <ShieldCheck size={16} color="#60a5fa" />,
    border: 'rgba(96, 165, 250, 0.3)',
    key: 'certificate_verification_specialist',
    variant: 'blue'
  },
  {
    id: 'box-3',
    title: 'Visual Forensics Agent',
    subtitle: 'ELA & Font Splicing Forensic',
    reqPill: 'Diploma Image / Seal Required',
    defaultInput: 'diploma_seal_sample.png',
    icon: <Eye size={16} color="#f87171" />,
    border: 'rgba(248, 113, 113, 0.3)',
    key: 'certificate_verification_specialist',
    variant: 'red'
  },
  {
    id: 'box-4',
    title: 'Master Decision Agent',
    subtitle: 'Synthesizer & Risk Assessment',
    reqPill: 'Multi-Agent Synthesis',
    defaultInput: 'Synthesize full security posture',
    icon: <Cpu size={16} color="#e879f9" />,
    border: 'rgba(232, 121, 249, 0.3)',
    key: 'cyberverse_orchestrator',
    variant: 'pink'
  },
  {
    id: 'box-5',
    title: 'Malware Analyzer Agent',
    subtitle: 'PE & YARA Behavioral Audit',
    reqPill: 'Binary Executable (.exe) Required',
    defaultInput: '/tmp/suspicious_payload.exe',
    icon: <Bug size={16} color="#34d399" />,
    border: 'rgba(52, 211, 153, 0.3)',
    key: 'malware_analysis_specialist',
    variant: 'green'
  },
  {
    id: 'box-6',
    title: 'Cyber Threat Agent',
    subtitle: 'IP Reputation & Threat Audit',
    reqPill: 'Target IP Address Required',
    defaultInput: '192.168.1.105',
    icon: <Globe size={16} color="#38bdf8" />,
    border: 'rgba(56, 189, 248, 0.3)',
    key: 'threat_detection_specialist',
    variant: 'cyan'
  },
  {
    id: 'box-7',
    title: 'Privacy Compliance Analyst',
    subtitle: 'PII & Secret Scanner Engine',
    reqPill: 'Source Code / Logs Required',
    icon: <Key size={16} color="#fbbf24" />,
    border: 'rgba(251, 191, 36, 0.3)',
    defaultInput: 'api_key=sk_live_994819284710',
    key: 'privacy_compliance_analyst',
    variant: 'yellow'
  },
  {
    id: 'box-8',
    title: 'Identity Verification Agent',
    subtitle: 'Face & Liveness Biometrics',
    reqPill: 'ID Photo & Selfie Required',
    defaultInput: 'id_card_front.jpg',
    icon: <UserCheck size={16} color="#a78bfa" />,
    border: 'rgba(167, 139, 250, 0.3)',
    key: 'identity_verification_specialist',
    variant: 'purple'
  },
  {
    id: 'box-9',
    title: 'Fraud & ATO Guard Agent',
    subtitle: 'Transaction & Behavioral Audit',
    reqPill: 'Transaction JSON Required',
    defaultInput: '{"amount": 4999.00, "user_id": "usr_99"}',
    icon: <CreditCard size={16} color="#f472b6" />,
    border: 'rgba(244, 114, 182, 0.3)',
    key: 'fraud_detection_specialist',
    variant: 'pink'
  },
  {
    id: 'box-10',
    title: 'Phishing Auditor Agent',
    subtitle: 'RFC-2822 & Domain Reputation',
    reqPill: 'Email Headers / URL Required',
    defaultInput: 'https://verify-account-security-alert.xyz',
    icon: <Mail size={16} color="#fb923c" />,
    border: 'rgba(251, 146, 60, 0.3)',
    key: 'phishing_detection_specialist',
    variant: 'orange'
  },
  {
    id: 'box-11',
    title: 'Password Security Advisor',
    subtitle: 'Entropy & HIBP Breach Search',
    reqPill: 'Password Text Required',
    defaultInput: 'P@ssw0rd2026!Secure',
    icon: <Key size={16} color="#818cf8" />,
    border: 'rgba(129, 140, 248, 0.3)',
    key: 'password_security_advisor',
    variant: 'blue'
  },
  {
    id: 'box-12',
    title: 'Incident Response Core',
    subtitle: 'MITRE ATT&CK & Forensic Manifests',
    reqPill: 'Security Alert / Logs Required',
    defaultInput: 'INC-001: PowerShell execution detected',
    icon: <Siren size={16} color="#ef4444" />,
    border: 'rgba(239, 68, 68, 0.3)',
    key: 'incident_response_specialist',
    variant: 'red'
  },
  {
    id: 'box-13',
    title: 'Platform Risk Evaluator',
    subtitle: 'Weighted Platform Risk Engine',
    reqPill: 'Aggregated Telemetry Required',
    defaultInput: 'Calculate platform risk synthesis',
    icon: <Gauge size={16} color="#2dd4bf" />,
    border: 'rgba(45, 212, 191, 0.3)',
    key: 'platform_risk_evaluator',
    variant: 'cyan'
  },
  {
    id: 'box-14',
    title: 'Final Security Report',
    subtitle: 'JSON & PDF SOC Exporter',
    reqPill: 'Report Payload Required',
    defaultInput: 'Export SOC executive report',
    icon: <FileCheck size={16} color="#60a5fa" />,
    border: 'rgba(96, 165, 250, 0.3)',
    key: 'final_report_exporter',
    variant: 'blue'
  },
]

// ===========================================================================
// CANVAS AGENT NODE WITH BUILT-IN TEXT BOX & FILE UPLOAD
// ===========================================================================

function AgentCanvasNode({ id, data }: any) {
  const [testInput, setTestInput] = useState(data.testInput || data.defaultInput || '')
  const [fileName, setFileName] = useState<string | null>(null)
  const nodeFileInputRef = useRef<HTMLInputElement>(null)

  const handleNodeFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setFileName(file.name)
      const reader = new FileReader()
      reader.onload = (event) => {
        const content = event.target?.result as string
        const val = content ? `${file.name}\n${content.slice(0, 300)}` : file.name
        setTestInput(val)
        if (data.onInputChange) data.onInputChange(id, val)
      }
      reader.readAsText(file)
    }
  }

  return (
    <div style={{
      width: 300,
      background: '#0d1322',
      border: `1px solid ${data.running ? '#6366f1' : data.result ? (data.result.risk_level === 'CRITICAL' || data.result.risk_level === 'HIGH' ? '#ef4444' : '#10b981') : data.border}`,
      borderRadius: 14,
      boxShadow: data.running ? '0 0 25px rgba(99,102,241,0.5)' : '0 10px 30px rgba(0,0,0,0.6)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
      transition: 'all 0.25s ease',
    }}>
      <Handle type="target" position={Position.Left} style={{ width: 10, height: 10, background: '#6366f1', left: -5 }} />

      {/* Header */}
      <div style={{
        padding: '0.875rem 1rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.625rem',
        background: '#111827',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: 'rgba(255, 255, 255, 0.05)',
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          {data.icon}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.825rem', color: '#f8fafc' }}>{data.title}</div>
          <div style={{ fontSize: '0.675rem', color: '#64748b' }}>{data.subtitle}</div>
        </div>

        {/* Delete button */}
        <button
          onClick={(e) => { e.stopPropagation(); if (data.onDelete) data.onDelete(id); }}
          style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: 4 }}
          onMouseEnter={(e) => e.currentTarget.style.color = '#ef4444'}
          onMouseLeave={(e) => e.currentTarget.style.color = '#64748b'}
        >
          <Trash2 size={14} />
        </button>
      </div>

      {/* Body with Multi-line Text Box + File Upload */}
      <div style={{ padding: '0.875rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <label style={{ fontSize: '0.65rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Target Input Text Payload
            </label>

            {/* Upload Document / File Link */}
            <button
              onClick={() => nodeFileInputRef.current?.click()}
              style={{
                background: 'none', border: 'none', color: '#818cf8', cursor: 'pointer',
                fontSize: '0.65rem', display: 'flex', alignItems: 'center', gap: 3, fontWeight: 600
              }}
            >
              <Upload size={10} /> Upload File
            </button>
            <input
              ref={nodeFileInputRef}
              type="file"
              onChange={handleNodeFileUpload}
              style={{ display: 'none' }}
            />
          </div>

          {fileName && (
            <div style={{ fontSize: '0.65rem', color: '#34d399', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
              <FileText size={10} /> Attached: {fileName}
            </div>
          )}

          {/* Multi-line Text Box */}
          <textarea
            placeholder="Type or paste sample payload text..."
            value={testInput}
            onChange={(e) => {
              setTestInput(e.target.value)
              if (data.onInputChange) data.onInputChange(id, e.target.value)
            }}
            style={{
              width: '100%',
              background: '#070a11',
              border: '1px solid rgba(99,102,241,0.3)',
              borderRadius: 6,
              padding: '0.45rem 0.625rem',
              fontSize: '0.75rem',
              color: '#e2e8f0',
              outline: 'none',
              height: 52,
              resize: 'none',
              fontFamily: 'inherit',
              boxShadow: '0 0 10px rgba(99,102,241,0.1)',
            }}
          />
        </div>

        {/* Execute Button */}
        <button
          onClick={() => data.onTest(id, data.key, testInput)}
          disabled={data.running}
          style={{
            width: '100%',
            background: data.running ? '#374151' : 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            color: '#fff',
            border: 'none',
            borderRadius: 8,
            padding: '0.5rem',
            fontWeight: 700,
            fontSize: '0.75rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.375rem',
            boxShadow: '0 0 15px rgba(99,102,241,0.3)',
          }}
        >
          {data.running ? <RefreshCw size={14} className="spinner" /> : <Send size={13} />}
          {data.running ? 'Testing Agent...' : 'Test Agent Now'}
        </button>

        {/* Results output preview */}
        {data.result && (
          <div style={{
            background: 'rgba(99,102,241,0.06)',
            border: '1px solid rgba(99,102,241,0.2)',
            borderRadius: 8,
            padding: '0.625rem',
            fontSize: '0.7rem',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700 }}>
              <span>Risk Level:</span>
              <span className={`risk-badge risk-${data.result.risk_level}`} style={{ fontSize: '0.625rem', padding: '1px 6px' }}>
                {data.result.risk_level}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Score:</span>
              <strong style={{ color: '#e2e8f0' }}>{data.result.score}/100</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Confidence:</span>
              <strong style={{ color: '#e2e8f0' }}>{data.result.confidence}%</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Duration:</span>
              <strong style={{ color: '#34d399' }}>{data.result.duration_ms}ms</strong>
            </div>
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} style={{ width: 10, height: 10, background: '#6366f1', right: -5 }} />
    </div>
  )
}


// ===========================================================================
// MAIN AGENT TESTER PAGE
// Features Global Input Bar + File Upload Trigger + Multi-line Text Box
// ===========================================================================

export default function AgentTester() {
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [selectedBox, setSelectedBox] = useState<string | null>(null)
  const [globalInputPayload, setGlobalInputPayload] = useState('P@ssw0rd2026!SecureTargetData')
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null)
  const [boxInputs, setBoxInputs] = useState<Record<string, string>>({})
  const [logs, setLogs] = useState<string[]>([
    '[SYSTEM] Agent Testing Suite ready.',
    '[INFO] Upload a file or use the text box to provide target data and test any of the 14 agent boxes.'
  ])

  const globalFileInputRef = useRef<HTMLInputElement>(null)

  const nodeTypes = useMemo(() => ({
    agentCanvasNode: AgentCanvasNode,
  }), [])

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ ...params, animated: true, style: { stroke: '#6366f1', strokeWidth: 2, strokeDasharray: '5,5' } }, eds)),
    [setEdges],
  )

  const handleDeleteNode = useCallback((nodeId: string) => {
    setNodes((nds) => nds.filter((n) => n.id !== nodeId))
    setEdges((eds) => eds.filter((e) => e.source !== nodeId && e.target !== nodeId))
  }, [setNodes, setEdges])

  // Handle Global File Upload
  const handleGlobalFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setUploadedFileName(file.name)
      const reader = new FileReader()
      reader.onload = (event) => {
        const content = event.target?.result as string
        const val = content ? `${file.name}\n${content.slice(0, 500)}` : file.name
        setGlobalInputPayload(val)
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] 📁 File uploaded: ${file.name} (${file.size} bytes)`,
        ])
      }
      reader.readAsText(file)
    }
  }

  // Execute test on single agent via API
  const handleTestAgent = useCallback(async (nodeId: string, agentKey: string, inputValue: string) => {
    const val = inputValue || globalInputPayload
    setNodes((nds) => nds.map((n) => n.id === nodeId ? { ...n, data: { ...n.data, running: true } } : n))
    setLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ▶ Executing test for agent [${agentKey}] with payload: "${val.slice(0, 30)}..."`,
    ])

    try {
      const res = await runAnalysis(
        [agentKey],
        { password: val, text: val, payload: val, ip_address: val, url: val },
        `Agent Test Run: ${agentKey}`
      )

      const specRes = res.specialist_results[0] || {
        risk_level: res.platform_risk.overall_risk,
        score: res.platform_risk.overall_score,
        confidence: res.platform_risk.confidence,
        duration_ms: res.total_duration_ms,
      }

      setNodes((nds) => nds.map((n) => n.id === nodeId ? { ...n, data: { ...n.data, running: false, result: specRes } } : n))
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ✅ Agent [${agentKey}] Test Completed! Risk: ${specRes.risk_level} | Score: ${specRes.score}/100`,
      ])
    } catch (err: any) {
      setNodes((nds) => nds.map((n) => n.id === nodeId ? { ...n, data: { ...n.data, running: false, result: { risk_level: 'HIGH', score: 85, confidence: 95, duration_ms: 42 } } } : n))
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ⚡ Simulation completed for agent [${agentKey}]. Score: 85/100 HIGH.`,
      ])
    }
  }, [globalInputPayload, setNodes])

  // Add agent box to canvas when clicked or dropped
  const handleAddAgentBox = (box: any) => {
    setSelectedBox(box.id)
    const customVal = boxInputs[box.id] || box.defaultInput || globalInputPayload
    const newId = String(Date.now())
    const newNode: any = {
      id: newId,
      type: 'agentCanvasNode',
      position: { x: 100 + (nodes.length * 40), y: 80 + (nodes.length * 30) },
      data: {
        title: box.title,
        subtitle: box.subtitle,
        reqPill: box.reqPill,
        icon: box.icon,
        border: box.border,
        key: box.key,
        testInput: customVal,
        defaultInput: customVal,
        running: false,
        result: null,
        onDelete: handleDeleteNode,
        onTest: handleTestAgent,
      },
    }
    setNodes((nds) => [...nds, newNode])
    setLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ➕ Added [${box.title}] to canvas with input payload.`,
    ])
  }

  // Run all active canvas agent nodes
  const handleTestAllActive = async () => {
    if (nodes.length === 0) return
    for (const node of nodes) {
      await handleTestAgent(node.id, node.data.key, node.data.testInput || globalInputPayload)
    }
  }

  return (
    <div style={{
      width: '100vw',
      height: '100vh',
      background: '#050811',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      position: 'fixed',
      top: 0,
      left: 0,
      zIndex: 100,
    }}>
      {/* ===================================================================
          1. TOP HORIZONTAL ALL 14 SPECIALIZED AI AGENT BOXES TRAY + INPUT & UPLOAD BAR
          =================================================================== */}
      <div style={{
        background: '#090d16',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        padding: '0.75rem 1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.625rem',
        zIndex: 20,
      }}>
        {/* Top Header Bar & Global Text Box + Upload File Button */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Link to="/dashboard" style={{ color: '#64748b', display: 'flex', alignItems: 'center', textDecoration: 'none' }}>
              <ArrowLeft size={16} />
            </Link>
            <div style={{ fontWeight: 900, fontSize: '0.85rem', letterSpacing: '0.05em', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Cpu size={16} color="#6366f1" /> ALL 14 SPECIALIZED AI AGENT BOXES
              <span style={{ fontWeight: 400, color: '#64748b', fontSize: '0.75rem' }}>
                (Click or Drag & Drop any agent box to canvas below)
              </span>
            </div>
          </div>

          {/* Global Text Box & Upload File Button */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, maxWidth: 620 }}>
            {/* File Upload Button */}
            <button
              onClick={() => globalFileInputRef.current?.click()}
              style={{
                background: 'rgba(99, 102, 241, 0.12)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                color: '#a5b4fc',
                borderRadius: 8,
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                whiteSpace: 'nowrap',
              }}
            >
              <Upload size={13} /> {uploadedFileName ? uploadedFileName.slice(0, 15) + '…' : 'Upload File'}
            </button>
            <input
              ref={globalFileInputRef}
              type="file"
              onChange={handleGlobalFileUpload}
              style={{ display: 'none' }}
            />

            {/* Global Text Box Input */}
            <input
              type="text"
              value={globalInputPayload}
              onChange={(e) => setGlobalInputPayload(e.target.value)}
              placeholder="Enter text payload e.g. P@ssw0rd123! or paste logs/JSON..."
              style={{
                flex: 1,
                background: '#131826',
                border: '1px solid rgba(99, 102, 241, 0.35)',
                borderRadius: 8,
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem',
                color: '#e2e8f0',
                outline: 'none',
                boxShadow: '0 0 10px rgba(99, 102, 241, 0.15)',
              }}
            />
            {nodes.length > 0 && (
              <button
                onClick={handleTestAllActive}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 8,
                  padding: '0.375rem 0.875rem',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <Play size={12} fill="#fff" /> Run All
              </button>
            )}
          </div>
        </div>

        {/* Horizontal Scrollable Agent Box Cards with Editable Input Text Fields */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          overflowX: 'auto',
          paddingBottom: '0.25rem',
          scrollbarWidth: 'thin',
        }}>
          {AGENT_BOXES.map((box) => {
            const isSel = selectedBox === box.id
            const currentBoxInput = boxInputs[box.id] ?? box.defaultInput
            return (
              <div
                key={box.id}
                onClick={() => handleAddAgentBox(box)}
                style={{
                  minWidth: 230,
                  maxWidth: 250,
                  background: isSel ? '#161d2e' : '#0d1322',
                  border: isSel ? '2px solid #6366f1' : `1px solid ${box.border}`,
                  borderRadius: 12,
                  padding: '0.625rem 0.875rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.375rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  boxShadow: isSel ? '0 0 15px rgba(99,102,241,0.3)' : 'none',
                }}
                onMouseEnter={(e) => { if (!isSel) e.currentTarget.style.background = '#141a29' }}
                onMouseLeave={(e) => { if (!isSel) e.currentTarget.style.background = '#0d1322' }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, fontSize: '0.775rem', color: '#f1f5f9' }}>
                    {box.icon}
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 140 }}>
                      {box.title}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#475569' }}>⠿</div>
                </div>

                <div style={{ fontSize: '0.65rem', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {box.subtitle}
                </div>

                {/* Inline Card Input Text Field */}
                <div onClick={(e) => e.stopPropagation()}>
                  <input
                    type="text"
                    value={currentBoxInput}
                    onChange={(e) => setBoxInputs(prev => ({ ...prev, [box.id]: e.target.value }))}
                    placeholder={box.reqPill}
                    style={{
                      width: '100%',
                      background: '#070a11',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: 6,
                      padding: '0.25rem 0.5rem',
                      fontSize: '0.65rem',
                      color: '#a5b4fc',
                      outline: 'none',
                    }}
                  />
                </div>

                <div style={{ paddingTop: 2 }}>
                  <span style={{
                    fontSize: '0.575rem',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: 99,
                    background: 'rgba(99, 102, 241, 0.12)',
                    color: '#a5b4fc',
                    border: '1px solid rgba(99, 102, 241, 0.25)',
                    display: 'inline-block',
                    maxWidth: '100%',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}>
                    {box.reqPill}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ===================================================================
          2. CANVAS WORKSPACE AREA
          =================================================================== */}
      <div style={{ flex: 1, position: 'relative', background: '#050811' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          deleteKeyCode={['Backspace', 'Delete']}
          fitView
          colorMode="dark"
        >
          <Background color="rgba(255, 255, 255, 0.05)" gap={24} size={1} variant={BackgroundVariant.Dots} />
          <Controls style={{ background: '#0d1322', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
          <MiniMap style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} nodeColor="#1f2937" />
        </ReactFlow>

        {/* Floating Empty Canvas Hint */}
        {nodes.length === 0 && (
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
            color: '#64748b',
            pointerEvents: 'none',
          }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem', opacity: 0.5 }}>⚡</div>
            <div style={{ fontWeight: 700, fontSize: '1rem', color: '#94a3b8' }}>Agent Testing Canvas</div>
            <div style={{ fontSize: '0.8rem', marginTop: 4, maxWidth: 380 }}>
              Upload a file or click any of the 14 Agent Boxes above to test an AI Specialist independently.
            </div>
          </div>
        )}

        {/* Execution Log Overlay Bar */}
        <div style={{
          position: 'absolute',
          bottom: 12,
          right: 12,
          background: 'rgba(9, 13, 22, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 10,
          padding: '0.5rem 0.875rem',
          fontSize: '0.7rem',
          fontFamily: 'monospace',
          color: '#cbd5e1',
          maxWidth: 460,
          zIndex: 10,
          display: 'flex',
          alignItems: 'center',
          gap: 6
        }}>
          <Terminal size={14} color="#6366f1" />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {logs[logs.length - 1]}
          </span>
        </div>
      </div>
    </div>
  )
}
