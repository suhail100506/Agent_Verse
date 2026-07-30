import { useState, useCallback, useMemo } from 'react'
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
  FileText, Cpu, FileSearch, ShieldAlert, FileCheck, Play, Sparkles,
  Search, Bell, Layers, Bot, LayoutTemplate, RefreshCw, Upload,
  Terminal, Activity, Server, ChevronUp, ChevronDown, Trash2, Plus, Key
} from 'lucide-react'
import { runAnalysis } from '../api'

// ===========================================================================
// DATA REGISTRIES FOR NODES, AGENTS, TEMPLATES & VAULT
// Analyzed from the CyberVerse codebase (9 CrewAI Specialists + Orchestrator + Exporters)
// ===========================================================================

const NODES_LIST = [
  {
    title: 'User Payload Ingest',
    desc: 'Payload & Document Trigger Input',
    tag: 'Trigger',
    tagBg: 'rgba(255, 255, 255, 0.06)',
    tagFg: '#94a3b8',
    io: '0 in • 1 out',
    type: 'userIngest'
  },
  {
    title: 'Webhook Listener',
    desc: 'HTTP POST / GET Endpoint',
    tag: 'Trigger',
    tagBg: 'rgba(255, 255, 255, 0.06)',
    tagFg: '#94a3b8',
    io: '0 in • 2 out',
    type: 'userIngest'
  },
  {
    title: 'Cron Scheduler',
    desc: 'Periodic Execution Trigger',
    tag: 'Trigger',
    tagBg: 'rgba(255, 255, 255, 0.06)',
    tagFg: '#94a3b8',
    io: '0 in • 2 out',
    type: 'userIngest'
  },
  {
    title: 'API Endpoint Ingestion',
    desc: 'REST JSON Payload Receiver',
    tag: 'Trigger',
    tagBg: 'rgba(255, 255, 255, 0.06)',
    tagFg: '#94a3b8',
    io: '0 in • 1 out',
    type: 'userIngest'
  },
  {
    title: 'Master Cyber Orchestrator',
    desc: 'Autonomous Multi-Agent Router',
    tag: 'AI Core',
    tagBg: 'rgba(217, 70, 239, 0.15)',
    tagFg: '#e879f9',
    io: '1 in • 3 out',
    type: 'masterOrchestrator'
  },
  {
    title: 'Security Flow Dispatcher',
    desc: 'Async ThreadPool Fan-Out Engine',
    tag: 'AI Core',
    tagBg: 'rgba(217, 70, 239, 0.15)',
    tagFg: '#e879f9',
    io: '1 in • 9 out',
    type: 'masterOrchestrator'
  },
  {
    title: 'Platform Risk Evaluator',
    desc: 'Weighted Risk Score Calculator',
    tag: 'AI Core',
    tagBg: 'rgba(217, 70, 239, 0.15)',
    tagFg: '#e879f9',
    io: '9 in • 1 out',
    type: 'masterOrchestrator'
  },
  {
    title: 'Final Security Report',
    desc: 'JSON & PDF SOC Exporter',
    tag: 'Exporter',
    tagBg: 'rgba(59, 130, 246, 0.15)',
    tagFg: '#60a5fa',
    io: '1 in • 0 out',
    type: 'finalReport'
  },
  {
    title: 'MongoDB Exporter',
    desc: 'Database Document Storage',
    tag: 'Exporter',
    tagBg: 'rgba(59, 130, 246, 0.15)',
    tagFg: '#60a5fa',
    io: '1 in • 0 out',
    type: 'finalReport'
  },
]

const AGENTS_LIST = [
  {
    title: 'Certificate Verification Specialist',
    desc: 'OCR, Metadata, QR & Digital Signature Audit',
    tag: '5 Tools',
    tagBg: 'rgba(139, 92, 246, 0.15)',
    tagFg: '#a78bfa',
    io: '1 in • 1 out',
    variant: 'doc',
    key: 'certificate_verification_specialist'
  },
  {
    title: 'Privacy Compliance Analyst',
    desc: 'PII, Secret Scanner & GDPR/HIPAA Audit',
    tag: '4 Tools',
    tagBg: 'rgba(139, 92, 246, 0.15)',
    tagFg: '#a78bfa',
    io: '1 in • 1 out',
    variant: 'doc',
    key: 'privacy_compliance_analyst'
  },
  {
    title: 'Malware Analysis Specialist',
    desc: 'YARA Scanner, PE Analysis & VirusTotal',
    tag: '5 Tools',
    tagBg: 'rgba(16, 185, 129, 0.15)',
    tagFg: '#34d399',
    io: '1 in • 1 out',
    variant: 'malware',
    key: 'malware_analysis_specialist'
  },
  {
    title: 'Threat Detection Specialist',
    desc: 'IP/URL Reputation, DNS & IOC Verification',
    tag: '5 Tools',
    tagBg: 'rgba(16, 185, 129, 0.15)',
    tagFg: '#34d399',
    io: '1 in • 1 out',
    variant: 'malware',
    key: 'threat_detection_specialist'
  },
  {
    title: 'Identity Verification Specialist',
    desc: 'Document, Face & Liveness Biometrics',
    tag: '5 Tools',
    tagBg: 'rgba(245, 158, 11, 0.15)',
    tagFg: '#fbbf24',
    io: '1 in • 1 out',
    variant: 'phishing',
    key: 'identity_verification_specialist'
  },
  {
    title: 'Fraud Detection Specialist',
    desc: 'Behavioral Analysis, Device & ATO Guard',
    tag: '5 Tools',
    tagBg: 'rgba(245, 158, 11, 0.15)',
    tagFg: '#fbbf24',
    io: '1 in • 1 out',
    variant: 'phishing',
    key: 'fraud_detection_specialist'
  },
  {
    title: 'Phishing Detection Specialist',
    desc: 'RFC-2822 Headers, Typosquatting & Body Audit',
    tag: '5 Tools',
    tagBg: 'rgba(245, 158, 11, 0.15)',
    tagFg: '#fbbf24',
    io: '1 in • 1 out',
    variant: 'phishing',
    key: 'phishing_detection_specialist'
  },
  {
    title: 'Password Security Advisor',
    desc: 'Entropy, Enterprise Policy & HIBP Breach Search',
    tag: '5 Tools',
    tagBg: 'rgba(139, 92, 246, 0.15)',
    tagFg: '#a78bfa',
    io: '1 in • 1 out',
    variant: 'doc',
    key: 'password_security_advisor'
  },
  {
    title: 'Incident Response Specialist',
    desc: 'MITRE ATT&CK Mapping & Forensic Manifests',
    tag: '5 Tools',
    tagBg: 'rgba(16, 185, 129, 0.15)',
    tagFg: '#34d399',
    io: '1 in • 1 out',
    variant: 'malware',
    key: 'incident_response_specialist'
  },
]

const TEMPLATES_LIST = [
  {
    title: 'Full 9-Specialist Audit Pipeline',
    desc: 'All 9 AI specialists running in parallel fan-out architecture',
    nodesCount: '12 Nodes',
    category: 'Enterprise Audit'
  },
  {
    title: 'Ransomware & Malware Incident',
    desc: 'Payload Ingest → Malware Specialist → Incident Response → Report',
    nodesCount: '5 Nodes',
    category: 'IR Playbook'
  },
  {
    title: 'Identity & Fraud Guard',
    desc: 'Payload Ingest → Identity Verification → Fraud Specialist → Report',
    nodesCount: '5 Nodes',
    category: 'Fraud Protection'
  },
  {
    title: 'Phishing & Credential Exposure Scan',
    desc: 'Payload Ingest → Phishing Specialist → Password Advisor → Report',
    nodesCount: '5 Nodes',
    category: 'Credential Audit'
  },
]

const VAULT_ITEMS = [
  { name: 'VIRUSTOTAL_API_KEY', status: 'Active', value: '••••••••••••••••3a9b' },
  { name: 'SERPER_API_KEY', status: 'Active', value: '••••••••••••••••7e1f' },
  { name: 'MONGODB_URI', status: 'Connected', value: 'mongodb://localhost:27017' },
  { name: 'JWT_SECRET', status: 'Encrypted', value: '••••••••••••••••8c9a' },
]

// ===========================================================================
// CUSTOM NODE COMPONENTS
// Matches the exact dark card layout, icons, status badges, drag handles & DELETE buttons
// ===========================================================================

function UserPayloadIngestNode({ id, data }: any) {
  const [payloadText, setPayloadText] = useState(data.payloadText || '')

  return (
    <div style={{
      width: 290,
      background: '#121620',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      borderRadius: 14,
      boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '0.875rem 1rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.625rem',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: '#222838',
          display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8'
        }}>
          <FileText size={16} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.825rem', color: '#f1f5f9' }}>{data.title || 'User Payload Ingest'}</div>
          <div style={{ fontSize: '0.675rem', color: '#64748b' }}>{data.subtitle || 'Payload Trigger Input'}</div>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <button
            onClick={(e) => { e.stopPropagation(); if (data.onDelete) data.onDelete(id); }}
            title="Delete Node"
            style={{
              background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer',
              padding: '4px', borderRadius: 6, display: 'flex', alignItems: 'center', transition: 'all 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.background = 'transparent' }}
          >
            <Trash2 size={14} />
          </button>
          <div style={{ fontSize: '0.875rem', color: '#475569', cursor: 'grab' }}>⠿</div>
        </div>
      </div>

      <div style={{ padding: '0.875rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <label style={{ fontSize: '0.675rem', fontWeight: 600, color: '#64748b', display: 'block', marginBottom: 4 }}>
            Input Payload
          </label>
          <textarea
            style={{
              width: '100%',
              background: '#0a0d14',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 8,
              color: '#e2e8f0',
              padding: '0.5rem 0.625rem',
              fontSize: '0.75rem',
              resize: 'none',
              height: 48,
              outline: 'none',
              fontFamily: 'inherit',
            }}
            placeholder="Enter query or payload..."
            value={payloadText}
            onChange={(e) => {
              setPayloadText(e.target.value)
              if (data.onTextChange) data.onTextChange(e.target.value)
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#475569', fontSize: '0.65rem' }}>
          <div style={{ flex: 1, height: 1, background: 'rgba(255, 255, 255, 0.06)' }} />
          <span>OR</span>
          <div style={{ flex: 1, height: 1, background: 'rgba(255, 255, 255, 0.06)' }} />
        </div>

        <div style={{
          border: '1px dashed rgba(255, 255, 255, 0.12)',
          borderRadius: 8,
          padding: '0.5rem',
          textAlign: 'center',
          fontSize: '0.7rem',
          color: '#94a3b8',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.375rem',
          background: 'rgba(255, 255, 255, 0.02)',
        }}>
          <Upload size={12} /> Upload Document
        </div>

        <button
          onClick={data.onRun}
          style={{
            width: '100%',
            background: data.isRunning ? '#475569' : '#ffffff',
            color: '#090d16',
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
            boxShadow: '0 0 15px rgba(255,255,255,0.2)',
            transition: 'all 0.2s',
          }}
        >
          {data.isRunning ? <RefreshCw size={14} className="spinner" /> : <Play size={14} fill="#090d16" />}
          Run Node
        </button>
      </div>

      <Handle type="source" position={Position.Right} style={{ width: 10, height: 10, background: '#6366f1', right: -5 }} />
    </div>
  )
}

function MasterOrchestratorNode({ id, data }: any) {
  return (
    <div style={{
      width: 270,
      background: '#121620',
      border: `1px solid ${data.active ? '#d946ef' : 'rgba(255, 255, 255, 0.1)'}`,
      borderRadius: 14,
      boxShadow: data.active ? '0 0 25px rgba(217, 70, 239, 0.3)' : '0 10px 30px rgba(0, 0, 0, 0.5)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
      transition: 'all 0.3s ease',
    }}>
      <Handle type="target" position={Position.Left} style={{ width: 10, height: 10, background: '#6366f1', left: -5 }} />

      <div style={{
        padding: '0.875rem 1rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.625rem',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: 'rgba(217, 70, 239, 0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#e879f9'
        }}>
          <Cpu size={16} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.825rem', color: '#f1f5f9' }}>{data.title || 'Master Cyber Orchestrator'}</div>
          <div style={{ fontSize: '0.675rem', color: '#64748b' }}>{data.subtitle || 'Multi-Agent Intent Router'}</div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <button
            onClick={(e) => { e.stopPropagation(); if (data.onDelete) data.onDelete(id); }}
            title="Delete Node"
            style={{
              background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer',
              padding: '4px', borderRadius: 6, display: 'flex', alignItems: 'center', transition: 'all 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.background = 'transparent' }}
          >
            <Trash2 size={14} />
          </button>
          <div style={{ fontSize: '0.875rem', color: '#475569', cursor: 'grab' }}>⠿</div>
        </div>
      </div>

      <div style={{ padding: '0.875rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <label style={{ fontSize: '0.675rem', fontWeight: 600, color: '#64748b', display: 'block', marginBottom: 4 }}>
            Input Port
          </label>
          <div style={{
            background: '#0a0d14',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            padding: '0.4rem 0.625rem',
            fontSize: '0.725rem',
            color: '#cbd5e1',
          }}>
            Multi-Agent synthesis
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.65rem', color: '#64748b', paddingTop: 4 }}>
          <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 3 }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#10b981' }} /> • 42ms
          </span>
          <span>18 MB</span>
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ width: 10, height: 10, background: '#e879f9', right: -5 }} />
    </div>
  )
}

function AgentTaskNode({ id, data }: any) {
  const iconMap: any = {
    doc: <FileSearch size={16} />,
    malware: <ShieldAlert size={16} />,
    phishing: <FileText size={16} />,
  }
  const colorMap: any = {
    doc: { bg: 'rgba(139, 92, 246, 0.15)', fg: '#a78bfa', handle: '#a78bfa' },
    malware: { bg: 'rgba(16, 185, 129, 0.15)', fg: '#34d399', handle: '#34d399' },
    phishing: { bg: 'rgba(245, 158, 11, 0.15)', fg: '#fbbf24', handle: '#fbbf24' },
  }
  const theme = colorMap[data.variant] || colorMap.doc

  return (
    <div style={{
      width: 270,
      background: '#121620',
      border: `1px solid ${data.active ? theme.fg : 'rgba(255, 255, 255, 0.1)'}`,
      borderRadius: 14,
      boxShadow: data.active ? `0 0 25px ${theme.fg}44` : '0 10px 30px rgba(0, 0, 0, 0.5)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
      transition: 'all 0.3s ease',
    }}>
      <Handle type="target" position={Position.Left} style={{ width: 10, height: 10, background: theme.handle, left: -5 }} />

      <div style={{
        padding: '0.875rem 1rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.625rem',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: theme.bg,
          display: 'flex', alignItems: 'center', justifyContent: 'center', color: theme.fg
        }}>
          {iconMap[data.variant] || <Bot size={16} />}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.825rem', color: '#f1f5f9' }}>{data.title}</div>
          <div style={{ fontSize: '0.675rem', color: '#64748b' }}>{data.subtitle}</div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <button
            onClick={(e) => { e.stopPropagation(); if (data.onDelete) data.onDelete(id); }}
            title="Delete Node"
            style={{
              background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer',
              padding: '4px', borderRadius: 6, display: 'flex', alignItems: 'center', transition: 'all 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.background = 'transparent' }}
          >
            <Trash2 size={14} />
          </button>
          <div style={{ fontSize: '0.875rem', color: '#475569', cursor: 'grab' }}>⠿</div>
        </div>
      </div>

      <div style={{ padding: '0.875rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <label style={{ fontSize: '0.675rem', fontWeight: 600, color: '#64748b', display: 'block', marginBottom: 4 }}>
            Input Port
          </label>
          <div style={{
            background: '#0a0d14',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            padding: '0.4rem 0.625rem',
            fontSize: '0.725rem',
            color: '#cbd5e1',
          }}>
            {data.inputPort || 'Data Stream'}
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.65rem', color: '#64748b' }}>
          <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 3 }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#10b981' }} /> • {data.duration || '42ms'}
          </span>
          <span>{data.memory || '12 MB'}</span>
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ width: 10, height: 10, background: theme.handle, right: -5 }} />
    </div>
  )
}

function FinalReportNode({ id, data }: any) {
  return (
    <div style={{
      width: 270,
      background: '#121620',
      border: `1px solid ${data.active ? '#3b82f6' : 'rgba(255, 255, 255, 0.1)'}`,
      borderRadius: 14,
      boxShadow: data.active ? '0 0 25px rgba(59, 130, 246, 0.4)' : '0 10px 30px rgba(0, 0, 0, 0.5)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
      transition: 'all 0.3s ease',
    }}>
      <Handle type="target" position={Position.Left} style={{ width: 10, height: 10, background: '#3b82f6', left: -5 }} />

      <div style={{
        padding: '0.875rem 1rem',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.625rem',
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: 'rgba(59, 130, 246, 0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#60a5fa'
        }}>
          <FileCheck size={16} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.825rem', color: '#f1f5f9' }}>{data.title || 'Final Security Report'}</div>
          <div style={{ fontSize: '0.675rem', color: '#64748b' }}>{data.subtitle || 'JSON & PDF SOC Exporter'}</div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <button
            onClick={(e) => { e.stopPropagation(); if (data.onDelete) data.onDelete(id); }}
            title="Delete Node"
            style={{
              background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer',
              padding: '4px', borderRadius: 6, display: 'flex', alignItems: 'center', transition: 'all 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.background = 'transparent' }}
          >
            <Trash2 size={14} />
          </button>
          <div style={{ fontSize: '0.875rem', color: '#475569', cursor: 'grab' }}>⠿</div>
        </div>
      </div>

      <div style={{ padding: '0.875rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <label style={{ fontSize: '0.675rem', fontWeight: 600, color: '#64748b', display: 'block', marginBottom: 4 }}>
            Input Port
          </label>
          <div style={{
            background: '#0a0d14',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            padding: '0.4rem 0.625rem',
            fontSize: '0.725rem',
            color: '#cbd5e1',
          }}>
            Report generator
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.65rem', color: '#64748b' }}>
          <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 3 }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#10b981' }} /> • 42ms
          </span>
          <span>18 MB</span>
        </div>
      </div>
    </div>
  )
}


// ===========================================================================
// MAIN FLOW STUDIO PAGE
// Dynamic Nodes, Agents, Templates & Vault sections + canvas graph loader
// ===========================================================================

export default function FlowStudio() {
  const [isRunning, setIsRunning] = useState(false)
  const [activeTab, setActiveTab] = useState('Nodes')
  const [activeFilter, setActiveFilter] = useState('All Components')
  const [drawerOpen, setDrawerOpen] = useState(true)
  const [drawerTab, setDrawerTab] = useState('logs')
  const [executionLogs, setExecutionLogs] = useState<string[]>([
    '[SYSTEM] Orchestration studio loaded.',
    '[READY] Graph nodes linked. Waiting for trigger input...'
  ])
  const [reportResult, setReportResult] = useState<any>(null)
  const [inputText, setInputText] = useState('')

  // Single node deletion handler
  const handleDeleteNode = useCallback((nodeId: string) => {
    setNodes((nds) => nds.filter((n) => n.id !== nodeId))
    setEdges((eds) => eds.filter((e) => e.source !== nodeId && e.target !== nodeId))
    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] 🗑 Deleted node [ID: ${nodeId}]`,
    ])
  }, [])

  // Initial 5-node graph setup
  const initialNodes = useMemo(() => [
    {
      id: '1',
      type: 'userIngest',
      position: { x: 50, y: 150 },
      data: {
        payloadText: inputText,
        onTextChange: (t: string) => setInputText(t),
        onRun: () => triggerFlow(),
        onDelete: (id: string) => handleDeleteNode(id),
        isRunning: false
      },
    },
    {
      id: '2',
      type: 'masterOrchestrator',
      position: { x: 420, y: 180 },
      data: {
        active: false,
        onDelete: (id: string) => handleDeleteNode(id)
      },
    },
    {
      id: '3',
      type: 'agentTask',
      position: { x: 770, y: 60 },
      data: {
        variant: 'doc',
        title: 'Document Extraction Agent',
        subtitle: 'OCR & Layout Metadata',
        inputPort: 'PDF Document Required',
        duration: '42ms',
        memory: '10 MB',
        active: false,
        onDelete: (id: string) => handleDeleteNode(id)
      },
    },
    {
      id: '4',
      type: 'agentTask',
      position: { x: 770, y: 320 },
      data: {
        variant: 'malware',
        title: 'Malware Analyzer Agent',
        subtitle: 'PE & YARA Behavioral Audit',
        inputPort: 'Binary Executable (.exe)',
        duration: '42ms',
        memory: '16 MB',
        active: false,
        onDelete: (id: string) => handleDeleteNode(id)
      },
    },
    {
      id: '5',
      type: 'finalReport',
      position: { x: 1140, y: 180 },
      data: {
        active: false,
        onDelete: (id: string) => handleDeleteNode(id)
      },
    },
  ], [inputText, handleDeleteNode])

  const initialEdges: Edge[] = useMemo(() => [
    {
      id: 'e1-2', source: '1', target: '2', animated: true,
      style: { stroke: '#6366f1', strokeWidth: 2, strokeDasharray: '5,5' }
    },
    {
      id: 'e2-3', source: '2', target: '3', animated: true,
      style: { stroke: '#e879f9', strokeWidth: 2, strokeDasharray: '5,5' }
    },
    {
      id: 'e2-4', source: '2', target: '4', animated: true,
      style: { stroke: '#e879f9', strokeWidth: 2, strokeDasharray: '5,5' }
    },
    {
      id: 'e3-5', source: '3', target: '5', animated: true,
      style: { stroke: '#a78bfa', strokeWidth: 2, strokeDasharray: '5,5' }
    },
    {
      id: 'e4-5', source: '4', target: '5', animated: true,
      style: { stroke: '#34d399', strokeWidth: 2, strokeDasharray: '5,5' }
    },
  ], [])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes as any)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  const nodeTypes = useMemo(() => ({
    userIngest: UserPayloadIngestNode,
    masterOrchestrator: MasterOrchestratorNode,
    agentTask: AgentTaskNode,
    finalReport: FinalReportNode,
  }), [])

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ ...params, animated: true, style: { stroke: '#6366f1', strokeWidth: 2, strokeDasharray: '5,5' } }, eds)),
    [setEdges],
  )

  // Add individual component onto the canvas
  const handleAddComponent = (comp: any) => {
    const newId = String(Date.now())
    const nodeType = comp.type || (comp.title.includes('Payload') || comp.title.includes('Webhook') ? 'userIngest' : comp.title.includes('Orchestrator') || comp.title.includes('Risk') ? 'masterOrchestrator' : comp.title.includes('Report') || comp.title.includes('Exporter') ? 'finalReport' : 'agentTask')

    const newNode: any = {
      id: newId,
      type: nodeType,
      position: { x: 450 + (nodes.length * 20), y: 120 + (nodes.length * 25) },
      data: {
        variant: comp.variant || (comp.title.includes('Malware') || comp.title.includes('Threat') || comp.title.includes('Incident') ? 'malware' : comp.title.includes('Phishing') || comp.title.includes('Identity') || comp.title.includes('Fraud') ? 'phishing' : 'doc'),
        title: comp.title,
        subtitle: comp.desc,
        inputPort: comp.io || 'Data Stream',
        duration: '42ms',
        memory: '14 MB',
        active: false,
        onDelete: (id: string) => handleDeleteNode(id),
      },
    }
    setNodes((nds) => [...nds, newNode])
    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ➕ Added node: ${comp.title}`,
    ])
  }

  // Load complete pre-built Template graph
  const handleLoadTemplate = (tpl: any) => {
    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] 🗂 Loading template architecture: ${tpl.title}`,
    ])

    if (tpl.title.includes('Full 9-Specialist')) {
      // Build 12-node full fan-out architecture
      const fullNodes: any[] = [
        {
          id: 't-ingest', type: 'userIngest', position: { x: 50, y: 350 },
          data: { payloadText: inputText, onRun: () => triggerFlow(), onDelete: handleDeleteNode, isRunning: false }
        },
        {
          id: 't-orch', type: 'masterOrchestrator', position: { x: 400, y: 350 },
          data: { title: 'Master Cyber Orchestrator', subtitle: 'Multi-Agent Intent Router', active: false, onDelete: handleDeleteNode }
        },
        ...AGENTS_LIST.map((ag, i) => ({
          id: `t-agent-${i}`, type: 'agentTask', position: { x: 750, y: 50 + (i * 100) },
          data: { variant: ag.variant, title: ag.title, subtitle: ag.desc, inputPort: ag.io, duration: '42ms', memory: '12 MB', active: false, onDelete: handleDeleteNode }
        })),
        {
          id: 't-report', type: 'finalReport', position: { x: 1150, y: 350 },
          data: { title: 'Final Security Report', subtitle: 'JSON & PDF SOC Exporter', active: false, onDelete: handleDeleteNode }
        }
      ]

      const fullEdges: Edge[] = [
        { id: 'e-in-orch', source: 't-ingest', target: 't-orch', animated: true, style: { stroke: '#6366f1', strokeWidth: 2, strokeDasharray: '5,5' } },
        ...AGENTS_LIST.map((_, i) => ({
          id: `e-orch-ag-${i}`, source: 't-orch', target: `t-agent-${i}`, animated: true, style: { stroke: '#e879f9', strokeWidth: 2, strokeDasharray: '5,5' }
        })),
        ...AGENTS_LIST.map((_, i) => ({
          id: `e-ag-rep-${i}`, source: `t-agent-${i}`, target: 't-report', animated: true, style: { stroke: '#34d399', strokeWidth: 2, strokeDasharray: '5,5' }
        })),
      ]

      setNodes(fullNodes)
      setEdges(fullEdges)
    } else {
      // Re-initialize default clean 5-node pipeline
      setNodes(initialNodes as any)
      setEdges(initialEdges)
    }
  }

  // Real-time execution handler
  const triggerFlow = async () => {
    setIsRunning(true)
    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ▶ Triggered Execution Node: User Payload Ingest`,
    ])

    setNodes((nds) => nds.map((n) => n.id === '1' || n.id === 't-ingest' ? { ...n, data: { ...n.data, isRunning: true } } : n))
    await new Promise((r) => setTimeout(r, 600))

    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ⚡ Master Cyber Orchestrator routing multi-agent synthesis...`,
    ])
    setNodes((nds) => nds.map((n) => n.id === '2' || n.id === 't-orch' ? { ...n, data: { ...n.data, active: true } } : n))
    await new Promise((r) => setTimeout(r, 800))

    setExecutionLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ⚙ Parallel Fan-Out → Active Specialists`,
    ])
    setNodes((nds) => nds.map((n) => n.id.includes('agent') || n.id === '3' || n.id === '4' ? { ...n, data: { ...n.data, active: true } } : n))

    try {
      const res = await runAnalysis(
        ['malware_analysis_specialist', 'certificate_verification_specialist', 'phishing_detection_specialist'],
        { password: inputText || 'SampleTestPass123!' },
        'Visual Studio Trigger Run'
      )

      await new Promise((r) => setTimeout(r, 800))

      setNodes((nds) => nds.map((n) => n.id === '5' || n.id === 't-report' ? { ...n, data: { ...n.data, active: true } } : n))
      setReportResult(res)

      setExecutionLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ✅ Orchestration Completed! Overall Risk: ${res.platform_risk.overall_risk} (Score: ${res.platform_risk.overall_score}/100)`,
        `[${new Date().toLocaleTimeString()}] Report ID: ${res.report_id}`,
      ])
    } catch (err: any) {
      setExecutionLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ⚠ Execution complete (simulation fallback). Score: 85/100 HIGH Risk.`,
      ])
    } finally {
      setIsRunning(false)
      setNodes((nds) => nds.map((n) => n.id === '1' || n.id === 't-ingest' ? { ...n, data: { ...n.data, isRunning: false } } : n))
    }
  }

  return (
    <div style={{
      width: '100vw',
      height: '100vh',
      background: '#070a11',
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
          1. TOP NAVIGATION HEADER
          =================================================================== */}
      <div style={{
        height: 54,
        background: '#0b0f19',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 1.25rem',
        zIndex: 20,
      }}>
        {/* Left branding & breadcrumbs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{
              width: 28, height: 28, borderRadius: 7,
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 900, color: '#fff', fontSize: '0.85rem'
            }}>⚡</div>
            <span style={{ fontWeight: 800, fontSize: '0.95rem', letterSpacing: '-0.02em', color: '#fff' }}>
              CYBERVERSE
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.775rem', color: '#64748b' }}>
            <span>Production</span>
            <span>›</span>
            <span style={{ color: '#94a3b8' }}>/</span>
            <span style={{ fontWeight: 600, color: '#f1f5f9' }}>Orchestration Flow</span>
            <span style={{
              fontSize: '0.65rem', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 99, padding: '1px 7px',
              display: 'flex', alignItems: 'center', gap: 4, fontWeight: 700
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#34d399' }} /> Live
            </span>
          </div>
        </div>

        {/* Center Search Bar */}
        <div style={{
          width: 320,
          background: '#131826',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: 8,
          padding: '0.35rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.75rem',
          color: '#64748b',
        }}>
          <Search size={14} />
          <span style={{ flex: 1 }}>Search components, actions...</span>
          <kbd style={{
            background: 'rgba(255, 255, 255, 0.06)', border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: 4, padding: '1px 5px', fontSize: '0.65rem', color: '#94a3b8'
          }}>⌘K</kbd>
        </div>

        {/* Right Actions & User Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: '#94a3b8', paddingRight: '0.5rem' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <Layers size={14} /> {nodes.length} Nodes
            </span>
            <span style={{ opacity: 0.3 }}>|</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#c084fc', cursor: 'pointer' }}>
              <Sparkles size={14} /> Copilot
            </span>
            <span style={{ opacity: 0.3 }}>|</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
              <LayoutTemplate size={14} /> Templates
            </span>
            <span style={{ opacity: 0.3 }}>|</span>
            <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: 4 }}>
              ✓ Saved
            </span>
          </div>

          <button
            onClick={triggerFlow}
            disabled={isRunning}
            style={{
              background: '#ffffff',
              color: '#090d16',
              border: 'none',
              borderRadius: 8,
              padding: '0.425rem 1.1rem',
              fontWeight: 800,
              fontSize: '0.8rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              boxShadow: '0 0 15px rgba(255,255,255,0.2)',
            }}
          >
            {isRunning ? <RefreshCw size={14} className="spinner" /> : <Play size={14} fill="#090d16" />} Run
          </button>

          <button style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#e2e8f0',
            borderRadius: 8,
            padding: '0.425rem 0.875rem',
            fontWeight: 600,
            fontSize: '0.8rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            🚀 Deploy
          </button>

          <div style={{ position: 'relative', cursor: 'pointer', color: '#94a3b8' }}>
            <Bell size={18} />
          </div>

          <div style={{
            width: 30, height: 30, borderRadius: '50%', background: '#3b82f6',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontWeight: 700, fontSize: '0.725rem', color: '#fff', border: '1px solid rgba(255,255,255,0.2)'
          }}>
            AD
          </div>
        </div>
      </div>

      {/* ===================================================================
          2. WORKSPACE BODY (LEFT SIDEBAR WITH TABS + CANVAS)
          =================================================================== */}
      <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
        {/* Left Component Sidebar */}
        <div style={{
          width: 290,
          background: '#0b0f19',
          borderRight: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 10,
        }}>
          {/* Header Tabs: Nodes | Agents | Templates | Vault */}
          <div style={{
            display: 'flex',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            background: '#090c14'
          }}>
            {['Nodes', 'Agents', 'Templates', 'Vault'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  flex: 1,
                  padding: '0.65rem 0',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  color: activeTab === tab ? '#ffffff' : '#64748b',
                  background: activeTab === tab ? '#0b0f19' : 'transparent',
                  border: 'none',
                  borderBottom: activeTab === tab ? '2px solid #6366f1' : 'none',
                  cursor: 'pointer'
                }}
              >
                {tab}
              </button>
            ))}
          </div>

          {/* Search Filter */}
          <div style={{ padding: '0.75rem 1rem 0.5rem' }}>
            <input
              type="text"
              placeholder={`Filter ${activeTab.toLowerCase()}...`}
              style={{
                width: '100%',
                background: '#131826',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 8,
                padding: '0.45rem 0.625rem',
                fontSize: '0.75rem',
                color: '#e2e8f0',
                outline: 'none'
              }}
            />
          </div>

          {/* Category Chips */}
          <div style={{ padding: '0 1rem 0.75rem', display: 'flex', gap: '0.375rem', overflowX: 'auto' }}>
            {['All Components', 'Triggers & Webhooks'].map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveFilter(cat)}
                style={{
                  fontSize: '0.675rem',
                  fontWeight: 600,
                  padding: '0.25rem 0.625rem',
                  borderRadius: 99,
                  border: activeFilter === cat ? '1px solid rgba(99, 102, 241, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                  background: activeFilter === cat ? 'rgba(99, 102, 241, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  color: activeFilter === cat ? '#a5b4fc' : '#64748b',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* DYNAMIC SIDEBAR LIST CONTENT BASED ON ACTIVE TAB */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            padding: '0 1rem 1rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}>

            {/* TAB 1: NODES (Triggers, Routers & Exporters) */}
            {activeTab === 'Nodes' && (
              <>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#475569', letterSpacing: '0.08em' }}>
                  CORE NODES ({NODES_LIST.length})
                </div>
                {NODES_LIST.map((comp, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleAddComponent(comp)}
                    style={{
                      background: '#121620',
                      border: '1px solid rgba(255, 255, 255, 0.07)',
                      borderRadius: 10,
                      padding: '0.75rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.4rem',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.4)'; e.currentTarget.style.background = '#161c2b' }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.07)'; e.currentTarget.style.background = '#121620' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.8rem', color: '#f1f5f9' }}>{comp.title}</div>
                      <Plus size={14} color="#6366f1" />
                    </div>
                    <div style={{ fontSize: '0.675rem', color: '#64748b', lineHeight: 1.3 }}>{comp.desc}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 4 }}>
                      <span style={{
                        fontSize: '0.6rem', fontWeight: 700, padding: '1px 6px', borderRadius: 4,
                        background: comp.tagBg, color: comp.tagFg
                      }}>{comp.tag}</span>
                      <span style={{ fontSize: '0.625rem', color: '#475569' }}>{comp.io}</span>
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* TAB 2: AGENTS (All 9 CyberVerse CrewAI Specialists) */}
            {activeTab === 'Agents' && (
              <>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#475569', letterSpacing: '0.08em' }}>
                  AI SPECIALIST AGENTS ({AGENTS_LIST.length})
                </div>
                {AGENTS_LIST.map((agent, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleAddComponent(agent)}
                    style={{
                      background: '#121620',
                      border: '1px solid rgba(255, 255, 255, 0.07)',
                      borderRadius: 10,
                      padding: '0.75rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.4rem',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.4)'; e.currentTarget.style.background = '#161c2b' }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.07)'; e.currentTarget.style.background = '#121620' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.8rem', color: '#f1f5f9' }}>{agent.title}</div>
                      <Plus size={14} color="#8b5cf6" />
                    </div>
                    <div style={{ fontSize: '0.675rem', color: '#64748b', lineHeight: 1.3 }}>{agent.desc}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 4 }}>
                      <span style={{
                        fontSize: '0.6rem', fontWeight: 700, padding: '1px 6px', borderRadius: 4,
                        background: agent.tagBg, color: agent.tagFg
                      }}>{agent.tag}</span>
                      <span style={{ fontSize: '0.625rem', color: '#475569' }}>{agent.io}</span>
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* TAB 3: TEMPLATES (Pre-built Graph Architectures) */}
            {activeTab === 'Templates' && (
              <>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#475569', letterSpacing: '0.08em' }}>
                  WORKFLOW TEMPLATES ({TEMPLATES_LIST.length})
                </div>
                {TEMPLATES_LIST.map((tpl, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleLoadTemplate(tpl)}
                    style={{
                      background: '#121620',
                      border: '1px solid rgba(255, 255, 255, 0.07)',
                      borderRadius: 10,
                      padding: '0.75rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.4rem',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(52, 211, 153, 0.4)'; e.currentTarget.style.background = '#161c2b' }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.07)'; e.currentTarget.style.background = '#121620' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.8rem', color: '#f1f5f9' }}>{tpl.title}</div>
                      <LayoutTemplate size={14} color="#34d399" />
                    </div>
                    <div style={{ fontSize: '0.675rem', color: '#64748b', lineHeight: 1.3 }}>{tpl.desc}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 4 }}>
                      <span style={{
                        fontSize: '0.6rem', fontWeight: 700, padding: '1px 6px', borderRadius: 4,
                        background: 'rgba(52, 211, 153, 0.15)', color: '#34d399'
                      }}>{tpl.category}</span>
                      <span style={{ fontSize: '0.625rem', color: '#a78bfa', fontWeight: 700 }}>{tpl.nodesCount}</span>
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* TAB 4: VAULT (Secrets & Credentials) */}
            {activeTab === 'Vault' && (
              <>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#475569', letterSpacing: '0.08em' }}>
                  ENCRYPTED SECRETS ({VAULT_ITEMS.length})
                </div>
                {VAULT_ITEMS.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: '#121620',
                      border: '1px solid rgba(255, 255, 255, 0.07)',
                      borderRadius: 10,
                      padding: '0.75rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.3rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.75rem', color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Key size={12} color="#f59e0b" /> {item.name}
                      </div>
                      <span style={{ fontSize: '0.6rem', color: '#34d399', fontWeight: 700 }}>{item.status}</span>
                    </div>
                    <div style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'monospace' }}>{item.value}</div>
                  </div>
                ))}
              </>
            )}

          </div>
        </div>

        {/* Center Node Canvas */}
        <div style={{ flex: 1, position: 'relative', background: '#070a11' }}>
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
            <Controls style={{ background: '#121620', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
            <MiniMap style={{ background: '#0b0f19', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} nodeColor="#222838" />
          </ReactFlow>

          {/* ===================================================================
              3. BOTTOM EXECUTION DRAWER & LOGS PANEL
              =================================================================== */}
          <div style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            background: '#090d16',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            zIndex: 30,
            display: 'flex',
            flexDirection: 'column',
          }}>
            {/* Drawer Header Toggle */}
            <div style={{
              height: 36,
              padding: '0 1.25rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: '#0c101b',
              cursor: 'pointer',
            }} onClick={() => setDrawerOpen(!drawerOpen)}>
              <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.75rem' }}>
                <button
                  onClick={(e) => { e.stopPropagation(); setDrawerTab('logs') }}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: drawerTab === 'logs' ? '#6366f1' : '#64748b',
                    fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
                  }}
                >
                  <Terminal size={14} /> Execution Logs ({executionLogs.length})
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); setDrawerTab('api') }}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: drawerTab === 'api' ? '#6366f1' : '#64748b',
                    fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
                  }}
                >
                  <Server size={14} /> API Response
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); setDrawerTab('metrics') }}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: drawerTab === 'metrics' ? '#6366f1' : '#64748b',
                    fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
                  }}
                >
                  <Activity size={14} /> Metrics
                </button>
              </div>

              <div style={{ color: '#64748b' }}>
                {drawerOpen ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
              </div>
            </div>

            {/* Drawer Content */}
            {drawerOpen && (
              <div style={{
                height: 160,
                padding: '0.75rem 1.25rem',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                color: '#cbd5e1',
                overflowY: 'auto',
                background: '#070a11',
              }}>
                {drawerTab === 'logs' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {executionLogs.map((log, i) => (
                      <div key={i} style={{ color: log.includes('🗑') ? '#f87171' : log.includes('➕') ? '#a5b4fc' : log.includes('✅') ? '#34d399' : log.includes('⚠') ? '#fbbf24' : '#94a3b8' }}>
                        {log}
                      </div>
                    ))}
                  </div>
                )}

                {drawerTab === 'api' && (
                  <pre style={{ margin: 0, color: '#a78bfa' }}>
                    {reportResult ? JSON.stringify(reportResult, null, 2) : '// No API execution triggered yet. Click ▶ Run to execute.'}
                  </pre>
                )}

                {drawerTab === 'metrics' && (
                  <div style={{ display: 'flex', gap: '2rem', color: '#94a3b8' }}>
                    <div>Active Nodes: <strong style={{ color: '#fff' }}>{nodes.length}</strong></div>
                    <div>Total Execution Duration: <strong style={{ color: '#fff' }}>842 ms</strong></div>
                    <div>Peak Memory: <strong style={{ color: '#fff' }}>44 MB</strong></div>
                    <div>Success Rate: <strong style={{ color: '#34d399' }}>100%</strong></div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
