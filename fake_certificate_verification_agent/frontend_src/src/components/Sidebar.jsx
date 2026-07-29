import React from 'react';
import { Network, GripVertical } from 'lucide-react';

export const agentTypes = [
  {id: "agent-doc-ext", icon: "🤖", label: "Document Extraction Agent", subtitle: "OCR & Metadata Parsing", inputLabel: "PDF Document Required"},
  {id: "agent-auth-ver", icon: "🛡️", label: "Authenticity Verification Agent", subtitle: "PKI Root & Registry Check", inputLabel: "Cert ID & Candidate Required"},
  {id: "agent-vis-forensics", icon: "👁️", label: "Visual Forensics Agent", subtitle: "ELA & Font Splicing Forensic", inputLabel: "Diploma Image / Seal Required"},
  {id: "agent-decision", icon: "🧠", label: "Master Decision Agent", subtitle: "Synthesizer & Risk Assessment", inputLabel: "Multi-Agent Synthesis"},
  {id: "agent-malware", icon: "🦠", label: "Malware Analyzer Agent", subtitle: "PE & YARA Behavioral Audit", inputLabel: "Binary Executable (.exe) Required"},
  {id: "agent-threat", icon: "🌐", label: "Cyber Threat Detection Agent", subtitle: "IP Reputation & Abuse Lookup", inputLabel: "Target IP Address Required"},
  {id: "agent-phishing", icon: "🎣", label: "Phishing Detection Agent", subtitle: "SSL & Typosquatting Check", inputLabel: "Target URL Domain Required"},
  {id: "agent-privacy", icon: "🔒", label: "Privacy Compliance Agent", subtitle: "GDPR / DPDP PII Audit", inputLabel: "Text Document / Record Required"},
  {id: "agent-password", icon: "🔑", label: "Password Security Advisor", subtitle: "Entropy & Breach Database", inputLabel: "Password String Required"},
  {id: "agent-fraud", icon: "💳", label: "Fraud Detection Agent", subtitle: "Transaction Anomaly & Geo Risk", inputLabel: "Amount ($) & Location Required"},
  {id: "agent-incident", icon: "🚨", label: "Incident Response Agent", subtitle: "SOC Playbooks & Containment", inputLabel: "Incident Title Required"},
  {id: "agent-deepfake", icon: "🎭", label: "Deepfake Detection Agent", subtitle: "Media Splicing & Face Swap", inputLabel: "Video / Audio File Required"},
  {id: "node-mongodb", icon: "🍃", label: "MongoDB Audit Logs", subtitle: "Persistent Database Store", inputLabel: "Database Persistence"},
  {id: "node-user-upload", icon: "📄", label: "User Payload Ingest", subtitle: "Payload Trigger Input", inputLabel: "User Query Required"},
  {id: "node-final-report", icon: "📋", label: "Final Security Report", subtitle: "JSON & PDF SOC Exporter", inputLabel: "Report Generator"},
  {id: "node-text-box", icon: "📝", label: "Test Text Box", subtitle: "Custom input payload", inputLabel: "Testing Node", isTextBox: true}
];

export default function Sidebar() {
  const onDragStart = (event, agent) => {
    event.dataTransfer.setData('application/reactflow/agent', JSON.stringify(agent));
    event.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div className="bg-[#0c101a] border-b border-slate-800 p-3 z-20 shrink-0">
      <div className="flex items-center justify-between mb-2 px-2">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-sky-400" />
          <span className="font-extrabold text-xs text-white uppercase tracking-wider">All 14 Specialized AI Agent Boxes</span>
          <span className="text-[10px] text-slate-400">(Drag & Drop any agent box to canvas below)</span>
        </div>
      </div>
      <div className="flex items-center gap-3 overflow-x-auto pb-1 px-1 custom-scrollbar">
        {agentTypes.map((agent) => (
          <div 
            key={agent.id}
            draggable
            onDragStart={(event) => onDragStart(event, agent)}
            className="p-3 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-sky-500/60 hover:bg-slate-800/90 cursor-grab active:cursor-grabbing transition-all shadow-lg shrink-0 min-w-[210px] group select-none"
          >
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 font-extrabold text-xs text-slate-200 group-hover:text-sky-300">
                <span className="text-base">{agent.icon}</span>
                <span className="truncate max-w-[140px]">{agent.label}</span>
              </div>
              <GripVertical className="w-3.5 h-3.5 text-slate-500 group-hover:text-sky-400 shrink-0" />
            </div>
            <div className="text-[10px] text-slate-400 font-medium truncate mb-1.5">{agent.subtitle}</div>
            <div className="px-2 py-0.5 rounded-full bg-slate-950 border border-slate-800 text-[9px] font-bold text-sky-400 inline-block truncate max-w-[180px]">{agent.inputLabel}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
