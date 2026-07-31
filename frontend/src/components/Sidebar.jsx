import React, { useState, useEffect, useCallback } from 'react';
import {
  NODE_CATEGORIES,
  NODE_LIBRARY
} from '../data/nodeLibrary';
import { WORKFLOW_TEMPLATES } from '../data/templates';
import { AGENT_LIBRARY, MODEL_OPTIONS } from '../data/agentLibrary';
import {
  Search,
  GripVertical,
  ChevronLeft,
  ChevronRight,
  Layers,
  Sliders,
  History,
  Key,
  Variable,
  Store,
  Zap,
  Bot,
  ShieldAlert,
  GitBranch,
  Database,
  Send,
  Code2,
  UserCheck,
  Sparkles,
  Plus,
  ArrowRight,
  Pencil,
  Loader2,
  Trash2,
  Fish,
  Bug,
  BadgeCheck,
  AlertTriangle,
  CreditCard,
  FileSearch,
  Lock
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

const ICON_MAP = {
  Zap,
  Bot,
  ShieldAlert,
  GitBranch,
  Database,
  Send,
  Code2,
  UserCheck,
  Layers,
  Fish,
  Bug,
  BadgeCheck,
  Key,
  AlertTriangle,
  CreditCard,
  FileSearch,
  Lock
};

export default function Sidebar({ onLoadTemplate, isCollapsed, setIsCollapsed }) {
  const [activeTab, setActiveTab] = useState('templates'); // 'agents', 'templates', 'credentials'
  const [activeTab, setActiveTab] = useState('agents'); // 'agents', 'templates', 'credentials'
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Agents playground: per-agent editable overrides, keyed by agent id
  const [agentOverrides, setAgentOverrides] = useState({});
  const [expandedAgentId, setExpandedAgentId] = useState(null);

  // Credential vault (backed by the real /api/credentials vault)
  const [credentials, setCredentials] = useState([]);
  const [credentialsLoading, setCredentialsLoading] = useState(false);
  const [showAddCredential, setShowAddCredential] = useState(false);
  const [newCredName, setNewCredName] = useState('');
  const [newCredType, setNewCredType] = useState('groq_api_key');
  const [newCredFields, setNewCredFields] = useState({});
  const [savingCred, setSavingCred] = useState(false);
  const [credError, setCredError] = useState(null);

  const fetchCredentials = useCallback(async () => {
    setCredentialsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/credentials`);
      const json = await res.json();
      setCredentials(json.credentials || []);
    } catch (err) {
      setCredError('Backend not reachable at ' + API_BASE);
    } finally {
      setCredentialsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'credentials') fetchCredentials();
  }, [activeTab, fetchCredentials]);

  const handleSaveCredential = async () => {
    if (!newCredName.trim()) {
      setCredError('Name is required.');
      return;
    }
    setSavingCred(true);
    setCredError(null);
    try {
      const formData = new FormData();
      formData.append('name', newCredName);
      formData.append('type', newCredType);
      Object.entries(newCredFields).forEach(([k, v]) => formData.append(k, v));
      const res = await fetch(`${API_BASE}/api/credentials`, { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Failed to save credential');
      }
      await fetchCredentials();
      setShowAddCredential(false);
      setNewCredName('');
      setNewCredFields({});
    } catch (err) {
      setCredError(err.message || 'Failed to save credential');
    } finally {
      setSavingCred(false);
    }
  };

  const handleDeleteCredential = async (credentialId) => {
    try {
      await fetch(`${API_BASE}/api/credentials/${credentialId}`, { method: 'DELETE' });
      await fetchCredentials();
    } catch (err) {
      setCredError('Failed to delete credential');
    }
  };

  const getAgentOverride = (agentId, field, fallback) => {
    const override = agentOverrides[agentId];
    return override && override[field] !== undefined ? override[field] : fallback;
  };

  const updateAgentOverride = (agentId, field, value) => {
    setAgentOverrides((prev) => ({
      ...prev,
      [agentId]: { ...prev[agentId], [field]: value },
    }));
  };

  const onDragStart = (event, nodeItem) => {
    event.dataTransfer.setData('application/reactflow/agent', JSON.stringify(nodeItem.defaultData));
    event.dataTransfer.effectAllowed = 'move';
  };

  const onAgentDragStart = (event, agent) => {
    const libraryEntry = NODE_LIBRARY.find((n) => n.defaultData.id === agent.id);
    const baseData = libraryEntry ? libraryEntry.defaultData : { id: agent.id, label: agent.name, icon: agent.icon };
    const payload = {
      ...baseData,
      systemPrompt: getAgentOverride(agent.id, 'systemPrompt', agent.defaultSystemPrompt),
      model: getAgentOverride(agent.id, 'model', agent.defaultModel),
    };
    event.dataTransfer.setData('application/reactflow/agent', JSON.stringify(payload));
    event.dataTransfer.effectAllowed = 'move';
  };

  const filteredNodes = NODE_LIBRARY.filter((node) => {
    const matchesCategory = selectedCategory === 'all' || node.category === selectedCategory;
    const matchesSearch = searchQuery === '' || 
      node.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
      node.subtitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
      node.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <aside 
      className={`h-full bg-[#2B2B2B] border-r border-black/20 flex flex-col shrink-0 transition-all duration-300 relative z-20 select-none text-zinc-300 ${
        isCollapsed ? 'w-16' : 'w-80'
      }`}
    >
      {/* Collapse / Expand Toggle Button - Positioned absolutely so it bridges the border.
          Vertically centered (rather than pinned near the top) so it never overlaps the
          top tab row's icons/labels, regardless of how many tabs are in that row. */}
      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full bg-[#3B3B3B] border border-black/40 text-zinc-400 hover:text-white flex items-center justify-center shadow-md z-30 transition-transform hover:scale-110"
      >
        {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
      </button>

      {/* COLLAPSED STATE */}
      {isCollapsed ? (
        <div className="flex-1 flex flex-col items-center py-4 space-y-4">
          
          <button
            title="Agents"
            onClick={() => { setActiveTab('agents'); setIsCollapsed(false); }}
            className={`p-2.5 rounded-xl border transition-all ${
              activeTab === 'agents' ? 'bg-[#3B3B3B] border-white/10 text-zinc-100 shadow-sm' : 'bg-transparent border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-black/10'
            }`}
          >
            <Bot className="w-5 h-5" />
          </button>

          <button
            title="Templates"
            onClick={() => { setActiveTab('templates'); setIsCollapsed(false); }}
            className={`p-2.5 rounded-xl border transition-all ${
              activeTab === 'templates' ? 'bg-[#3B3B3B] border-white/10 text-zinc-100 shadow-sm' : 'bg-transparent border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-black/10'
            }`}
          >
            <Sliders className="w-5 h-5" />
          </button>

          <button
            title="Credentials"
            onClick={() => { setActiveTab('credentials'); setIsCollapsed(false); }} 
            className={`p-2.5 rounded-xl border transition-all ${
              activeTab === 'credentials' ? 'bg-[#3B3B3B] border-white/10 text-zinc-100 shadow-sm' : 'bg-transparent border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-black/10'
            }`}
          >
            <Key className="w-5 h-5" />
          </button>
        </div>
      ) : (
        /* EXPANDED STATE */
        <>
          {/* TOP NAVIGATION TABS FOR SIDEBAR */}
          <div className="p-2 border-b border-black/20 flex items-center justify-around gap-1 shrink-0 bg-[#252525]">

            <button
              onClick={() => setActiveTab('agents')}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all flex-1 justify-center ${
                activeTab === 'agents'
                  ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm border border-white/5'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-black/10 border border-transparent'
              }`}
            >
              <Bot className="w-4 h-4" />
              <span>Agents</span>
            </button>

            <button
              onClick={() => setActiveTab('templates')}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all flex-1 justify-center ${
                activeTab === 'templates' 
                  ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm border border-white/5' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-black/10 border border-transparent'
              }`}
            >
              <Sliders className="w-4 h-4" />
              <span>Templates</span>
            </button>

            <button
              onClick={() => setActiveTab('credentials')}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all flex-1 justify-center ${
                activeTab === 'credentials' 
                  ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm border border-white/5' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-black/10 border border-transparent'
              }`}
            >
              <Key className="w-4 h-4" />
              <span>Vault</span>
            </button>
          </div>

          {activeTab === 'agents' ? (
            /* AGENTS PLAYGROUND VIEW */
            <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar">
              <div className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 px-1 mb-1">
                Editable Agents ({AGENT_LIBRARY.length})
              </div>
              {AGENT_LIBRARY.map((agent) => {
                const isExpanded = expandedAgentId === agent.id;
                const promptValue = getAgentOverride(agent.id, 'systemPrompt', agent.defaultSystemPrompt);
                const modelValue = getAgentOverride(agent.id, 'model', agent.defaultModel);
                return (
                  <div
                    key={agent.id}
                    draggable
                    onDragStart={(e) => onAgentDragStart(e, agent)}
                    className="p-3 rounded-xl bg-[#333333] border border-white/5 hover:border-white/20 hover:bg-[#3B3B3B] transition-all cursor-grab active:cursor-grabbing group select-none"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-[#252525] border border-black/20 flex items-center justify-center text-sm shadow-inner shrink-0">
                          {(() => {
                            const IconComponent = ICON_MAP[agent.icon];
                            return IconComponent ? <IconComponent className="w-4 h-4 text-zinc-300" /> : agent.icon;
                          })()}
                        </div>
                        <div className="min-w-0">
                          <h4 className="text-xs font-semibold text-zinc-200 leading-tight truncate">{agent.name}</h4>
                          <span className="text-[10px] text-zinc-400 font-medium block truncate max-w-[170px] mt-0.5">{agent.description}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <GripVertical className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
                        <button
                          onClick={(e) => { e.stopPropagation(); setExpandedAgentId(isExpanded ? null : agent.id); }}
                          className="p-1 rounded-md text-zinc-500 hover:text-zinc-200 hover:bg-white/5 transition-colors"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="mt-2 space-y-2 nodrag" onMouseDown={(e) => e.stopPropagation()}>
                        <label className="text-[9px] font-semibold text-zinc-500 uppercase tracking-widest block">System Prompt</label>
                        <textarea
                          rows={5}
                          value={promptValue}
                          onChange={(e) => updateAgentOverride(agent.id, 'systemPrompt', e.target.value)}
                          className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-2 text-[10.5px] text-zinc-200 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 resize-none"
                        />
                        <label className="text-[9px] font-semibold text-zinc-500 uppercase tracking-widest block">Model</label>
                        <select
                          value={modelValue}
                          onChange={(e) => updateAgentOverride(agent.id, 'model', e.target.value)}
                          className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-[10.5px] text-zinc-200 focus:outline-none focus:border-indigo-500/50"
                        >
                          {MODEL_OPTIONS.map((m) => (
                            <option key={m.value} value={m.value}>{m.label}</option>
                          ))}
                        </select>
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-2 mt-2 text-[10px] font-mono text-zinc-500 border-t border-white/5">
                      <span className="px-1.5 py-0.5 rounded bg-black/20 text-zinc-300 font-medium">{modelValue}</span>
                      <span>Drag to canvas</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : activeTab === 'templates' ? (
            /* TEMPLATES VIEW */
            <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar">
              <div className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 px-1 mb-1">
                Pre-built Workflows ({WORKFLOW_TEMPLATES.length})
              </div>
              {WORKFLOW_TEMPLATES.map((tmpl) => (
                <div
                  key={tmpl.id}
                  onClick={() => onLoadTemplate(tmpl.id)}
                  className="p-3.5 rounded-xl bg-[#333333] border border-white/5 hover:border-indigo-500/50 hover:bg-[#3B3B3B] cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-[10px] font-medium border border-indigo-500/20">
                      {tmpl.badge}
                    </span>
                    <span className="text-[10px] text-zinc-400 font-medium">{tmpl.nodeCount} Nodes</span>
                  </div>
                  <h4 className="text-xs font-semibold text-zinc-200 group-hover:text-indigo-300 transition-colors mb-1.5">
                    {tmpl.title}
                  </h4>
                  <p className="text-[10px] text-zinc-400 leading-relaxed mb-3">
                    {tmpl.description}
                  </p>
                  <div className="flex items-center justify-end text-[10px] font-medium text-indigo-400 group-hover:translate-x-1 transition-transform">
                    Load Template <ArrowRight className="w-3 h-3 ml-1" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* VAULT / CREDENTIALS VIEW - backed by the real /api/credentials vault */
            <div className="flex-1 p-3 overflow-y-auto space-y-3 custom-scrollbar text-xs">
              <div className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 px-1 mb-1 flex items-center justify-between">
                <span>Encrypted Secrets</span>
                {credentialsLoading && <Loader2 className="w-3 h-3 animate-spin text-zinc-500" />}
              </div>

              {credentials.length === 0 && !credentialsLoading && (
                <p className="text-[10px] text-zinc-500 px-1">No credentials saved yet. Add one below, or bind one directly from a node's popup.</p>
              )}

              {credentials.map((c) => (
                <div key={c.credential_id} className="p-3 rounded-xl bg-[#333333] border border-white/5 hover:border-white/10 transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-medium text-zinc-200 truncate">{c.name}</span>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-[9px] text-emerald-400 font-mono px-1.5 bg-emerald-500/10 rounded">{c.type}</span>
                      <button onClick={() => handleDeleteCredential(c.credential_id)} className="p-0.5 text-zinc-500 hover:text-rose-400 transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  <span className="text-[10px] text-zinc-400 font-mono">{c.masked_preview}</span>
                </div>
              ))}

              {credError && <div className="text-[10px] text-rose-400 px-1">{credError}</div>}

              {!showAddCredential ? (
                <button
                  onClick={() => setShowAddCredential(true)}
                  className="w-full py-2.5 rounded-lg bg-[#252525] border border-dashed border-white/20 hover:border-white/40 hover:bg-[#3B3B3B] text-zinc-300 font-medium text-[11px] flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Credential</span>
                </button>
              ) : (
                <div className="p-3 rounded-xl bg-[#333333] border border-white/10 space-y-2">
                  <input
                    type="text"
                    placeholder="Credential name"
                    value={newCredName}
                    onChange={(e) => setNewCredName(e.target.value)}
                    className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none"
                  />
                  <select
                    value={newCredType}
                    onChange={(e) => { setNewCredType(e.target.value); setNewCredFields({}); }}
                    className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 focus:border-indigo-500/50 focus:outline-none"
                  >
                    <option value="groq_api_key">Groq API Key</option>
                    <option value="smtp">SMTP / Email</option>
                    <option value="mongodb">MongoDB Connection</option>
                    <option value="generic_api_key">Generic API Key</option>
                  </select>
                  {(newCredType === 'groq_api_key' || newCredType === 'generic_api_key') && (
                    <input
                      type="password"
                      placeholder="API key"
                      value={newCredFields.api_key || ''}
                      onChange={(e) => setNewCredFields((f) => ({ ...f, api_key: e.target.value }))}
                      className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none"
                    />
                  )}
                  {newCredType === 'smtp' && (
                    <>
                      <input type="text" placeholder="SMTP host" value={newCredFields.smtp_host || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_host: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="SMTP port" value={newCredFields.smtp_port || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_port: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="SMTP username / email" value={newCredFields.smtp_user || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_user: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="password" placeholder="SMTP password" value={newCredFields.smtp_pass || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_pass: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="email" placeholder="Default recipient (optional)" value={newCredFields.recipient_default || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, recipient_default: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                    </>
                  )}
                  {newCredType === 'mongodb' && (
                    <>
                      <input type="text" placeholder="mongodb://localhost:27017" value={newCredFields.mongodb_uri || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, mongodb_uri: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="Database name" value={newCredFields.database_name || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, database_name: e.target.value }))} className="w-full bg-[#1E1E1E] border border-black/20 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <p className="text-[9.5px] text-zinc-500 leading-relaxed px-0.5">Applies platform-wide - view saved reports live in MongoDB Compass using this same URI.</p>
                    </>
                  )}
                  <div className="flex gap-2 pt-1">
                    <button onClick={handleSaveCredential} disabled={savingCred} className="flex-1 py-1.5 rounded-md bg-white hover:bg-zinc-200 text-zinc-950 font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50 transition-all">
                      {savingCred ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
                      Save
                    </button>
                    <button onClick={() => { setShowAddCredential(false); setCredError(null); }} className="px-3 py-1.5 rounded-md bg-white/5 hover:bg-white/10 text-zinc-300 font-medium transition-all">
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </aside>
  );
}
