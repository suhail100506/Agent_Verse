import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  Copy,
  Trash2,
  KeyRound,
  Plus,
  ShieldCheck,
  Loader2,
  ChevronDown,
  Fish,
  Bug,
  BadgeCheck,
  Key,
  AlertTriangle,
  CreditCard,
  FileSearch,
  Lock,
} from 'lucide-react';

const ICON_MAP = {
  Fish, Bug, BadgeCheck, Key, AlertTriangle, CreditCard, FileSearch, Lock
};
import { getNodeKind, AGENT_EXTRA_FIELDS } from '../data/nodeSettingsSchema';
import { MODEL_OPTIONS } from '../data/agentLibrary';

const API_BASE = 'http://localhost:8000';

const CREDENTIAL_TYPES = [
  { value: 'groq_api_key', label: 'Groq API Key' },
  { value: 'smtp', label: 'SMTP / Email' },
  { value: 'mongodb', label: 'MongoDB Connection' },
  { value: 'generic_api_key', label: 'Generic API Key' },
];

const POPUP_WIDTH = 340;
const POPUP_MAX_HEIGHT = 460;

export default function NodePopup({ node, anchor, onUpdateNode, onDeleteNode, onClose }) {
  const [activeTab, setActiveTab] = useState('config');
  const [copied, setCopied] = useState(false);

  const [credentials, setCredentials] = useState([]);
  const [credentialsLoading, setCredentialsLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newCredType, setNewCredType] = useState('groq_api_key');
  const [newCredName, setNewCredName] = useState('');
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
    if (node) fetchCredentials();
    // Reset transient UI state whenever the selected node changes
    setActiveTab('config');
    setShowAddForm(false);
    setCredError(null);
  }, [node?.id, fetchCredentials]);

  if (!node) return null;

  const { id, data } = node;
  const kind = getNodeKind(data);
  const extraFields = kind === 'agent' ? (AGENT_EXTRA_FIELDS[data.id] || []) : [];
  const tabs = kind === 'agent' ? ['config', 'credentials', 'json', 'logs'] : ['config', 'json', 'logs'];

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const boundCredential = credentials.find(c => c.credential_id === data.credential_id);

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
      const created = await res.json();
      await fetchCredentials();
      onUpdateNode(id, { credential_id: created.credential_id });
      setShowAddForm(false);
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
      if (data.credential_id === credentialId) {
        onUpdateNode(id, { credential_id: null });
      }
      await fetchCredentials();
    } catch (err) {
      setCredError('Failed to delete credential');
    }
  };

  // Clamp the popup within the viewport so it never renders off-screen.
  const left = anchor ? Math.min(Math.max(anchor.x + 16, 12), window.innerWidth - POPUP_WIDTH - 12) : 200;
  const top = anchor ? Math.min(Math.max(anchor.y - 40, 12), window.innerHeight - POPUP_MAX_HEIGHT - 12) : 200;

  return (
    <div
      className="fixed z-40 animate-fadeIn select-none"
      style={{ left, top, width: POPUP_WIDTH }}
      onClick={(e) => e.stopPropagation()}
    >
      <div
        className="rounded-2xl bg-[#1a1f28]/95 backdrop-blur-xl border border-white/10 shadow-2xl flex flex-col text-zinc-300 overflow-hidden"
        style={{ maxHeight: POPUP_MAX_HEIGHT }}
      >
        {/* HEADER */}
        <div className="p-3 border-b border-white/10 flex items-center justify-between bg-black/20 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-[#252b36] border border-white/5 flex items-center justify-center text-sm shadow-inner shrink-0">
              {(() => {
                const IconComponent = ICON_MAP[data.icon];
                return IconComponent ? <IconComponent className="w-3.5 h-3.5 text-zinc-300" /> : (data.icon || '🤖');
              })()}
            </div>
            <div className="flex flex-col min-w-0">
              <h3 className="text-xs font-semibold text-zinc-100 truncate leading-tight">
                {data.label || 'Node Properties'}
              </h3>
              <span className="text-[10px] text-zinc-500 font-mono truncate">ID: {id}</span>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-md text-zinc-400 hover:text-zinc-100 hover:bg-white/10 transition-colors shrink-0">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* BOUND CREDENTIAL PREVIEW */}
        {boundCredential && (
          <div className="px-3 py-1.5 bg-emerald-500/10 border-b border-emerald-500/20 flex items-center gap-1.5 text-[10px] text-emerald-400 shrink-0">
            <ShieldCheck className="w-3 h-3 shrink-0" />
            <span className="truncate">Using "{boundCredential.name}" ({boundCredential.masked_preview})</span>
          </div>
        )}

        {/* TABS */}
        <div className="px-2 py-1.5 border-b border-white/10 flex items-center gap-1 text-[10.5px] shrink-0">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-1.5 rounded-md font-medium transition-all capitalize ${
                activeTab === tab
                  ? 'bg-white/10 text-zinc-100 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5'
              }`}
            >
              {tab === 'json' ? 'Payload' : tab}
            </button>
          ))}
        </div>

        {/* CONTENT */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar text-[11px]">
          {activeTab === 'config' && (
            <div className="space-y-3">
              <div>
                <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">Node Name</label>
                <input
                  type="text"
                  value={data.label || ''}
                  onChange={(e) => onUpdateNode(id, { label: e.target.value })}
                  className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all"
                />
              </div>

              <div>
                <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">Subtitle / Role</label>
                <input
                  type="text"
                  value={data.subtitle || ''}
                  onChange={(e) => onUpdateNode(id, { subtitle: e.target.value })}
                  className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all"
                />
              </div>

              {/* AGENT-KIND NODES: LLM reasoning settings + any agent-specific fields */}
              {kind === 'agent' && (
                <>
                  <div>
                    <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">System Prompt Override</label>
                    <textarea
                      rows={3}
                      placeholder="Leave blank to use this agent's default prompt..."
                      value={data.systemPrompt || ''}
                      onChange={(e) => onUpdateNode(id, { systemPrompt: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all resize-none"
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">Model</label>
                    <select
                      value={data.model || MODEL_OPTIONS[0].value}
                      onChange={(e) => onUpdateNode(id, { model: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-indigo-500/50"
                    >
                      {MODEL_OPTIONS.map((m) => (
                        <option key={m.value} value={m.value}>{m.label}</option>
                      ))}
                    </select>
                  </div>

                  {extraFields.map((field) => (
                    <div key={field.key}>
                      <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">{field.label}</label>
                      {field.type === 'select' ? (
                        <select
                          value={data[field.key] ?? field.default ?? ''}
                          onChange={(e) => onUpdateNode(id, { [field.key]: e.target.value })}
                          className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-indigo-500/50"
                        >
                          {field.options.map((opt) => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type={field.type}
                          placeholder={field.placeholder}
                          value={data[field.key] ?? ''}
                          onChange={(e) => onUpdateNode(id, { [field.key]: e.target.value })}
                          className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500/50"
                        />
                      )}
                    </div>
                  ))}

                  <div>
                    <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">Notify Email</label>
                    <input
                      type="email"
                      placeholder="analyst@company.com"
                      value={data.notifyEmail || ''}
                      onChange={(e) => onUpdateNode(id, { notifyEmail: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all"
                    />
                  </div>
                </>
              )}

              {/* REPORT NODE: just wants somewhere to send the aggregated result */}
              {kind === 'report' && (
                <div>
                  <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1">Notify Email</label>
                  <input
                    type="email"
                    placeholder="analyst@company.com"
                    value={data.notifyEmail || ''}
                    onChange={(e) => onUpdateNode(id, { notifyEmail: e.target.value })}
                    className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all"
                  />
                </div>
              )}

              {/* LOGIC NODE: only the branch condition */}
              {kind === 'logic' && (
                <div className="p-2.5 rounded-xl bg-black/20 border border-white/10 space-y-2">
                  <span className="text-[10px] font-bold text-amber-500/80 uppercase tracking-widest block">Branch Expression</span>
                  <input
                    type="text"
                    value={data.conditionField || 'overall_score'}
                    onChange={(e) => onUpdateNode(id, { conditionField: e.target.value })}
                    className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 focus:border-indigo-500/50 focus:outline-none"
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={data.conditionOperator || '>'}
                      onChange={(e) => onUpdateNode(id, { conditionOperator: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 focus:border-indigo-500/50 focus:outline-none"
                    >
                      <option value=">">{'>'}</option>
                      <option value="<">{'<'}</option>
                      <option value="==">{'=='}</option>
                      <option value="!=">{'!='}</option>
                    </select>
                    <input
                      type="text"
                      value={data.conditionValue || '75'}
                      onChange={(e) => onUpdateNode(id, { conditionValue: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 focus:border-indigo-500/50 focus:outline-none"
                    />
                  </div>
                </div>
              )}

              {/* WEBHOOK TRIGGER: only the URL to hit */}
              {kind === 'trigger-webhook' && (
                <div className="p-2.5 rounded-xl bg-black/20 border border-white/10 space-y-1.5">
                  <span className="text-[10px] font-semibold text-zinc-400 block">Webhook URL (connect this node to an agent first)</span>
                  <code className="block text-[9.5px] text-indigo-300 font-mono break-all bg-black/30 rounded p-1.5">
                    {API_BASE}/api/triggers/webhook/{id}
                  </code>
                </div>
              )}

              {/* SCHEDULE TRIGGER: only cron + armed toggle */}
              {kind === 'trigger-schedule' && (
                <div className="p-2.5 rounded-xl bg-black/20 border border-white/10 space-y-2">
                  <div>
                    <label className="text-[10px] font-semibold text-zinc-400 mb-1 block">Cron Expression</label>
                    <input
                      type="text"
                      value={data.cron || '*/15 * * * *'}
                      onChange={(e) => onUpdateNode(id, { cron: e.target.value })}
                      className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 font-mono focus:border-indigo-500/50 focus:outline-none"
                    />
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[10px] font-semibold text-zinc-400">Armed</span>
                    <button
                      onClick={() => onUpdateNode(id, { armed: !data.armed })}
                      className={`w-9 h-5 rounded-full transition-colors relative ${data.armed ? 'bg-emerald-500' : 'bg-zinc-700'}`}
                    >
                      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${data.armed ? 'translate-x-4' : 'translate-x-0.5'}`} />
                    </button>
                  </div>
                  <p className="text-[9.5px] text-zinc-500 leading-relaxed">Arming only marks this node as active - real background scheduling isn't implemented yet; trigger it manually via the Run button or the webhook endpoint.</p>
                </div>
              )}

              {/* TRIGGER-TEXT node's own input/file fields live inline on the node itself - nothing extra to configure here. */}

              <button
                onClick={() => onDeleteNode(id)}
                className="w-full py-2 mt-1 rounded-lg bg-rose-500/10 border border-rose-500/20 hover:bg-rose-500/20 text-rose-400 font-medium flex items-center justify-center gap-1.5 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Remove Node</span>
              </button>
            </div>
          )}

          {activeTab === 'credentials' && (
            <div className="space-y-3">
              <div>
                <label className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-1.5">Bound Credential</label>
                {credentialsLoading ? (
                  <div className="flex items-center gap-2 text-zinc-500 py-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading vault...
                  </div>
                ) : (
                  <select
                    value={data.credential_id || ''}
                    onChange={(e) => onUpdateNode(id, { credential_id: e.target.value || null })}
                    className="w-full bg-black/30 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-indigo-500/50"
                  >
                    <option value="">None (use server default)</option>
                    {credentials.map((c) => (
                      <option key={c.credential_id} value={c.credential_id}>
                        {c.name} ({c.type}) - {c.masked_preview}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {credentials.length > 0 && (
                <div className="space-y-1">
                  {credentials.map((c) => (
                    <div key={c.credential_id} className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-black/20 border border-white/5">
                      <div className="min-w-0">
                        <div className="text-zinc-200 truncate">{c.name}</div>
                        <div className="text-[9px] text-zinc-500 font-mono">{c.type} · {c.masked_preview}</div>
                      </div>
                      <button onClick={() => handleDeleteCredential(c.credential_id)} className="p-1 text-zinc-500 hover:text-rose-400 transition-colors shrink-0">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {!showAddForm ? (
                <button
                  onClick={() => setShowAddForm(true)}
                  className="w-full py-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 text-zinc-300 font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" /> Add Credential
                </button>
              ) : (
                <div className="p-2.5 rounded-xl bg-black/20 border border-white/10 space-y-2">
                  <input
                    type="text"
                    placeholder="Credential name (e.g. My Groq Key)"
                    value={newCredName}
                    onChange={(e) => setNewCredName(e.target.value)}
                    className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none"
                  />
                  <select
                    value={newCredType}
                    onChange={(e) => { setNewCredType(e.target.value); setNewCredFields({}); }}
                    className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 focus:border-indigo-500/50 focus:outline-none"
                  >
                    {CREDENTIAL_TYPES.map((t) => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>

                  {(newCredType === 'groq_api_key' || newCredType === 'generic_api_key') && (
                    <input
                      type="password"
                      placeholder="API key"
                      value={newCredFields.api_key || ''}
                      onChange={(e) => setNewCredFields((f) => ({ ...f, api_key: e.target.value }))}
                      className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none"
                    />
                  )}

                  {newCredType === 'smtp' && (
                    <>
                      <input type="text" placeholder="SMTP host (e.g. smtp.gmail.com)" value={newCredFields.smtp_host || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_host: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="SMTP port (e.g. 587)" value={newCredFields.smtp_port || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_port: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="SMTP username / email" value={newCredFields.smtp_user || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_user: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="password" placeholder="SMTP password / app password" value={newCredFields.smtp_pass || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, smtp_pass: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="email" placeholder="Default recipient (optional)" value={newCredFields.recipient_default || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, recipient_default: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                    </>
                  )}

                  {newCredType === 'mongodb' && (
                    <>
                      <input type="text" placeholder="mongodb://localhost:27017" value={newCredFields.mongodb_uri || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, mongodb_uri: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <input type="text" placeholder="Database name (e.g. certificate_verifier)" value={newCredFields.database_name || ''} onChange={(e) => setNewCredFields((f) => ({ ...f, database_name: e.target.value }))} className="w-full bg-black/30 border border-white/10 rounded-md p-1.5 text-zinc-200 placeholder-zinc-600 focus:border-indigo-500/50 focus:outline-none" />
                      <p className="text-[9.5px] text-zinc-500 leading-relaxed">Applies platform-wide (all agents' reports will save here) - view it live in MongoDB Compass with this same URI.</p>
                    </>
                  )}

                  {credError && <div className="text-rose-400 text-[10px]">{credError}</div>}

                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={handleSaveCredential}
                      disabled={savingCred}
                      className="flex-1 py-1.5 rounded-md bg-white hover:bg-zinc-200 text-zinc-950 font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50 transition-all"
                    >
                      {savingCred ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                      Save
                    </button>
                    <button
                      onClick={() => { setShowAddForm(false); setCredError(null); }}
                      className="px-3 py-1.5 rounded-md bg-white/5 hover:bg-white/10 text-zinc-300 font-medium transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {credError && !showAddForm && <div className="text-rose-400 text-[10px]">{credError}</div>}
            </div>
          )}

          {activeTab === 'json' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">Raw Payload</span>
                <button onClick={handleCopyJson} className="flex items-center gap-1 text-[10px] font-medium text-indigo-400 hover:text-indigo-300 transition-colors">
                  <Copy className="w-3 h-3" />
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-2.5 rounded-xl bg-black/30 border border-white/10 text-[10px] font-mono text-indigo-200 overflow-x-auto custom-scrollbar leading-relaxed">
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="space-y-2 font-mono text-[10px]">
              <div className="text-zinc-500 font-semibold uppercase tracking-widest mb-1">Execution Status</div>
              <div className="p-2.5 rounded-xl bg-black/20 border border-white/10 space-y-1.5">
                <div className="flex justify-between text-zinc-400">
                  <span>Status</span>
                  <span className="text-zinc-200">{data.status || 'idle'}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
