import React, { useState, useEffect } from 'react';
import {
  Folder,
  Play,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  FileText,
  Shield,
  UserCheck,
  Award,
  Database,
  Clock,
  ExternalLink,
  X
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

export default function GoogleDriveVerificationModal({ isOpen, onClose, setNodes }) {
  const [driveUrl, setDriveUrl] = useState('https://drive.google.com/drive/folders/1A2B3C4D5E6F7G8H9I0J_DemoFolder');
  const [loading, setLoading] = useState(false);
  const [workflowResult, setWorkflowResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeStepIndex, setActiveStepIndex] = useState(-1);
  const [errorMessage, setErrorMessage] = useState(null);

  const TIMELINE_STEPS = [
    { label: 'Google Drive Connected', icon: Folder },
    { label: 'Downloading Files', icon: FileText },
    { label: 'Document Discovery', icon: FileText },
    { label: 'Identity Verification Specialist', icon: UserCheck },
    { label: 'Document Verification Specialist', icon: Award },
    { label: 'Fraud Detection Specialist', icon: Shield },
    { label: 'Report Generated', icon: CheckCircle2 },
    { label: 'Saved to MongoDB', icon: Database },
  ];

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/verify/gdrive/history`);
      const data = await res.json();
      setHistory(data.history || []);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  };

  const handleRunVerification = async () => {
    if (!driveUrl.trim()) return;

    setLoading(true);
    setErrorMessage(null);
    setWorkflowResult(null);
    setActiveStepIndex(0);

    // Simulate animated timeline progress
    const stepInterval = setInterval(() => {
      setActiveStepIndex((prev) => {
        if (prev < TIMELINE_STEPS.length - 2) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const res = await fetch(`${API_BASE}/api/verify/gdrive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ drive_url: driveUrl.trim() }),
      });

      clearInterval(stepInterval);

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail?.message || errJson.detail || 'Verification request failed');
      }

      const json = await res.json();
      setWorkflowResult(json);
      setActiveStepIndex(TIMELINE_STEPS.length - 1);
      fetchHistory();

      if (setNodes) {
        setNodes((nds) => nds.map((n) => {
          if (n.data?.id === 'node-gdrive-connector') return { ...n, data: { ...n.data, status: 'completed', lastResult: json } };
          if (n.data?.id === 'agent-discovery') return { ...n, data: { ...n.data, status: 'completed', lastResult: json } };
          if (n.data?.id === 'agent-identity-spec') {
            const idRes = json.agents?.identity;
            const isFake = idRes?.output?.status === 'Fake' || idRes?.output?.tampering_detected || (idRes?.output?.verified === false);
            return { ...n, data: { ...n.data, status: isFake ? 'error' : 'completed', lastResult: idRes } };
          }
          if (n.data?.id === 'agent-doc-spec') {
            const docRes = json.agents?.document;
            const isFake = docRes?.output?.status === 'Fake' || docRes?.output?.tampering_detected || (docRes?.output?.verified === false);
            return { ...n, data: { ...n.data, status: isFake ? 'error' : 'completed', lastResult: docRes } };
          }
          if (n.data?.id === 'agent-fraud-spec') {
            const fraudRes = json.agents?.fraud;
            const decision = json.report?.summary?.decision || fraudRes?.output?.decision || 'Approved';
            const trustScore = json.report?.summary?.trust_score ?? 96;
            const isFake = decision === 'Rejected' || trustScore < 60;
            return { ...n, data: { ...n.data, status: isFake ? 'error' : 'completed', lastResult: fraudRes } };
          }
          if (n.data?.id === 'node-final-report' || n.data?.label?.includes('Report') || n.data?.subtitle?.includes('Report')) {
            const summary = json.report?.summary || {};
            const decision = summary.decision || 'Approved';
            const trustScore = summary.trust_score ?? 96;
            const isFake = decision === 'Rejected' || trustScore < 60;
            return { ...n, data: { ...n.data, status: isFake ? 'error' : 'completed', lastResult: json } };
          }
          return n;
        }));
      }
    } catch (err) {
      clearInterval(stepInterval);
      setErrorMessage(err.message || 'Verification workflow failed to execute.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-4xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">AI Document Trust & Verification Workflow</h2>
              <p className="text-xs text-slate-400">Google Drive Service Account • Parallel Multi-Agent • MongoDB Compass</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content Scrollable */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200 text-sm">
          {/* Input Box */}
          <div className="bg-slate-800/50 border border-slate-700/60 rounded-xl p-4 space-y-3">
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Google Drive Folder Link
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Folder className="absolute left-3 top-3 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  value={driveUrl}
                  onChange={(e) => setDriveUrl(e.target.value)}
                  placeholder="https://drive.google.com/drive/folders/..."
                  className="w-full pl-9 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
              <button
                onClick={handleRunVerification}
                disabled={loading || !driveUrl.trim()}
                className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 text-white font-medium rounded-lg text-xs flex items-center gap-2 shadow-lg shadow-indigo-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
                {loading ? 'Running Agents...' : 'Run Verification'}
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              💡 Folders are accessed securely using Service Account <code className="text-indigo-300">credentials.json</code>.
            </p>
          </div>

          {/* Timeline Animation */}
          {(loading || activeStepIndex >= 0) && (
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Execution Timeline</span>
                <span className="text-indigo-400 font-mono text-[11px]">
                  {loading ? 'STATUS: IN PROGRESS' : 'STATUS: COMPLETED'}
                </span>
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {TIMELINE_STEPS.map((step, i) => {
                  const IconComp = step.icon;
                  const isDone = activeStepIndex > i || (!loading && workflowResult);
                  const isCurrent = loading && activeStepIndex === i;

                  return (
                    <div
                      key={i}
                      className={`p-2.5 rounded-lg border text-xs flex items-center gap-2 transition ${
                        isDone
                          ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                          : isCurrent
                          ? 'bg-indigo-950/50 border-indigo-500/50 text-indigo-300 animate-pulse'
                          : 'bg-slate-900 border-slate-800 text-slate-500'
                      }`}
                    >
                      {isDone ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400 shrink-0" />
                      ) : (
                        <IconComp className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                      )}
                      <span className="truncate text-[11px] font-medium">{step.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl flex items-center gap-3 text-red-300 text-xs">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <div>
                <p className="font-semibold">Workflow Error</p>
                <p className="text-[11px] text-red-400">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Standardized Agent Cards & Results */}
          {workflowResult && (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-4">
                <div>
                  <h3 className="text-sm font-semibold text-emerald-300">
                    Decision: {workflowResult.report?.summary?.decision || 'Approved'}
                  </h3>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Workflow ID: <span className="font-mono text-indigo-300">{workflowResult.workflow_id}</span> • Elapsed: {workflowResult.elapsed_seconds}s
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-bold text-emerald-400">
                    {workflowResult.report?.summary?.trust_score ?? 96}%
                  </span>
                  <p className="text-[10px] text-slate-400 uppercase tracking-wider">Trust Score</p>
                </div>
              </div>

              {/* Grid of Agent Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Agent 1 Card */}
                {workflowResult.agents?.identity && (
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <UserCheck className="w-4 h-4 text-emerald-400" />
                        <h4 className="text-xs font-semibold text-white">Identity Specialist</h4>
                      </div>
                      <span className="px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[10px] rounded-full">
                        {workflowResult.agents.identity.confidence}% Conf.
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Processing Time: {workflowResult.agents.identity.processing_time_ms}ms
                    </p>
                    <div className="bg-slate-900 rounded-lg p-2.5 text-[11px] space-y-1 font-mono text-slate-300">
                      <div><span className="text-slate-500">Name:</span> {workflowResult.agents.identity.output?.name}</div>
                      <div><span className="text-slate-500">Doc:</span> {workflowResult.agents.identity.output?.document}</div>
                      <div><span className="text-slate-500">Face Match:</span> {workflowResult.agents.identity.output?.face_match}</div>
                    </div>
                  </div>
                )}

                {/* Agent 2 Card */}
                {workflowResult.agents?.document && (
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Award className="w-4 h-4 text-indigo-400" />
                        <h4 className="text-xs font-semibold text-white">Document Specialist</h4>
                      </div>
                      <span className="px-2 py-0.5 bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-[10px] rounded-full">
                        {workflowResult.agents.document.confidence}% Conf.
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Processing Time: {workflowResult.agents.document.processing_time_ms}ms
                    </p>
                    <div className="bg-slate-900 rounded-lg p-2.5 text-[11px] space-y-1 font-mono text-slate-300">
                      <div><span className="text-slate-500">Doc:</span> {workflowResult.agents.document.output?.document}</div>
                      <div><span className="text-slate-500">Issuer:</span> {workflowResult.agents.document.output?.issuer}</div>
                      <div><span className="text-slate-500">QR/Sig:</span> {workflowResult.agents.document.output?.qr_and_signature}</div>
                    </div>
                  </div>
                )}

                {/* Agent 3 Card */}
                {workflowResult.agents?.fraud && (
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-purple-400" />
                        <h4 className="text-xs font-semibold text-white">Fraud Specialist</h4>
                      </div>
                      <span className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[10px] rounded-full">
                        Risk: {workflowResult.agents.fraud.output?.risk}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Processing Time: {workflowResult.agents.fraud.processing_time_ms}ms
                    </p>
                    <div className="bg-slate-900 rounded-lg p-2.5 text-[11px] space-y-1 font-mono text-slate-300">
                      <div><span className="text-slate-500">Trust:</span> {workflowResult.agents.fraud.output?.trust_score}%</div>
                      <div><span className="text-slate-500">Fraud Score:</span> {workflowResult.agents.fraud.output?.fraud_score}%</div>
                      <div><span className="text-slate-500">Anomalies:</span> {workflowResult.agents.fraud.output?.anomalies?.length || 0}</div>
                    </div>
                  </div>
                )}
              </div>

              {/* Markdown Report Preview */}
              {workflowResult.report?.markdown_report && (
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Generated Verification Markdown Summary
                  </h4>
                  <pre className="p-3 bg-slate-900 rounded-lg text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {workflowResult.report.markdown_report}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* History Section */}
          {history.length > 0 && (
            <div className="space-y-3 pt-4 border-t border-slate-800">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Database className="w-4 h-4 text-indigo-400" />
                <span>MongoDB Compass Verification History ({history.length})</span>
              </h3>
              <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden max-h-40 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-2.5">Workflow ID</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5">Decision</th>
                      <th className="p-2.5">Docs</th>
                      <th className="p-2.5">Created At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {history.map((h, i) => (
                      <tr key={i} className="hover:bg-slate-900/50">
                        <td className="p-2.5 font-mono text-indigo-300">{h.workflow_id}</td>
                        <td className="p-2.5">
                          <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded text-[10px]">
                            {h.status || 'COMPLETED'}
                          </span>
                        </td>
                        <td className="p-2.5 font-semibold text-white">{h.report?.summary?.decision || 'Approved'}</td>
                        <td className="p-2.5">{h.uploaded_documents?.length || 3}</td>
                        <td className="p-2.5 text-slate-400 text-[11px]">{h.created_at || 'Recently'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
