import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Loader2, CheckCircle2, ShieldAlert, ArrowRight } from 'lucide-react';
import PipelineStageTracker from '../components/PipelineStageTracker';
import api from '../api/client';

export default function VerificationStatus() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [statusData, setStatusData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let interval = null;

    const fetchStatus = async () => {
      try {
        const response = await api.get(`/verification/${id}/status`);
        setStatusData(response.data);
        setLoading(false);

        if (response.data.status === 'completed' || response.data.status === 'failed') {
          clearInterval(interval);
          setTimeout(() => {
            navigate(`/verification/${id}/result`);
          }, 1500);
        }
      } catch (err) {
        setError("Failed to connect to verification engine.");
        setLoading(false);
        clearInterval(interval);
      }
    };

    fetchStatus();
    interval = setInterval(fetchStatus, 2000);

    return () => clearInterval(interval);
  }, [id, navigate]);

  if (loading && !statusData) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <Loader2 className="w-10 h-10 text-brand-600 animate-spin" />
        <p className="text-sm font-mono text-slate-600 font-medium">Connecting to Verification Orchestrator...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-md mx-auto p-6 rounded-2xl bg-rose-50 border border-rose-200 text-center space-y-4 shadow-sm">
        <ShieldAlert className="w-10 h-10 text-rose-600 mx-auto" />
        <h3 className="text-lg font-bold text-rose-900">Execution Error</h3>
        <p className="text-xs text-rose-700 font-medium">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 rounded-xl bg-white border border-slate-300 text-slate-800 text-xs font-mono font-bold shadow-2xs"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const isCompleted = statusData?.status === 'completed';

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <div>
          <span className="text-xs font-mono font-semibold text-slate-500 uppercase tracking-widest">
            Pipeline Execution ID: {id}
          </span>
          <h2 className="text-xl font-extrabold text-slate-900 mt-1 flex items-center gap-2">
            <span>Certificate Forensic Verification Engine</span>
            {isCompleted ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-600" />
            ) : (
              <Loader2 className="w-5 h-5 text-brand-600 animate-spin" />
            )}
          </h2>
        </div>

        {isCompleted && (
          <button
            onClick={() => navigate(`/verification/${id}/result`)}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-sm transition-all shadow-sm active:scale-95"
          >
            <span>View Full Report</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>

      <PipelineStageTracker
        currentStage={statusData?.current_stage}
        progressPct={statusData?.stage_progress_pct}
        stageResults={statusData?.stage_results}
        isCompleted={isCompleted}
      />
    </div>
  );
}
