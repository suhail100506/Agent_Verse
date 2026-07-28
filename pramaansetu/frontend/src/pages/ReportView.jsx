import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ShieldCheck, AlertTriangle, Cpu, User, Building, Calendar, Award, Hash, ArrowLeft, Loader2 } from 'lucide-react';
import ClassificationBadge from '../components/ClassificationBadge';
import ScoreBreakdownCard from '../components/ScoreBreakdownCard';
import ReportPDFDownload from '../components/ReportPDFDownload';
import api from '../api/client';

export default function ReportView() {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchResult = async () => {
      try {
        const response = await api.get(`/verification/${id}/result`);
        setReport(response.data);
      } catch (err) {
        setError('Unable to load verification report.');
      } finally {
        setLoading(false);
      }
    };
    fetchResult();
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <Loader2 className="w-10 h-10 text-brand-600 animate-spin" />
        <p className="text-sm font-mono text-slate-600 font-medium">Loading Forensic Audit Record...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-md mx-auto p-6 rounded-2xl bg-rose-50 border border-rose-200 text-center space-y-4 shadow-sm">
        <h3 className="text-lg font-bold text-rose-900">Record Error</h3>
        <p className="text-xs text-rose-700 font-medium">{error || 'Verification report unavailable.'}</p>
        <Link to="/upload" className="inline-block px-4 py-2 rounded-xl bg-white border border-slate-300 text-xs font-mono font-bold text-slate-800">
          Back to Upload
        </Link>
      </div>
    );
  }

  const { extracted_data = {}, authenticity_score = {}, classification, ai_reasoning, recommendation, duplicate_alert } = report;

  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-12">
      {/* Top Header Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link to="/history" className="inline-flex items-center gap-2 text-xs font-mono font-bold text-slate-600 hover:text-brand-600 transition-colors">
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Audit History</span>
        </Link>
        <ReportPDFDownload verificationId={id} />
      </div>

      {/* Fraud Alert Banner */}
      {duplicate_alert?.flagged && (
        <div className="p-4.5 rounded-2xl bg-amber-50 border-2 border-amber-300 flex items-start gap-3 shadow-xs">
          <AlertTriangle className="w-6 h-6 text-amber-600 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-bold text-amber-900 text-sm">Fraud Pattern Alert — Repeated Certificate Number</h4>
            <p className="text-xs text-amber-800 mt-1 font-medium">{duplicate_alert.message}</p>
          </div>
        </div>
      )}

      {/* Main Verdict Summary Hero */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-slate-100 pb-6">
          <div>
            <span className="text-xs font-mono font-semibold text-slate-500">Audit Record ID: {id}</span>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 mt-1">
              Certificate Authenticity Report
            </h1>
            <p className="text-xs text-slate-500 mt-1 font-mono">
              Pipeline Version {report.pipeline_version} • Completed: {report.completed_at ? new Date(report.completed_at).toLocaleString() : 'N/A'}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <div className="text-left sm:text-right">
              <span className="block text-xs font-mono font-semibold text-slate-500 uppercase">Authenticity Score</span>
              <span className="text-3xl font-extrabold font-mono text-emerald-600">
                {authenticity_score.overall_score?.toFixed(1) || 0} / 100
              </span>
            </div>
            <ClassificationBadge classification={classification} />
          </div>
        </div>

        {/* Extracted Candidate Information Grid */}
        <div>
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-500 mb-4">
            1. Extracted Certificate Credentials
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <User className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Candidate Name</span>
                <span className="text-sm font-bold text-slate-900 truncate block">{extracted_data.name || 'Not Found'}</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <Hash className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Certificate Number</span>
                <span className="text-sm font-bold font-mono text-amber-700 truncate block">{extracted_data.certificate_number || 'Not Found'}</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <Building className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Issuing Institution</span>
                <span className="text-sm font-bold text-slate-900 truncate block">{extracted_data.institution || 'Not Found'}</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <Award className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Course / Degree</span>
                <span className="text-sm font-bold text-slate-900 truncate block">{extracted_data.course || 'Not Found'}</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <Calendar className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Date of Issue</span>
                <span className="text-sm font-bold text-slate-900 truncate block">{extracted_data.date || 'Not Found'}</span>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-brand-600 flex-shrink-0" />
              <div className="overflow-hidden">
                <span className="block text-[10px] font-mono font-bold text-slate-400 uppercase">Grade / CGPA</span>
                <span className="text-sm font-bold text-slate-900 truncate block">{extracted_data.grade || 'Not Found'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Score Breakdown Card */}
      <ScoreBreakdownCard authenticityScore={authenticity_score} />

      {/* AI Forensic Reasoning Box (Gemini 2.5 Flash) */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
          <Cpu className="w-5 h-5 text-brand-600" />
          <h3 className="text-lg font-bold text-slate-900 font-mono">
            2. Gemini 2.5 Flash Forensic Reasoning Analysis
          </h3>
        </div>
        <p className="text-sm text-slate-700 leading-relaxed font-sans bg-slate-50 p-5 rounded-2xl border border-slate-200">
          {ai_reasoning || "Forensic reasoning analysis generated based on evidence extraction."}
        </p>
      </div>

      {/* Recommendation Box */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-3">
        <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-500">
          3. Actionable Verification Recommendation
        </h3>
        <p className="text-sm text-emerald-800 font-bold bg-emerald-50 p-5 rounded-2xl border border-emerald-200">
          {recommendation || "Proceed with standard verification processing."}
        </p>
      </div>
    </div>
  );
}
