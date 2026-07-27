import React from 'react';
import { CheckCircle2, XCircle, Loader2, Circle } from 'lucide-react';

const STAGES = [
  "File Validation",
  "Image Preprocessing",
  "OCR Text Extraction",
  "Information Parsing",
  "QR Code Verification",
  "Certificate Number Verification",
  "Template Matching",
  "Logo Verification",
  "Seal Verification",
  "Signature Verification",
  "Metadata Analysis",
  "Tampering Detection",
  "Issuing Authority Verification",
  "AI Reasoning Analysis",
  "Authenticity Score",
  "Classification Assignment",
  "Recommendation Generation",
  "Generating PDF Report"
];

export default function PipelineStageTracker({ currentStage, progressPct, stageResults = {}, isCompleted }) {
  const currentStageIndex = STAGES.findIndex(
    (s) => s.toLowerCase() === (currentStage || "").toLowerCase()
  );

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
            <span>18-Stage Forensic Pipeline Execution</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">Real-time status monitoring & fault-isolated inspection</p>
        </div>
        <div className="text-right font-mono">
          <span className="text-2xl font-bold text-brand-600">{progressPct || 0}%</span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-slate-100 rounded-full h-3 mb-6 overflow-hidden border border-slate-200">
        <div
          className="bg-gradient-to-r from-brand-600 via-blue-500 to-emerald-500 h-3 transition-all duration-500 rounded-full"
          style={{ width: `${progressPct || 0}%` }}
        />
      </div>

      {/* Vertical Stepper List */}
      <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-2">
        {STAGES.map((stageName, idx) => {
          let status = 'pending'; // pending | running | passed | failed
          let detail = null;

          if (isCompleted) {
            status = 'passed';
          } else if (idx < currentStageIndex) {
            status = 'passed';
          } else if (idx === currentStageIndex) {
            status = 'running';
          }

          const keyMap = {
            "File Validation": "file_validation",
            "Image Preprocessing": "preprocessing",
            "OCR Text Extraction": "ocr",
            "Information Parsing": "info_parsing",
            "QR Code Verification": "qr_verification",
            "Certificate Number Verification": "certificate_number_verification",
            "Template Matching": "template_matching",
            "Logo Verification": "logo_verification",
            "Seal Verification": "seal_verification",
            "Signature Verification": "signature_verification",
            "Metadata Analysis": "metadata_analysis",
            "Tampering Detection": "tampering_detection",
            "Issuing Authority Verification": "authority_verification"
          };

          const stageKey = keyMap[stageName];
          if (stageKey && stageResults[stageKey]) {
            const res = stageResults[stageKey];
            if (res.error) {
              status = 'failed';
              detail = res.error;
            } else if (res.notes || res.details) {
              detail = res.notes || res.details;
            }
          }

          return (
            <div
              key={stageName}
              className={`flex items-start gap-3 p-3 rounded-xl border text-sm transition-colors ${
                status === 'running'
                  ? 'bg-amber-50/80 border-amber-300 text-slate-900 shadow-2xs'
                  : status === 'passed'
                  ? 'bg-slate-50/70 border-slate-200 text-slate-800'
                  : status === 'failed'
                  ? 'bg-rose-50/80 border-rose-200 text-rose-900'
                  : 'bg-white border-slate-200/60 text-slate-400'
              }`}
            >
              <div className="mt-0.5 flex-shrink-0">
                {status === 'running' && <Loader2 className="w-4 h-4 text-amber-600 animate-spin" />}
                {status === 'passed' && <CheckCircle2 className="w-4 h-4 text-emerald-600" />}
                {status === 'failed' && <XCircle className="w-4 h-4 text-rose-600" />}
                {status === 'pending' && <Circle className="w-4 h-4 text-slate-300" />}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs sm:text-sm text-slate-800">
                    {idx + 1}. {stageName}
                  </span>
                  <span className={`text-[10px] font-mono font-bold capitalize px-2.5 py-0.5 rounded border ${
                    status === 'passed' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                    status === 'running' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                    status === 'failed' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                    'bg-slate-100 text-slate-500 border-slate-200'
                  }`}>
                    {status}
                  </span>
                </div>
                {detail && (
                  <p className="text-xs text-slate-600 mt-1 font-mono truncate">{detail}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
