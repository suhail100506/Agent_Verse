import React from 'react';
import { BarChart2 } from 'lucide-react';

export default function ScoreBreakdownCard({ authenticityScore = {} }) {
  const stageMetrics = [
    { label: "OCR Accuracy", key: "ocr_score", weight: "10%" },
    { label: "QR Code Match", key: "qr_score", weight: "15%" },
    { label: "Certificate No. Format", key: "cert_number_score", weight: "10%" },
    { label: "Template Similarity", key: "template_score", weight: "15%" },
    { label: "Logo Verification", key: "logo_score", weight: "10%" },
    { label: "Official Seal Confidence", key: "seal_score", weight: "10%" },
    { label: "Authority Signature", key: "signature_score", weight: "10%" },
    { label: "Metadata Integrity", key: "metadata_score", weight: "10%" },
    { label: "Tampering Resistance", key: "tampering_score", weight: "10%" },
  ];

  const overallScore = authenticityScore.overall_score || 0;

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-brand-600" />
            <span>Forensic Authenticity Score Breakdown</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">Weighted stage contribution & weight-renormalized metrics</p>
        </div>

        <div className="text-right">
          <span className="text-3xl font-extrabold font-mono text-emerald-600">{overallScore.toFixed(1)}</span>
          <span className="text-slate-400 font-mono text-sm font-semibold"> / 100</span>
        </div>
      </div>

      <div className="space-y-4">
        {stageMetrics.map((item) => {
          const val = authenticityScore[item.key];
          const isExcluded = val === null || val === undefined;

          let colorClass = "bg-emerald-500";
          if (!isExcluded) {
            if (val < 50) colorClass = "bg-rose-500";
            else if (val < 75) colorClass = "bg-amber-500";
          }

          return (
            <div key={item.key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-700 font-semibold">{item.label} <span className="text-slate-400 font-mono">({item.weight})</span></span>
                <span className="font-mono">
                  {isExcluded ? (
                    <span className="text-slate-400 italic">Excluded / Unset</span>
                  ) : (
                    <span className={val >= 75 ? "text-emerald-700 font-bold" : val >= 50 ? "text-amber-700 font-bold" : "text-rose-700 font-bold"}>
                      {val.toFixed(1)}%
                    </span>
                  )}
                </span>
              </div>

              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200">
                {!isExcluded && (
                  <div
                    className={`h-2 rounded-full transition-all duration-500 ${colorClass}`}
                    style={{ width: `${Math.max(0, Math.min(100, val))}%` }}
                  />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
