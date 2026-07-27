import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, XCircle, HelpCircle } from 'lucide-react';

export default function ClassificationBadge({ classification, score }) {
  let badgeStyle = "bg-slate-100 text-slate-700 border-slate-300";
  let Icon = HelpCircle;

  switch (classification) {
    case "Verified":
      badgeStyle = "bg-emerald-50 text-emerald-800 border-emerald-300 shadow-xs";
      Icon = ShieldCheck;
      break;
    case "Likely Genuine":
      badgeStyle = "bg-teal-50 text-teal-800 border-teal-300 shadow-xs";
      Icon = ShieldCheck;
      break;
    case "Suspicious":
      badgeStyle = "bg-amber-50 text-amber-800 border-amber-300 shadow-xs";
      Icon = AlertTriangle;
      break;
    case "Likely Fake":
    case "Fake":
      badgeStyle = "bg-rose-50 text-rose-800 border-rose-300 shadow-xs";
      Icon = XCircle;
      break;
    case "Manual Review Required":
      badgeStyle = "bg-slate-100 text-slate-800 border-slate-300 shadow-xs";
      Icon = ShieldAlert;
      break;
    default:
      badgeStyle = "bg-slate-100 text-slate-700 border-slate-300";
  }

  return (
    <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-xs font-bold tracking-wide ${badgeStyle}`}>
      <Icon className="w-4 h-4 flex-shrink-0" />
      <span>{classification || "Processing"}</span>
      {score !== undefined && score !== null && (
        <span className="ml-0.5 font-mono opacity-80 font-semibold">({score.toFixed(1)}%)</span>
      )}
    </div>
  );
}
