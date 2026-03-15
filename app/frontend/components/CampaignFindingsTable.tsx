import type { FC } from "react";
import { useState } from "react";

import type { FindingResponse } from "../lib/types";

interface CampaignFindingsTableProps {
  findings: FindingResponse[];
  loading?: boolean;
}

const CampaignFindingsTable: FC<CampaignFindingsTableProps> = ({ findings, loading }) => {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const toggle = (id: number) => {
    setExpanded((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  return (
    <section className="mt-4 rounded-xl border border-neutral-800 bg-neutral-900/40">
      <header className="flex items-center justify-between border-b border-neutral-800 px-4 py-3 md:px-6">
        <div>
          <h2 className="text-sm font-medium text-neutral-100">Campaign Findings</h2>
          <p className="mt-0.5 text-xs text-neutral-400">
            {loading
              ? "Collecting findings from the active campaign..."
              : findings.length
              ? `Showing ${findings.length} highest-risk findings.`
              : "Start a campaign to populate this table with high-risk behaviors."}
          </p>
        </div>
      </header>

      {findings.length === 0 ? (
        <div className="px-4 py-10 text-center text-sm text-neutral-400 md:px-6">
          <p className="mb-2 font-medium text-neutral-200">No findings yet.</p>
          <p className="text-xs text-neutral-500">
            When a campaign is running, PromptSentinel will log each simulated attack and surface the
            most concerning responses here.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full border-t border-neutral-800 text-sm">
            <thead className="bg-neutral-950/80">
              <tr className="text-xs uppercase tracking-[0.16em] text-neutral-500">
                <th className="whitespace-nowrap px-4 py-3 text-left font-medium md:px-6">
                  Iteration
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left font-medium md:px-4">
                  Signals
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left font-medium md:px-4">
                  Risk
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-right font-medium md:px-6">
                  Response
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/80">
              {findings.map((finding) => {
                const isExpanded = expanded[finding.id] ?? false;
                const riskBadgeClass =
                  finding.risk_score >= 70
                    ? "bg-red-600/20 text-red-400"
                    : finding.risk_score >= 40
                    ? "bg-amber-600/20 text-amber-400"
                    : "bg-green-600/20 text-green-400";

                return (
                  <tr key={finding.id} className="align-top">
                    <td className="px-4 py-4 md:px-6">
                      <div className="flex flex-col gap-1">
                        <span className="text-[11px] font-mono uppercase tracking-[0.2em] text-neutral-500">
                          Iteration #{finding.iteration}
                        </span>
                        <p className="text-xs text-neutral-400">
                          {new Date(finding.created_at).toLocaleString()}
                        </p>
                        <p className="text-sm leading-relaxed text-neutral-100">
                          {finding.category}
                        </p>
                        <p className="mt-1 text-xs text-neutral-300 line-clamp-2">
                          {finding.attack_prompt}
                        </p>
                      </div>
                    </td>
                    <td className="px-4 py-4 md:px-4">
                      <div className="flex flex-col gap-2">
                        <span
                          className={`inline-flex w-fit items-center rounded-full px-2.5 py-1 text-[11px] font-medium ${
                            finding.leakage_detected
                              ? "bg-red-600/15 text-red-400"
                              : "bg-emerald-600/15 text-emerald-300"
                          }`}
                        >
                          {finding.leakage_detected ? "Leakage detected" : "No leakage detected"}
                        </span>
                        <span
                          className={`inline-flex w-fit items-center rounded-full px-2.5 py-1 text-[11px] font-medium ${
                            finding.override_detected
                              ? "bg-red-600/15 text-red-400"
                              : "bg-emerald-600/15 text-emerald-300"
                          }`}
                        >
                          {finding.override_detected
                            ? "Override behavior detected"
                            : "No override behavior detected"}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-4 md:px-4">
                      <div className="flex flex-col items-start gap-1">
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold tabular-nums ${riskBadgeClass}`}
                        >
                          {finding.risk_score}
                        </span>
                        <span className="text-[11px] text-neutral-400">
                          {(finding.risk_score >= 70 && "High risk") ||
                            (finding.risk_score >= 40 && "Medium risk") ||
                            "Low risk"}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-right md:px-6">
                      <button
                        type="button"
                        onClick={() => toggle(finding.id)}
                        className="inline-flex items-center justify-end gap-1.5 rounded-full border border-neutral-700 bg-neutral-900/60 px-3 py-1.5 text-[11px] font-medium text-neutral-200 transition-colors hover:border-neutral-500 hover:bg-neutral-800"
                      >
                        <span className="uppercase tracking-[0.16em]">
                          {isExpanded ? "Hide response" : "Show response"}
                        </span>
                        <span className="text-xs">{isExpanded ? "▴" : "▾"}</span>
                      </button>
                      {isExpanded && (
                        <div className="mt-3 max-h-56 overflow-y-auto rounded-lg border border-neutral-800 bg-neutral-950/80 px-3 py-2 text-left text-xs leading-relaxed text-neutral-100">
                          <pre className="whitespace-pre-wrap font-mono text-[11px] text-neutral-100">
                            {finding.llm_response}
                          </pre>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};

export default CampaignFindingsTable;

