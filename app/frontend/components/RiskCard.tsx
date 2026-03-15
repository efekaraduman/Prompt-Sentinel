import type { FC } from "react";

interface RiskCardProps {
  riskScore: number | null;
  summary?: string;
}

function getRiskLevel(score: number | null): { label: string; description: string; badgeClass: string } {
  if (score === null) {
    return {
      label: "NO DATA",
      description: "Run a test to compute a prompt-injection risk score.",
      badgeClass: "bg-neutral-700/40 text-neutral-300",
    };
  }

  if (score >= 70) {
    return {
      label: "HIGH",
      description: "Significant leakage or override behavior detected across tests.",
      badgeClass: "bg-red-600/20 text-red-400",
    };
  }

  if (score >= 40) {
    return {
      label: "MEDIUM",
      description: "Some moderate prompt-injection concerns were observed.",
      badgeClass: "bg-amber-600/20 text-amber-400",
    };
  }

  return {
    label: "LOW",
    description: "No major issues detected; residual risk is low for this prompt.",
    badgeClass: "bg-green-600/20 text-green-400",
  };
}

const RiskCard: FC<RiskCardProps> = ({ riskScore, summary }) => {
  const level = getRiskLevel(riskScore);

  return (
    <section className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-6 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-medium uppercase tracking-[0.2em] text-neutral-400">
            Overall Risk
          </h2>
          <div className="mt-3 flex items-baseline gap-3">
            <span className="text-5xl font-semibold tabular-nums text-neutral-50">
              {riskScore !== null ? riskScore : "--"}
            </span>
            <div className="flex flex-col gap-1">
              <span
                className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-medium ${level.badgeClass}`}
              >
                {level.label} RISK
              </span>
              <p className="text-xs text-neutral-400 max-w-xs">{level.description}</p>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 text-right text-xs text-neutral-500">
          <span>PromptSentinel · LLM security baseline</span>
          <span className="font-mono text-[11px] text-neutral-500/80">
            Simulated prompt-injection test bench
          </span>
        </div>
      </div>
      {summary && (
        <p className="mt-5 text-sm leading-relaxed text-neutral-200">{summary}</p>
      )}
    </section>
  );
};

export default RiskCard;

