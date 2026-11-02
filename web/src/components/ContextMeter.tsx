import type { ContextUsage } from "../lib/types";

function formatTokens(value: number): string {
  return value >= 1000 ? `${(value / 1000).toFixed(1)}k` : String(Math.round(value));
}

/** 上下文占用条：展示估算 token、预算百分比与压缩节省量 */
export function ContextMeter({ usage, className = "", compact = false }: {
  usage?: ContextUsage;
  className?: string;
  compact?: boolean;
}) {
  if (!usage || usage.budgetTokens <= 0) return null;
  const percent = Math.min(100, Math.max(0, usage.percent));
  const tone = percent >= 90 ? "bg-danger" : percent >= 70 ? "bg-warn" : "bg-brand";
  return (
    <div
      className={`min-w-[130px] ${className}`}
      title={`估算 ${usage.usedTokens}/${usage.budgetTokens} tokens；已压缩 ${usage.compressedItems} 项，节省约 ${usage.savedTokens} tokens；历史 ${usage.historyItems} 项`}
    >
      <div className="flex items-center justify-between gap-2 text-[9px] text-ink3">
        <span>上下文占用</span>
        <span className="font-mono">
          {formatTokens(usage.usedTokens)}/{formatTokens(usage.budgetTokens)} · {percent.toFixed(0)}%
        </span>
      </div>
      <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-subtle">
        <div className={`h-full rounded-full transition-all ${tone}`} style={{ width: `${percent}%` }} />
      </div>
      {!compact && usage.compressedItems > 0 && (
        <p className="mt-0.5 text-[9px] text-ink3">
          已压缩 {usage.compressedItems} 项 · 节省约 {formatTokens(usage.savedTokens)}
        </p>
      )}
    </div>
  );
}
