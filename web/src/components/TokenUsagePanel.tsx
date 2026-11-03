import { useCallback, useEffect, useId, useState } from "react";
import { CircleAlert, Coins, Loader2, TrendingUp } from "lucide-react";
import { api } from "../lib/api";
import { compactNumber } from "../lib/format";
import type { TokenUsage } from "../lib/types";

const rangeOptions = [
  { days: 7, label: "近 7 天" },
  { days: 30, label: "近 30 天" },
  { days: 90, label: "近 90 天" }
];

const purposeMeta: Record<string, { label: string; color: string }> = {
  agent: { label: "终端 Agent", color: "var(--color-brand)" },
  qa: { label: "终端问答", color: "var(--color-signal)" },
  assistant: { label: "智能助手", color: "var(--color-ok)" },
  approval: { label: "AI 审批判断", color: "var(--color-warn)" },
  reference: { label: "命令检索", color: "#8B5CF6" },
  benchmark: { label: "加速基准测试", color: "#64748B" },
  unknown: { label: "未标注", color: "#98A2B3" }
};

const CHART_W = 100;
const CHART_H = 40;
const CHART_PAD = 3;

function trendPoints(values: number[], max: number): string {
  if (values.length === 0) return "";
  if (values.length === 1) {
    const y = CHART_H - CHART_PAD - Math.min(1, Math.max(0, values[0] / max)) * (CHART_H - CHART_PAD * 2);
    return `0,${y} ${CHART_W},${y}`;
  }
  return values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * CHART_W;
      const y = CHART_H - CHART_PAD - Math.min(1, Math.max(0, value / max)) * (CHART_H - CHART_PAD * 2);
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

function formatDate(value: string): string {
  const parts = value.split("-");
  return parts.length === 3 ? `${Number(parts[1])}/${Number(parts[2])}` : value;
}

// TokenUsagePanel 展示模型调用的 token 消耗：按模型、按用途与按天趋势
export function TokenUsagePanel() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState<TokenUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const gradientId = useId().replace(/[:]/g, "");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.tokenUsage(days));
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载 Token 统计失败");
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    void load();
  }, [load]);

  const totals = data?.totals;
  const values = data?.trend.map((point) => point.totalTokens) ?? [];
  const peak = Math.max(...values, 1);
  const hasData = Boolean(totals && totals.requests > 0);

  return (
    <section className="card mb-4 overflow-hidden">
      <header className="flex flex-wrap items-center gap-3 px-5 py-3.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand">
          <Coins size={15} />
        </span>
        <div className="min-w-0">
          <h2 className="text-[14px] font-semibold text-ink">Token 消耗</h2>
          <p className="mt-0.5 text-[11.5px] text-ink3">按模型与用途统计模型调用量，数据来自每次 Chat Completions 的 usage</p>
        </div>
        <div className="ml-auto flex items-center gap-1 rounded-[8px] border border-line p-0.5">
          {rangeOptions.map((option) => (
            <button
              key={option.days}
              type="button"
              onClick={() => setDays(option.days)}
              className={`h-6 rounded-[6px] px-2 text-[11px] transition-colors ${
                days === option.days ? "bg-brand-soft font-medium text-brand-strong" : "text-ink3 hover:bg-subtle"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </header>

      {error && (
        <div className="mx-5 mb-3 flex items-center gap-2 rounded-[8px] bg-dangerSoft px-2.5 py-2 text-[11px] text-danger">
          <CircleAlert size={13} />
          {error}
        </div>
      )}

      {loading && !data ? (
        <div className="flex items-center gap-2 border-t border-line px-5 py-10 text-[11.5px] text-ink3">
          <Loader2 size={13} className="animate-spin" />
          正在统计 Token 消耗…
        </div>
      ) : !hasData ? (
        <div className="border-t border-line px-5 py-10 text-center">
          <p className="text-[12px] text-ink2">统计区间内还没有模型调用记录</p>
          <p className="mt-1 text-[11px] text-ink3">使用终端 Agent、终端问答或智能助手后，这里会按模型自动累计</p>
        </div>
      ) : (
        <div className="border-t border-line px-5 py-4">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="总消耗" value={compactNumber(totals!.totalTokens)} suffix="tokens" emphasis />
            <Stat label="调用次数" value={totals!.requests.toLocaleString("zh-CN")} suffix="次" />
            <Stat
              label="输入 / 输出"
              value={`${compactNumber(totals!.promptTokens)} / ${compactNumber(totals!.completionTokens)}`}
              suffix="tokens"
            />
            <Stat label="平均每次" value={compactNumber(Math.round(totals!.avgTokensPerCall))} suffix="tokens" />
          </div>

          <div className="mt-4 grid grid-cols-12 gap-4">
            <div className="col-span-12 xl:col-span-7">
              <div className="flex items-center justify-between">
                <p className="text-[12px] font-medium text-ink">模型消耗占比</p>
                <span className="text-[10.5px] text-ink3">按 token 总量排序</span>
              </div>
              <div className="mt-2 space-y-2.5">
                {data!.models.slice(0, 8).map((item, index) => (
                  <div key={item.model}>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="truncate text-[11.5px] text-ink" title={item.model}>
                        {item.model}
                      </span>
                      <span className="shrink-0 font-mono text-[10.5px] text-ink2">
                        {compactNumber(item.totalTokens)} · {item.share}%
                      </span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-subtle">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${Math.max(item.share, 1)}%`,
                          background: index === 0 ? "var(--color-brand)" : index === 1 ? "var(--color-signal)" : "var(--color-ok)"
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="col-span-12 xl:col-span-5">
              <div className="flex items-center justify-between">
                <p className="text-[12px] font-medium text-ink">每日趋势</p>
                <span className="flex items-center gap-1 text-[10.5px] text-ink3">
                  <TrendingUp size={11} />
                  峰值 {compactNumber(peak)}
                </span>
              </div>
              <div className="relative mt-2 h-[110px]">
                <svg
                  viewBox={`0 0 ${CHART_W} ${CHART_H}`}
                  preserveAspectRatio="none"
                  className="h-full w-full overflow-visible"
                  role="img"
                  aria-label="每日 Token 消耗趋势"
                >
                  <defs>
                    <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--color-brand)" stopOpacity="0.24" />
                      <stop offset="100%" stopColor="var(--color-brand)" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  {[0.25, 0.5, 0.75].map((ratio) => (
                    <line
                      key={ratio}
                      x1="0"
                      x2={CHART_W}
                      y1={CHART_H * ratio}
                      y2={CHART_H * ratio}
                      stroke="var(--color-line)"
                      strokeWidth="0.4"
                      vectorEffect="non-scaling-stroke"
                    />
                  ))}
                  <polygon
                    points={`0,${CHART_H} ${trendPoints(values, peak)} ${CHART_W},${CHART_H}`}
                    fill={`url(#${gradientId})`}
                  />
                  <polyline
                    points={trendPoints(values, peak)}
                    fill="none"
                    stroke="var(--color-brand)"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    vectorEffect="non-scaling-stroke"
                  />
                </svg>
              </div>
              <div className="mt-1 flex justify-between font-mono text-[9.5px] text-ink3">
                <span>{formatDate(data!.trend[0]?.date ?? "")}</span>
                <span>{formatDate(data!.trend[data!.trend.length - 1]?.date ?? "")}</span>
              </div>

              <p className="mt-3 text-[12px] font-medium text-ink">用途分布</p>
              <div className="mt-1.5 space-y-1.5">
                {data!.purposes.map((item) => {
                  const meta = purposeMeta[item.purpose] ?? { label: item.purpose, color: "#98A2B3" };
                  return (
                    <div key={item.purpose} className="flex items-center gap-2">
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: meta.color }} />
                      <span className="w-[86px] shrink-0 truncate text-[10.5px] text-ink2">{meta.label}</span>
                      <div className="h-1 flex-1 overflow-hidden rounded-full bg-subtle">
                        <div className="h-full rounded-full" style={{ width: `${Math.max(item.share, 1)}%`, background: meta.color }} />
                      </div>
                      <span className="w-[52px] shrink-0 text-right font-mono text-[10px] text-ink3">{item.share}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-[11.5px]">
              <thead>
                <tr className="border-b border-line text-left text-[10.5px] text-ink3">
                  <th className="py-1.5 pr-3 font-medium">模型</th>
                  <th className="py-1.5 pr-3 text-right font-medium">调用次数</th>
                  <th className="py-1.5 pr-3 text-right font-medium">输入</th>
                  <th className="py-1.5 pr-3 text-right font-medium">输出</th>
                  <th className="py-1.5 pr-3 text-right font-medium">合计</th>
                  <th className="py-1.5 text-right font-medium">占比</th>
                </tr>
              </thead>
              <tbody>
                {data!.models.map((item) => (
                  <tr key={item.model} className="border-b border-line/50 last:border-0">
                    <td className="max-w-[260px] truncate py-1.5 pr-3 text-ink" title={item.model}>
                      {item.model}
                      {item.estimatedRequests > 0 && (
                        <span className="ml-1.5 text-[9.5px] text-ink3" title="服务未返回 usage，按字符估算">
                          {item.estimatedRequests} 次估算
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 text-right font-mono text-ink2">{item.requests.toLocaleString("zh-CN")}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-ink2">{compactNumber(item.promptTokens)}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-ink2">{compactNumber(item.completionTokens)}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-ink">{compactNumber(item.totalTokens)}</td>
                    <td className="py-1.5 text-right font-mono text-ink2">{item.share}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totals!.estimatedRequests > 0 && (
            <p className="mt-2 text-[10px] text-ink3">
              其中 {totals!.estimatedRequests} 次调用未返回 usage，按「中文 1 字 1 token、其他 4 字符 1 token」估算。
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function Stat({ label, value, suffix, emphasis = false }: { label: string; value: string; suffix: string; emphasis?: boolean }) {
  return (
    <div className="rounded-[9px] border border-line bg-subtle/40 px-3 py-2.5">
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className={`mt-1 font-mono text-[18px] leading-6 ${emphasis ? "text-brand-strong" : "text-ink"}`}>{value}</p>
      <p className="text-[9.5px] text-ink3">{suffix}</p>
    </div>
  );
}
