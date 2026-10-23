import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowUpRight, RefreshCw, ShieldAlert } from "lucide-react";
import { api } from "../lib/api";
import type { Overview } from "../lib/types";
import { Dot, RiskMeter, SectionCard, Skeleton } from "../components/ui";
import { TrendChart } from "../components/TrendChart";
import { compactNumber, formatTime, priorityMeta, timeAgo } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const actionLabels: Record<string, string> = {
  "finding.status": "状态变更",
  "finding.ticket": "创建工单",
  "finding.rescan": "触发复扫",
  "scan.trigger": "触发扫描",
  "auth.login": "登录",
  "auth.logout": "登出",
  "export.findings": "导出",
  "policy.update": "策略调整",
  "selfcheck.run": "平台自检",
  "sync.cve": "CVE 同步",
  "sync.poc": "POC 同步",
  "sync.epss": "EPSS 同步"
};

export function OverviewPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const { isAdmin } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();

  const load = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    try {
      const result = await api.overview();
      setData(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function syncIntel() {
    if (syncing) return;
    setSyncing(true);
    try {
      const result = await api.triggerSync("cve");
      toast.push(`CVE 情报同步完成：新增 ${result.inserted} 条 · 更新 ${result.updated} 条`);
      await load(true);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "同步失败", "error");
    } finally {
      setSyncing(false);
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {[0, 1, 2, 3].map((key) => (
            <div key={key} className="card p-5">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="mt-4 h-9 w-20" />
              <Skeleton className="mt-4 h-1.5 w-full" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-12 gap-4">
          <div className="card col-span-12 p-5 xl:col-span-8">
            <Skeleton className="h-5 w-24" />
            <Skeleton className="mt-4 h-[176px] w-full" />
          </div>
          <div className="card col-span-12 p-5 xl:col-span-4">
            <Skeleton className="h-5 w-24" />
            <Skeleton className="mt-4 h-[176px] w-full" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card flex flex-col items-center gap-3 p-10 text-center">
        <ShieldAlert size={22} className="text-ink3" />
        <p className="text-[13.5px] font-medium text-ink">无法加载概览数据</p>
        <p className="max-w-[360px] text-[12.5px] leading-[19px] text-ink3">{error}</p>
        <button type="button" className="btn btn-secondary mt-1" onClick={() => void load()}>
          <RefreshCw size={14} />
          重试
        </button>
      </div>
    );
  }

  const { counts, trend } = data;
  const first = trend[0];

  const shares = (() => {
    const values = [counts.p0, counts.p1, counts.p2, counts.p3];
    const total = values.reduce((sum, value) => sum + value, 0) || 1;
    const raw = values.map((value) => (value / total) * 100);
    const base = raw.map(Math.floor);
    let rest = 100 - base.reduce((sum, value) => sum + value, 0);
    const order = raw
      .map((value, index) => ({ index, frac: value - Math.floor(value) }))
      .sort((a, b) => b.frac - a.frac);
    for (let index = 0; index < rest && index < order.length; index += 1) {
      base[order[index].index] += 1;
    }
    return base;
  })();

  const kpis = [
    { key: "p0" as const, delta: first ? counts.p0 - first.p0 : 0 },
    { key: "p1" as const, delta: first ? counts.p1 - first.p1 : 0 },
    { key: "p2" as const, delta: first ? counts.p2 - first.p2 : 0 },
    { key: "p3" as const, delta: first ? counts.p3 - first.p3 : 0 }
  ];

  const agentRate = data.agents.total ? data.agents.online / data.agents.total : 0;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[12px] text-ink3">
          <span>数据截至 {formatTime(data.generatedAt)}</span>
          <span className="h-3 w-px bg-line" />
          <span>{counts.total} 条漏洞 · {counts.open + counts.fixing} 条待闭环</span>
        </div>
        <button
          type="button"
          className="btn btn-secondary h-8"
          onClick={() => void load(true)}
          disabled={refreshing}
        >
          <RefreshCw size={13.5} className={refreshing ? "animate-spin" : ""} />
          刷新
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {kpis.map(({ key, delta }, index) => {
          const meta = priorityMeta[key.toUpperCase() as "P0" | "P1" | "P2" | "P3"];
          const value = counts[key];
          const share = shares[index];
          return (
            <button
              key={key}
              type="button"
              onClick={() => navigate(`/findings?priority=${key.toUpperCase()}`)}
              className="card group p-5 text-left transition-shadow hover:shadow-float"
            >
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-ink2">
                  <Dot color={meta.color} />
                  {key.toUpperCase()} {meta.label}
                </span>
                <ArrowUpRight
                  size={14}
                  className="text-ink3 opacity-0 transition-opacity group-hover:opacity-100"
                />
              </div>
              <p className="metric mt-3 text-ink">{value}</p>
              <div className="mt-3 flex items-center justify-between gap-2 whitespace-nowrap text-[11px] text-ink3">
                <span>占总量 {share}%</span>
                <span className={delta > 0 ? "text-[#C4170E]" : delta < 0 ? "text-[#1E7B3C]" : ""}>
                  {delta > 0 ? `+${delta}` : delta < 0 ? delta : "持平"}
                  <span className="hidden sm:inline"> · 14 天</span>
                </span>
              </div>
              <span className="mt-2 block h-1 overflow-hidden rounded-full bg-line">
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${share}%`, backgroundColor: meta.color }}
                />
              </span>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-12 gap-4">
        <SectionCard
          className="col-span-12 xl:col-span-8"
          title="漏洞趋势"
          subtitle="每 6 小时快照一次，按优先级堆叠"
          bodyClassName="px-5 pb-5 pt-4"
        >
          <TrendChart data={trend} />
        </SectionCard>

        <SectionCard
          className="col-span-12 xl:col-span-4"
          title="运行状态"
          subtitle="情报、采集与自检"
          bodyClassName="px-5 pb-5 pt-2"
          action={
            isAdmin ? (
              <button
                type="button"
                onClick={() => void syncIntel()}
                disabled={syncing}
                className="inline-flex items-center gap-1 rounded-full border border-line px-2 py-1 text-[11px] text-ink2 transition-colors hover:bg-subtle disabled:opacity-50"
              >
                <RefreshCw size={11} className={syncing ? "animate-spin" : ""} />
                同步情报
              </button>
            ) : undefined
          }
        >
          <div className="flex flex-col">
            <div className="flex flex-col gap-2.5 py-3">
              {data.sync.map((source) => {
                const color = source.status === "ok" ? "#34C759" : source.status === "warn" ? "#FF9F0A" : "#FF3B30";
                const name = source.source === "cve" ? "CVE 情报" : source.source === "poc" ? "POC 情报" : "EPSS";
                return (
                  <div key={source.source} className="flex items-center justify-between gap-3">
                    <span className="inline-flex items-center gap-2 text-[12.5px] text-ink">
                      <Dot color={color} />
                      {name}
                    </span>
                    <span className="flex items-center gap-2 text-[11.5px] text-ink3">
                      <span className="tabular-nums">{compactNumber(source.count)} 条</span>
                      <span className="h-3 w-px bg-line" />
                      <span className={source.lagHours > 6 ? "text-[#9A5B00]" : ""}>
                        {source.lagHours}h 前
                      </span>
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="divider" />

            <Link to="/assets" className="group flex items-center justify-between gap-3 py-3">
              <span className="text-[12.5px] text-ink">Agent 在线</span>
              <span className="flex items-center gap-2 text-[11.5px] text-ink3">
                <span className="tabular-nums text-ink">
                  {data.agents.online} / {data.agents.total}
                </span>
                <span className="h-1.5 w-16 overflow-hidden rounded-full bg-line">
                  <span
                    className="block h-full rounded-full"
                    style={{
                      width: `${Math.round(agentRate * 100)}%`,
                      backgroundColor: agentRate >= 0.8 ? "#34C759" : "#FF9F0A"
                    }}
                  />
                </span>
              </span>
            </Link>

            <div className="divider" />

            <Link to="/selfcheck" className="group flex items-center justify-between gap-3 py-3">
              <span className="text-[12.5px] text-ink">平台自检</span>
              <span className="flex items-center gap-2 text-[11.5px] text-ink3">
                <span
                  className="pill"
                  style={{
                    backgroundColor: data.selfcheck.status === "pass" ? "#E9F9EE" : "#FFF3E0",
                    color: data.selfcheck.status === "pass" ? "#1E7B3C" : "#9A5B00"
                  }}
                >
                  {data.selfcheck.status === "pass" ? "全部通过" : "有告警"}
                </span>
                <span>{timeAgo(data.selfcheck.checkedAt)}</span>
                <ArrowUpRight size={13} className="text-ink3 transition-colors group-hover:text-ink" />
              </span>
            </Link>
          </div>
        </SectionCard>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <SectionCard
          className="col-span-12 xl:col-span-5"
          title="风险最高的组件"
          subtitle="按单组件最高风险分排序"
          bodyClassName="px-3 pb-3 pt-1"
          action={
            <Link to="/findings" className="inline-flex items-center gap-0.5 text-[11.5px] text-brand">
              查看全部
              <ArrowUpRight size={12} />
            </Link>
          }
        >
          <div className="flex flex-col">
            {data.topComponents.slice(0, 6).map((component, index) => (
              <button
                key={`${component.name}-${component.version}`}
                type="button"
                onClick={() => navigate(`/findings?q=${encodeURIComponent(component.name)}`)}
                className="row-hover flex items-center gap-3 rounded-[10px] px-2 py-2.5 text-left"
              >
                <span className="w-4 text-[11px] tabular-nums text-ink3">{index + 1}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[12.5px] font-medium text-ink">{component.name}</span>
                  <span className="mt-0.5 flex items-center gap-1.5 text-[11px] text-ink3">
                    <span className="font-mono">{component.version}</span>
                    <span className="h-2.5 w-px bg-line" />
                    {component.ecosystem}
                    <span className="h-2.5 w-px bg-line" />
                    {component.cveCount} 个 CVE · {component.assetCount} 台
                  </span>
                </span>
                <RiskMeter value={component.maxRisk} width={48} />
              </button>
            ))}
          </div>
        </SectionCard>

        <SectionCard
          className="col-span-12 xl:col-span-7"
          title="最近动态"
          subtitle="来自审计日志的写操作与扫描记录"
          bodyClassName="px-5 pb-4 pt-1"
          action={
            <Link to="/settings" className="inline-flex items-center gap-0.5 text-[11.5px] text-brand">
              审计日志
              <ArrowUpRight size={12} />
            </Link>
          }
        >
          <ol className="relative flex flex-col">
            {data.recentEvents.slice(0, 7).map((event) => (
              <li key={event.id} className="relative flex gap-3 py-2.5">
                <span className="relative mt-1.5 flex h-1.5 w-1.5 shrink-0 rounded-full bg-brand" />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                    <span className="text-[12.5px] font-medium text-ink">
                      {actionLabels[event.action] ?? event.action}
                    </span>
                    <span className="truncate text-[12px] text-ink2">{event.target}</span>
                  </span>
                  <span className="mt-0.5 flex items-center gap-1.5 overflow-hidden whitespace-nowrap text-[11px] text-ink3">
                    <span className="shrink-0">{event.actor}</span>
                    <span className="h-2.5 w-px shrink-0 bg-line" />
                    <span className="shrink-0">{timeAgo(event.time)}</span>
                    {event.detail && (
                      <>
                        <span className="hidden h-2.5 w-px shrink-0 bg-line sm:block" />
                        <span className="hidden min-w-0 truncate sm:block">{event.detail}</span>
                      </>
                    )}
                  </span>
                </span>
              </li>
            ))}
          </ol>
        </SectionCard>
      </div>
    </div>
  );
}
