import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  History,
  MinusCircle,
  Play,
  ShieldCheck,
  XCircle
} from "lucide-react";
import { api } from "../lib/api";
import type { CheckItem, SelfCheckHistoryItem, SelfCheckRun } from "../lib/types";
import { CheckPill, Empty, Skeleton } from "../components/ui";
import { checkMeta, formatTime, timeAgo } from "../lib/format";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";

const statusIcon = {
  pass: <CheckCircle2 size={16} className="text-ok" />,
  warn: <AlertTriangle size={16} className="text-warn" />,
  fail: <XCircle size={16} className="text-danger" />,
  skip: <MinusCircle size={16} className="text-ink3" />
};

const groupOrder = ["数据库", "情报同步", "采集链路", "平台自身", "权限与审计"];

export function SelfCheckPage() {
  const toast = useToast();
  const { canWrite } = useAuth();
  const [run, setRun] = useState<SelfCheckRun | null>(null);
  const [history, setHistory] = useState<SelfCheckHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [latest, list] = await Promise.all([api.latestSelfCheck(), api.selfCheckHistory()]);
      setRun(latest.run ?? null);
      setHistory(list.items ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function execute() {
    if (running) return;
    if (!canWrite) {
      toast.push("只读账号无执行自检权限", "error");
      return;
    }
    setRunning(true);
    try {
      const result = await api.runSelfCheck();
      setRun(result);
      const list = await api.selfCheckHistory();
      setHistory(list.items ?? []);
      const tone = result.status === "fail" ? "error" : result.status === "warn" ? "info" : "success";
      toast.push(
        `自检完成：${result.passed} 通过 · ${result.warnings} 警告 · ${result.failed} 失败（${result.durationMs} ms）`,
        tone
      );
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "自检执行失败", "error");
    } finally {
      setRunning(false);
    }
  }

  const grouped = useMemo(() => {
    if (!run) return [];
    const map = new Map<string, CheckItem[]>();
    run.checks.forEach((check) => {
      const list = map.get(check.group) ?? [];
      list.push(check);
      map.set(check.group, list);
    });
    return [...map.entries()].sort(
      (a, b) => groupOrder.indexOf(a[0]) - groupOrder.indexOf(b[0])
    );
  }, [run]);

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <div className="card p-5">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="mt-4 h-12 w-full" />
        </div>
        <div className="grid grid-cols-12 gap-4">
          <div className="card col-span-12 p-5 xl:col-span-8">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="mt-4 h-64 w-full" />
          </div>
          <div className="card col-span-12 p-5 xl:col-span-4">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="mt-4 h-64 w-full" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <span
                className="flex h-9 w-9 items-center justify-center rounded-[10px]"
                style={{
                  backgroundColor:
                    run?.status === "fail" ? "#FFECEA" : run?.status === "warn" ? "#FFF3E0" : "#E9F9EE"
                }}
              >
                {run?.status === "fail" ? (
                  <XCircle size={18} className="text-danger" />
                ) : run?.status === "warn" ? (
                  <AlertTriangle size={18} className="text-warn" />
                ) : (
                  <ShieldCheck size={18} className="text-ok" />
                )}
              </span>
              <div>
                <h2 className="text-[16.5px] font-semibold leading-5 text-ink">
                  {run
                    ? run.status === "pass"
                      ? "自检全部通过"
                      : run.status === "warn"
                        ? "自检存在告警"
                        : "自检存在失败项"
                    : "尚未执行自检"}
                </h2>
                <p className="mt-0.5 text-[11.5px] text-ink3">
                  {run
                    ? `${formatTime(run.finishedAt)} · ${run.triggeredBy} 触发 · 耗时 ${run.durationMs} ms`
                    : "运行一次自检，检查数据库、情报、采集与平台自身状态"}
                </p>
              </div>
            </div>

            {run && (
              <div className="mt-4 flex flex-wrap gap-2">
                <Metric label="通过" value={run.passed} color="#1E7B3C" soft="#E9F9EE" />
                <Metric label="警告" value={run.warnings} color="#9A5B00" soft="#FFF3E0" />
                <Metric label="失败" value={run.failed} color="#C4170E" soft="#FFECEA" />
                {run.checks.filter((check) => check.status === "skip").length > 0 && (
                  <Metric
                    label="跳过"
                    value={run.checks.filter((check) => check.status === "skip").length}
                    color="#55555A"
                    soft="#F2F2F7"
                  />
                )}
                <Metric label="检查项" value={run.checks.length} color="#55555A" soft="#F2F2F7" />
              </div>
            )}
          </div>

          <div className="flex flex-col items-end gap-2">
            <button type="button" className="btn btn-primary h-9" onClick={() => void execute()} disabled={running}>
              {running ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
              ) : (
                <Play size={13} />
              )}
              {running ? "正在执行…" : "运行自检"}
            </button>
            <span className="text-[10.5px] text-ink3">
              {canWrite ? "只读运行，仅写入一条审计记录" : "当前账号无执行权限"}
            </span>
          </div>
        </div>
      </section>

      {error ? (
        <div className="card">
          <Empty title="自检数据加载失败" description={error} action={
            <button type="button" className="btn btn-secondary" onClick={() => void load()}>
              重试
            </button>
          } />
        </div>
      ) : !run ? (
        <div className="card">
          <Empty
            title="还没有自检记录"
            description="点击「运行自检」开始检查 16 项健康指标，结果会保留最近 10 次。"
            action={
              <button type="button" className="btn btn-primary" onClick={() => void execute()} disabled={running}>
                <Play size={13} />
                运行自检
              </button>
            }
          />
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 flex flex-col gap-4 xl:col-span-8">
            {grouped.map(([group, checks]) => {
              const warn = checks.filter((check) => check.status === "warn").length;
              const fail = checks.filter((check) => check.status === "fail").length;
              return (
                <section key={group} className="card overflow-hidden">
                  <header className="flex items-center justify-between gap-3 px-5 py-3.5">
                    <h3 className="text-[13px] font-semibold text-ink">{group}</h3>
                    <span className="text-[11px] text-ink3">
                      {checks.length} 项
                      {fail > 0 && <span className="ml-1.5 text-[#C4170E]">{fail} 失败</span>}
                      {warn > 0 && <span className="ml-1.5 text-[#9A5B00]">{warn} 告警</span>}
                    </span>
                  </header>
                  <div className="divider" />
                  <ul className="divide-y divide-line/70">
                    {checks.map((check) => (
                      <li key={check.id} className="flex items-start gap-3 px-5 py-3">
                        <span className="mt-0.5 shrink-0">{statusIcon[check.status]}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[12.5px] font-medium text-ink">{check.name}</span>
                            <span className="font-mono text-[10px] text-ink3">{check.id}</span>
                            {check.status !== "pass" && <CheckPill status={check.status} />}
                          </div>
                          <p className="mt-0.5 text-[11.5px] leading-[17px] text-ink2">{check.detail}</p>
                          {check.hint && check.status !== "pass" && (
                            <p className="mt-1 rounded-[8px] bg-subtle px-2 py-1 text-[10.5px] leading-[16px] text-ink3">
                              建议：{check.hint}
                            </p>
                          )}
                        </div>
                        {typeof check.durationMs === "number" && (
                          <span className="shrink-0 pt-0.5 font-mono text-[10px] text-ink3">
                            {check.durationMs < 1 ? "<1" : Math.round(check.durationMs)} ms
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              );
            })}
          </div>

          <div className="col-span-12 flex flex-col gap-4 xl:col-span-4">
            <section className="card">
              <header className="flex items-center gap-2 px-5 pt-4">
                <History size={14} className="text-ink3" />
                <h3 className="text-[13px] font-semibold text-ink">历史记录</h3>
                <span className="ml-auto text-[11px] text-ink3">{history.length} 次</span>
              </header>
              <ul className="mt-2 flex flex-col px-2 pb-2">
                {history.slice(0, 8).map((item) => {
                  const meta = checkMeta[item.status] ?? checkMeta.skip;
                  return (
                    <li
                      key={item.runId}
                      className="flex items-center gap-2.5 rounded-[10px] px-3 py-2.5 transition-colors hover:bg-subtle"
                    >
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: meta.color }}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block text-[11.5px] text-ink">{formatTime(item.finishedAt)}</span>
                        <span className="mt-0.5 block font-mono text-[10px] text-ink3">{item.runId}</span>
                      </span>
                      <span className="shrink-0 text-right">
                        <span className="block text-[11px] tabular-nums text-ink2">
                          {item.passed}/{item.passed + item.warnings + item.failed + (item.skipped ?? 0)}
                        </span>
                        <span className="block text-[10px] text-ink3">{item.durationMs} ms</span>
                      </span>
                    </li>
                  );
                })}
                {history.length === 0 && <li className="px-3 py-4 text-[11.5px] text-ink3">暂无历史记录</li>}
              </ul>
            </section>

            <section className="card p-5">
              <h3 className="text-[13px] font-semibold text-ink">自检覆盖范围</h3>
              <ul className="mt-2.5 flex flex-col gap-2 text-[11.5px] leading-[17px] text-ink2">
                <li className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-lineStrong" />
                  数据库完整性、数据量与读写延迟
                </li>
                <li className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-lineStrong" />
                  CVE / EPSS / POC 情报新鲜度与覆盖率
                </li>
                <li className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-lineStrong" />
                  Agent 在线率、离线超 24h 资产与最近上报
                </li>
                <li className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-lineStrong" />
                  平台自身依赖漏洞、构建信息与外部密钥
                </li>
                <li className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-lineStrong" />
                  默认口令、角色配置与审计可用性
                </li>
              </ul>
              <div className="mt-3 flex items-center gap-1.5 border-t border-line pt-3 text-[10.5px] text-ink3">
                <Clock3 size={11} />
                上次检查 {run ? timeAgo(run.finishedAt) : "—"}
              </div>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  color,
  soft
}: {
  label: string;
  value: number;
  color: string;
  soft: string;
}) {
  return (
    <span
      className="inline-flex items-center gap-2 rounded-[10px] px-3 py-1.5"
      style={{ backgroundColor: soft }}
    >
      <span className="text-[15px] font-semibold tabular-nums" style={{ color }}>
        {value}
      </span>
      <span className="text-[11px]" style={{ color }}>
        {label}
      </span>
    </span>
  );
}
