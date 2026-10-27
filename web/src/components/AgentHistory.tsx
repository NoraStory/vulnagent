import { useEffect, useState } from "react";
import { Bot, CircleAlert, History, Loader2, RotateCcw, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { formatTime, timeAgo } from "../lib/format";
import type { SshAgentRun, SshAgentRunDetail } from "../lib/types";

type Props = {
  onClose: () => void;
  onReuseGoal?: (goal: string) => void;
};

const modeLabel: Record<string, string> = {
  confirm: "逐条确认",
  safe: "仅危险确认",
  auto: "全自动"
};

const statusLabel: Record<string, string> = {
  running: "运行中",
  completed: "已完成",
  failed: "失败"
};

export function AgentHistory({ onClose, onReuseGoal }: Props) {
  const [runs, setRuns] = useState<SshAgentRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<SshAgentRunDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .sshAgentRuns({ limit: 30 })
      .then((result) => {
        if (cancelled) return;
        setRuns(result.items ?? []);
        setError("");
        if (result.items?.length) setSelected(result.items[0].id);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "读取运行历史失败");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setDetailLoading(true);
    api
      .sshAgentRunDetail(selected)
      .then((data) => {
        if (!cancelled) setDetail(data);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4" onClick={onClose} role="presentation">
      <div
        className="flex h-[76vh] max-h-[680px] w-[860px] max-w-[96vw] flex-col overflow-hidden rounded-[12px] border border-line bg-surface shadow-float"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Agent 运行历史"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-brand-soft text-brand">
            <History size={14} />
          </span>
          <div className="min-w-0">
            <p className="text-[12.5px] font-semibold text-ink">Agent 运行历史</p>
            <p className="text-[10px] text-ink3">目标、模式、每一步命令与输出均可在事后复盘</p>
          </div>
          <button
            type="button"
            className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={onClose}
            aria-label="关闭运行历史"
          >
            <X size={15} />
          </button>
        </header>

        {error && (
          <div className="mx-4 mt-3 flex items-center gap-2 rounded-[8px] bg-dangerSoft px-2.5 py-2 text-[11px] text-danger">
            <CircleAlert size={13} />
            {error}
          </div>
        )}

        <div className="flex min-h-0 flex-1">
          <div className="w-[220px] shrink-0 overflow-y-auto border-r border-line">
            {loading && (
              <div className="flex items-center gap-2 px-3 py-4 text-[11px] text-ink3">
                <Loader2 size={12} className="animate-spin" />
                读取中…
              </div>
            )}
            {!loading && runs.length === 0 && (
              <p className="px-3 py-8 text-center text-[10.5px] text-ink3">还没有 Agent 运行记录</p>
            )}
            {runs.map((run) => (
              <button
                key={run.id}
                type="button"
                onClick={() => setSelected(run.id)}
                className={`block w-full border-b border-line/60 px-3 py-2 text-left transition-colors ${
                  selected === run.id ? "bg-brand-soft/60" : "hover:bg-subtle/60"
                }`}
              >
                <div className="flex items-center gap-1">
                  <span className="truncate text-[11px] font-medium text-ink">{run.hostName}</span>
                  <span
                    className={`ml-auto shrink-0 text-[9px] ${
                      run.status === "completed"
                        ? "text-ok"
                        : run.status === "failed"
                          ? "text-danger"
                          : "text-warn"
                    }`}
                  >
                    {statusLabel[run.status] ?? run.status}
                  </span>
                </div>
                <p className="mt-0.5 line-clamp-2 text-[10px] leading-[14px] text-ink2">{run.goal}</p>
                <p className="mt-0.5 text-[9px] text-ink3">
                  {run.steps} 步 · {timeAgo(run.startedAt)}
                </p>
              </button>
            ))}
          </div>

          <div className="min-w-0 flex-1 overflow-y-auto px-4 py-3">
            {detailLoading && (
              <div className="flex items-center gap-2 text-[11px] text-ink3">
                <Loader2 size={12} className="animate-spin" />
                正在读取运行详情…
              </div>
            )}
            {!detailLoading && !detail && runs.length > 0 && (
              <p className="py-8 text-center text-[11px] text-ink3">选择左侧运行查看详情</p>
            )}
            {detail && (
              <div className="space-y-3">
                <div>
                  <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-ink3">
                    <Bot size={11} className="text-brand" />
                    <span className="font-mono">#{detail.run.id.slice(0, 8)}</span>
                    <span>{detail.run.hostName}</span>
                    <span>{detail.run.actor}</span>
                    <span>{modeLabel[detail.run.mode] ?? detail.run.mode}</span>
                    <span>{formatTime(detail.run.startedAt)}</span>
                    <span
                      className={`ml-auto ${
                        detail.run.status === "completed"
                          ? "text-ok"
                          : detail.run.status === "failed"
                            ? "text-danger"
                            : "text-warn"
                      }`}
                    >
                      {statusLabel[detail.run.status] ?? detail.run.status}
                    </span>
                  </div>
                  <p className="mt-1.5 rounded-[8px] bg-subtle/70 px-2.5 py-2 text-[11px] leading-[17px] text-ink">
                    {detail.run.goal}
                  </p>
                  {onReuseGoal && (
                    <button
                      type="button"
                      className="btn btn-secondary mt-1.5 h-6 px-2 text-[10px]"
                      onClick={() => {
                        onReuseGoal(detail.run.goal);
                        onClose();
                      }}
                    >
                      <RotateCcw size={10} />
                      复用此目标
                    </button>
                  )}
                </div>

                {detail.steps.length === 0 && <p className="text-[11px] text-ink3">本次运行没有记录步骤。</p>}
                {detail.steps.map((step) => (
                  <div key={step.index} className="rounded-[9px] border border-line bg-surface px-2.5 py-2">
                    <div className="flex items-center gap-1.5 text-[9.5px] text-ink3">
                      <span className="font-mono">#{step.index + 1}</span>
                      <span className="pill h-[18px] px-1.5 text-[9px]">{step.risk}</span>
                      {step.approved === "rejected" && <span className="text-danger">已拒绝</span>}
                      {step.approved === "user" && <span className="text-ok">已确认</span>}
                      {step.approved === "auto" && <span>自动执行</span>}
                      <span className="ml-auto font-mono">exit {step.exitCode}</span>
                    </div>
                    {step.thought && <p className="mt-1 text-[10.5px] leading-[16px] text-ink2">{step.thought}</p>}
                    <pre className="mt-1.5 overflow-x-auto rounded-[6px] bg-[#0B1220] px-2 py-1.5 font-mono text-[10.5px] leading-[15px] text-[#D7DEEA]">
                      {step.command}
                    </pre>
                    <details className="mt-1.5">
                      <summary className="cursor-pointer text-[10px] text-ink3">查看输出</summary>
                      <pre className="mt-1 max-h-44 overflow-auto whitespace-pre-wrap break-all rounded-[6px] bg-subtle px-2 py-1.5 font-mono text-[10px] leading-[15px] text-ink2">
                        {step.output || "（无输出）"}
                      </pre>
                    </details>
                  </div>
                ))}

                {detail.run.summary && (
                  <div className="rounded-[9px] border border-line bg-subtle/70 px-2.5 py-2">
                    <p className="text-[10.5px] font-medium text-ink">收尾结论</p>
                    <p className="mt-1 text-[10.5px] leading-[17px] text-ink2">{detail.run.summary}</p>
                  </div>
                )}
                {detail.run.error && (
                  <div className="rounded-[9px] bg-dangerSoft px-2.5 py-2 text-[10.5px] text-danger">{detail.run.error}</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
