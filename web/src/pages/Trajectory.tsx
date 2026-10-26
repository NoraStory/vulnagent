import { useCallback, useEffect, useState } from "react";
import { Activity, RefreshCw, ShieldAlert, Terminal, Wrench } from "lucide-react";
import { api } from "../lib/api";
import type { TrajectoryItem } from "../lib/types";
import { Empty, Skeleton } from "../components/ui";
import { formatTime } from "../lib/format";

const kinds = [
  { key: "", label: "全部", icon: Activity },
  { key: "audit", label: "审计", icon: ShieldAlert },
  { key: "job", label: "主机作业", icon: Terminal },
  { key: "tool", label: "工具调用", icon: Wrench }
];

export function TrajectoryPage() {
  const [items, setItems] = useState<TrajectoryItem[]>([]);
  const [kind, setKind] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.trajectory({ kind, limit: 200 });
      setItems(result.items);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [kind]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1">
          {kinds.map((item) => {
            const Icon = item.icon;
            const active = kind === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setKind(item.key)}
                className={`inline-flex items-center gap-1.5 rounded-[8px] px-3 py-1.5 text-[12px] font-medium transition-colors ${
                  active ? "bg-subtle text-ink" : "text-ink2 hover:text-ink"
                }`}
              >
                <Icon size={12.5} />
                {item.label}
              </button>
            );
          })}
        </div>
        <button type="button" className="btn btn-secondary h-8" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          刷新
        </button>
      </div>

      {loading ? (
        <div className="card flex flex-col gap-3 p-5">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-14 w-full" />
        </div>
      ) : error ? (
        <Empty title="轨迹加载失败" description={error} action={<button type="button" className="btn btn-secondary h-8" onClick={() => void load()}>重试</button>} />
      ) : items.length === 0 ? (
        <Empty title="暂无操作轨迹" description="登录、漏洞处置、主机作业与工具调用都会记录在这里。" />
      ) : (
        <section className="card overflow-hidden">
          <div className="border-b border-line px-5 py-3">
            <p className="text-[13px] font-semibold text-ink">操作轨迹</p>
            <p className="mt-0.5 text-[11px] text-ink3">{items.length} 条记录 · 按时间倒序</p>
          </div>
          <ol className="divide-y divide-line">
            {items.map((item) => (
              <li key={item.id} className="flex gap-3 px-5 py-3.5">
                <span className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-subtle text-ink2">
                  <KindIcon kind={item.kind} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11.5px] text-ink">{item.action}</span>
                    <span className={`pill ${statusTone(item.status)}`}>{item.status}</span>
                    <span className="text-[10.5px] text-ink3">{item.kind}</span>
                  </div>
                  <p className="mt-1 text-[11.5px] text-ink2">
                    {item.actor || "系统"} · {item.target || "—"}
                  </p>
                  {item.detail && <p className="mt-1 break-all text-[11px] leading-[17px] text-ink3">{item.detail}</p>}
                </div>
                <span className="shrink-0 text-[10.5px] text-ink3">{formatTime(item.time)}</span>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}

function KindIcon({ kind }: { kind: string }) {
  if (kind === "job") return <Terminal size={13} />;
  if (kind === "tool") return <Wrench size={13} />;
  return <ShieldAlert size={13} />;
}

function statusTone(status: string): string {
  if (status === "succeeded" || status === "ok") return "bg-[#E8F7EE] text-[#1E7B3C]";
  if (status === "failed" || status === "error") return "bg-[#FFECEA] text-[#C4170E]";
  if (status === "running" || status === "pending") return "bg-[#EAF1FF] text-[#2A5BD7]";
  return "bg-subtle text-ink2";
}
