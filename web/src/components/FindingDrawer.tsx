import { useCallback, useEffect, useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  RotateCw,
  Ticket,
  TriangleAlert,
  X
} from "lucide-react";
import { api } from "../lib/api";
import type { FindingDetail } from "../lib/types";
import { PriorityPill, Skeleton, StatusPill } from "./ui";
import { envMeta, formatTime, priorityMeta } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const factorColor: Record<string, string> = {
  cvss: "#FF3B30",
  epss: "#FF9F0A",
  exploit: "#0064D6",
  asset: "#34C759"
};

export function FindingDrawer({
  findingId,
  onClose,
  onChanged
}: {
  findingId: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { canWrite } = useAuth();
  const toast = useToast();
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [pending, setPending] = useState("");
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.finding(findingId);
      setDetail(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    document.body.dataset.drawer = "open";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      delete document.body.dataset.drawer;
    };
  }, [onClose]);

  async function runAction(kind: "ticket" | "rescan" | "fixed") {
    if (!detail || pending) return;
    setPending(kind);
    try {
      if (kind === "ticket") {
        const result = await api.createTicket(detail.id);
        toast.push(
          result.created ? `工单 ${result.ticketId} 已创建` : `工单已存在：${result.ticketId}`,
          result.created ? "success" : "info"
        );
      } else if (kind === "rescan") {
        const result = await api.rescan(detail.id);
        if (result.skipped) {
          toast.push("复扫已跳过：该资产在防抖窗口内已扫描", "info");
        } else {
          const parts = [
            `验证 ${result.verified} 条`,
            result.reopened > 0 ? `重新打开 ${result.reopened} 条` : "",
            result.closed > 0 ? `关闭 ${result.closed} 条` : "",
            result.created > 0 ? `新增 ${result.created} 条` : ""
          ].filter(Boolean);
          if (result.verified + result.reopened + result.closed + result.created === 0) {
            toast.push("复扫完成：组件仍受影响，状态未变化", "info");
          } else {
            toast.push(`复扫完成：${parts.join(" · ")}`);
          }
        }
      } else {
        await api.patchFinding(detail.id, { status: "fixed" });
        toast.push("已标记为已修复，等待复扫确认");
      }
      onChanged();
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "操作失败", "error");
    } finally {
      setPending("");
    }
  }

  async function copyCommand(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      toast.push("复制失败，请手动选择文本", "error");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="关闭详情"
        className="animate-fade absolute inset-0 bg-[#1D1D1F]/18 backdrop-blur-[1px]"
        onClick={onClose}
      />

      <aside className="animate-drawer relative flex h-full w-full max-w-[568px] flex-col border-l border-line bg-surface shadow-drawer">
        <header className="flex items-start justify-between gap-4 border-b border-line px-6 py-5">
          <div className="min-w-0">
            {detail ? (
              <>
                <div className="flex items-center gap-2">
                  <PriorityPill priority={detail.priority} emphasis />
                  <span className="font-mono text-[11.5px] text-ink3">{detail.cveId}</span>
                </div>
                <h2 className="mt-2 text-[16.5px] font-semibold leading-[23px] tracking-[-0.01em] text-ink">
                  {detail.title}
                </h2>
              </>
            ) : (
              <>
                <Skeleton className="h-5 w-24" />
                <Skeleton className="mt-3 h-6 w-72" />
              </>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
            aria-label="关闭"
          >
            <X size={17} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-6 py-5">
          {loading ? (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-32 w-full" />
              <Skeleton className="h-40 w-full" />
            </div>
          ) : error || !detail ? (
            <div className="flex flex-col items-center gap-2 py-16 text-center">
              <TriangleAlert size={20} className="text-ink3" />
              <p className="text-[13px] font-medium text-ink">详情加载失败</p>
              <p className="text-[12px] text-ink3">{error}</p>
              <button type="button" className="btn btn-secondary mt-2" onClick={() => void load()}>
                重试
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-6">
              <section className="grid grid-cols-2 gap-x-4 gap-y-3.5">
                <Meta label="资产">
                  <span className="text-[13px] font-medium text-ink">{detail.asset.hostname}</span>
                  <span className="ml-1.5 text-[11px] text-ink3">
                    {envMeta[detail.asset.env] ?? detail.asset.env} ·{" "}
                    {detail.asset.exposure === "public" ? "公网" : detail.asset.exposure === "internal" ? "内网" : "隔离"}
                  </span>
                </Meta>
                <Meta label="组件">
                  <span className="text-[13px] text-ink">{detail.component.name}</span>
                  <span className="ml-1.5 font-mono text-[11.5px] text-ink3">{detail.component.version}</span>
                </Meta>
                <Meta label="CVSS">
                  <span className="tabular-nums">{detail.cvss.toFixed(1)}</span>
                  <span className="ml-1.5 text-[11px] text-ink3">基础分</span>
                </Meta>
                <Meta label="EPSS">
                  <span className="tabular-nums">{detail.epss ? detail.epss.toFixed(3) : "—"}</span>
                  <span className="ml-1.5 text-[11px] text-ink3">利用概率</span>
                </Meta>
                <Meta label="首次发现">
                  <span>{formatTime(detail.firstSeen)}</span>
                </Meta>
                <Meta label="状态与责任人">
                  <span className="inline-flex items-center gap-2">
                    <StatusPill status={detail.status} />
                    <span className="text-[11.5px] text-ink3">{detail.assignee || "未指派"}</span>
                  </span>
                </Meta>
              </section>

              <section>
                <h3 className="text-[12.5px] font-semibold text-ink">风险构成</h3>
                <p className="mt-0.5 text-[11px] text-ink3">每一分都可追溯到因子与权重</p>
                <div className="mt-3 flex flex-col gap-3">
                  {detail.scoreBreakdown.map((factor) => (
                    <div key={factor.factor}>
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="text-[12.5px] text-ink">
                          {factor.label}
                          <span className="ml-1.5 text-[11px] text-ink3">
                            {typeof factor.value === "number" ? factor.value : String(factor.value)} × {factor.weight}
                          </span>
                        </span>
                        <span className="tabular-nums text-[12.5px] font-semibold text-ink">
                          {factor.weighted.toFixed(1)}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-line">
                        <div
                          className="h-full rounded-full transition-[width] duration-500"
                          style={{
                            width: `${Math.min(100, factor.weighted)}%`,
                            backgroundColor: factorColor[factor.factor]
                          }}
                        />
                      </div>
                      {factor.note && <p className="mt-1 text-[10.5px] text-ink3">{factor.note}</p>}
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex items-center justify-between rounded-[10px] bg-subtle px-3 py-2">
                  <span className="text-[11.5px] text-ink2">综合风险分</span>
                  <span
                    className="text-[15px] font-semibold tabular-nums"
                    style={{ color: priorityMeta[detail.priority].color }}
                  >
                    {detail.risk} / 100
                  </span>
                </div>
              </section>

              <section>
                <h3 className="text-[12.5px] font-semibold text-ink">漏洞描述</h3>
                <p className="mt-2 text-[12.5px] leading-[20px] text-ink2">{detail.description}</p>
                <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                  <span className="pill bg-subtle text-ink2">CWE-{detail.cwe.id}</span>
                  <span className="text-[11px] text-ink3">{detail.cwe.cn}</span>
                  <span className="h-2.5 w-px bg-line" />
                  <span className="text-[11px] text-ink3">披露于 {formatTime(detail.publishedAt)}</span>
                  {detail.inferred && <span className="pill bg-[#FFF3E0] text-[#9A5B00]">映射推断</span>}
                </div>
              </section>

              <section>
                <h3 className="text-[12.5px] font-semibold text-ink">修复建议</h3>
                <div className="mt-2 rounded-panel border border-line bg-subtle/60 p-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11.5px] text-ink2">
                      建议版本
                      <span className="ml-1.5 font-mono text-[12px] text-ink">
                        {detail.advice.fixedVersion || "暂无官方修复版本"}
                      </span>
                    </span>
                    {detail.advice.upgradePath && (
                      <span className="text-[11px] text-ink3">{detail.advice.upgradePath}</span>
                    )}
                  </div>

                  {detail.advice.command && (
                    <div className="mt-2.5 flex items-start gap-2 rounded-[9px] border border-line bg-surface px-2.5 py-2">
                      <code className="flex-1 whitespace-pre-wrap break-all font-mono text-[11.5px] leading-[17px] text-ink">
                        {detail.advice.command}
                      </code>
                      <button
                        type="button"
                        onClick={() => void copyCommand(detail.advice.command)}
                        className="shrink-0 rounded-[6px] p-1 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
                        aria-label="复制命令"
                      >
                        {copied ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
                      </button>
                    </div>
                  )}

                  {detail.advice.note && (
                    <p className="mt-2 text-[11px] leading-[17px] text-ink3">{detail.advice.note}</p>
                  )}
                </div>
              </section>

              {detail.poc.length > 0 && (
                <section>
                  <h3 className="text-[12.5px] font-semibold text-ink">公开 POC</h3>
                  <div className="mt-2 flex flex-col gap-1.5">
                    {detail.poc.map((item) => (
                      <a
                        key={item.link}
                        href={item.link}
                        target="_blank"
                        rel="noreferrer"
                        className="group flex items-center justify-between gap-2 rounded-[9px] border border-line px-2.5 py-2 text-[11.5px] text-ink2 transition-colors hover:bg-subtle"
                      >
                        <span className="truncate font-mono">{item.link}</span>
                        <ExternalLink size={12} className="shrink-0 text-ink3 group-hover:text-ink" />
                      </a>
                    ))}
                  </div>
                </section>
              )}

              {detail.ticket && (
                <section>
                  <h3 className="text-[12.5px] font-semibold text-ink">本地工单</h3>
                  <div className="mt-2 rounded-panel border border-line bg-subtle/60 p-3.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[12.5px] text-ink">{detail.ticket.id}</span>
                      <StatusPill status={detail.ticket.status} />
                    </div>
                    <div className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-2.5">
                      <Meta label="责任人">{detail.ticket.assignee || "未指派"}</Meta>
                      <Meta label="创建人">{detail.ticket.createdBy || "系统"}</Meta>
                      <Meta label="更新时间">{formatTime(detail.ticket.updatedAt)}</Meta>
                      <Meta label="优先级">{detail.ticket.priority}</Meta>
                    </div>
                    {detail.ticket.note && (
                      <p className="mt-2.5 text-[11px] leading-[17px] text-ink3">{detail.ticket.note}</p>
                    )}
                  </div>
                </section>
              )}

              <section>
                <h3 className="text-[12.5px] font-semibold text-ink">处理记录</h3>
                <ol className="mt-2 flex flex-col gap-3 border-l border-line pl-3">
                  {detail.events.length === 0 && (
                    <li className="text-[11.5px] text-ink3">暂无处理记录</li>
                  )}
                  {detail.events.map((event, index) => (
                    <li key={`${event.time}-${index}`} className="relative">
                      <span className="absolute -left-[17px] top-1.5 h-1.5 w-1.5 rounded-full bg-lineStrong" />
                      <p className="text-[12px] text-ink">{event.event}</p>
                      <p className="mt-0.5 text-[10.5px] text-ink3">
                        {event.actor || "系统"} · {formatTime(event.time)}
                        {event.detail ? ` · ${event.detail}` : ""}
                      </p>
                    </li>
                  ))}
                </ol>
              </section>
            </div>
          )}
        </div>

        {detail && (
          <footer className="flex items-center justify-between gap-2 border-t border-line px-6 py-4">
            <span className="text-[11px] text-ink3">
              {canWrite ? "操作会写入审计日志" : "只读账号，无处置权限"}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="btn btn-secondary h-8"
                disabled={!canWrite || pending !== ""}
                onClick={() => void runAction("rescan")}
              >
                <RotateCw size={13} className={pending === "rescan" ? "animate-spin" : ""} />
                触发复扫
              </button>
              <button
                type="button"
                className="btn btn-secondary h-8"
                disabled={!canWrite || pending !== "" || Boolean(detail.ticket)}
                onClick={() => void runAction("ticket")}
              >
                <Ticket size={13} />
                {detail.ticket ? "工单已创建" : "创建工单"}
              </button>
              <button
                type="button"
                className="btn btn-primary h-8"
                disabled={!canWrite || pending !== "" || ["fixed", "verified", "closed"].includes(detail.status)}
                onClick={() => void runAction("fixed")}
              >
                <CheckCircle2 size={13} />
                标记已修复
              </button>
            </div>
          </footer>
        )}
      </aside>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10.5px] uppercase tracking-[0.04em] text-ink3">{label}</p>
      <p className="mt-1 text-[12.5px] text-ink">{children}</p>
    </div>
  );
}
