import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Download, RefreshCw, Search, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { api } from "../lib/api";
import type { Finding } from "../lib/types";
import { Empty, Pagination, PriorityPill, RiskMeter, Skeleton, StatusPill } from "../components/ui";
import { FindingDrawer } from "../components/FindingDrawer";
import { envMeta, priorityMeta } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const PAGE_SIZE = 12;

const priorityOptions = [
  { value: "all", label: "全部" },
  { value: "P0", label: "P0", color: priorityMeta.P0.color },
  { value: "P1", label: "P1", color: priorityMeta.P1.color },
  { value: "P2", label: "P2", color: priorityMeta.P2.color },
  { value: "P3", label: "P3", color: priorityMeta.P3.color }
];

const statusOptions = [
  { value: "", label: "全部状态" },
  { value: "open", label: "待处理" },
  { value: "triaged", label: "已定级" },
  { value: "fixing", label: "修复中" },
  { value: "fixed", label: "已修复" },
  { value: "verified", label: "已验证" }
];

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const { canWrite } = useAuth();
  const toast = useToast();

  const priority = params.get("priority") ?? "all";
  const status = params.get("status") ?? "";
  const queryParam = params.get("q") ?? "";
  const page = Math.max(1, Number(params.get("page") ?? 1));

  const [search, setSearch] = useState(queryParam);
  const [items, setItems] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeId, setActiveId] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState<"" | "pdf" | "csv">("");
  const firstRender = useRef(true);

  const updateParams = useCallback(
    (patch: Record<string, string | number | null>, resetPage = true) => {
      const next = new URLSearchParams(params);
      Object.entries(patch).forEach(([key, value]) => {
        if (value === null || value === "" ) next.delete(key);
        else next.set(key, String(value));
      });
      if (resetPage) next.delete("page");
      setParams(next, { replace: true });
    },
    [params, setParams]
  );

  useEffect(() => {
    if (!firstRender.current) return;
    firstRender.current = false;
    if (queryParam) setSearch(queryParam);
  }, [queryParam]);

  useEffect(() => {
    if (search === queryParam) return;
    const timer = window.setTimeout(() => {
      updateParams({ q: search || null });
    }, 320);
    return () => window.clearTimeout(timer);
  }, [search, queryParam, updateParams]);

  const load = useCallback(
    async (silent = false) => {
      if (silent) setRefreshing(true);
      else setLoading(true);
      try {
        const result = await api.findings({
          priority: priority === "all" ? undefined : priority,
          status: status || undefined,
          q: queryParam || undefined,
          page,
          pageSize: PAGE_SIZE
        });
        setItems(result.items ?? []);
        setTotal(result.total);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "加载失败");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [priority, status, queryParam, page]
  );

  useEffect(() => {
    void load();
  }, [load]);

  const downloadReport = async (kind: "pdf" | "csv") => {
    setExporting(kind);
    try {
      const params = {
        priority: priority === "all" ? undefined : priority,
        status: status || undefined,
        q: queryParam || undefined
      };
      const blob = kind === "pdf" ? await api.reportFindings(params) : await api.reportFindingsCSV(params);
      const url = URL.createObjectURL(blob);
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, "0");
      const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
      const link = document.createElement("a");
      link.href = url;
      link.download = `vulnagent-findings-${stamp}.${kind}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast.push(kind === "pdf" ? "PDF 报告已生成" : "CSV 已导出");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "导出失败", "error");
    } finally {
      setExporting("");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
          <div className="flex flex-wrap items-center gap-1.5">
            {priorityOptions.map((option) => {
              const active = priority === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => updateParams({ priority: option.value === "all" ? null : option.value })}
                  className={`inline-flex h-7 items-center gap-1.5 rounded-full px-2.5 text-[12.5px] font-medium transition-colors ${
                    active ? "bg-ink text-white" : "text-ink2 hover:bg-subtle"
                  }`}
                >
                  {option.color && (
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ backgroundColor: active ? "#FFFFFF" : option.color }}
                    />
                  )}
                  {option.label}
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink3" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="搜索 CVE、资产或组件"
                className="input h-8 w-[220px] pl-8 text-[12.5px]"
              />
            </label>

            <div className="relative">
              <SlidersHorizontal
                size={13}
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink3"
              />
              <select
                value={status}
                onChange={(event) => updateParams({ status: event.target.value || null })}
                className="input h-8 w-[118px] appearance-none pl-7 pr-6 text-[12.5px]"
              >
                {statusOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              className="btn btn-secondary h-8 px-2.5"
              onClick={() => void load(true)}
              disabled={refreshing}
              aria-label="刷新"
            >
              <RefreshCw size={13.5} className={refreshing ? "animate-spin" : ""} />
            </button>
            {canWrite && (
              <>
                <button
                  type="button"
                  className="btn btn-secondary h-8"
                  onClick={() => void downloadReport("csv")}
                  disabled={exporting !== "" || total === 0}
                  title="按当前筛选条件导出 CSV"
                >
                  <Download size={13.5} className={exporting === "csv" ? "animate-pulse" : undefined} />
                  CSV
                </button>
                <button
                  type="button"
                  className="btn btn-secondary h-8"
                  onClick={() => void downloadReport("pdf")}
                  disabled={exporting !== "" || total === 0}
                  title="按当前筛选条件导出 PDF 报告"
                >
                  <Download size={13.5} className={exporting === "pdf" ? "animate-pulse" : undefined} />
                  {exporting === "pdf" ? "生成中" : "PDF 报告"}
                </button>
              </>
            )}
          </div>
        </div>

        <div className="divider" />

        {loading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2, 3, 4, 5].map((key) => (
              <Skeleton key={key} className="h-12 w-full" />
            ))}
          </div>
        ) : error ? (
          <Empty title="加载失败" description={error} action={
            <button type="button" className="btn btn-secondary" onClick={() => void load()}>
              重试
            </button>
          } />
        ) : items.length === 0 ? (
          <Empty
            title="没有匹配的漏洞"
            description="调整优先级或清空搜索条件后重试。"
            action={
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setSearch("");
                  setParams(new URLSearchParams(), { replace: true });
                }}
              >
                清空筛选
              </button>
            }
          />
        ) : (
          <>
            <div className="sm:hidden">
              {items.map((finding) => (
                <button
                  key={finding.id}
                  type="button"
                  onClick={() => setActiveId(finding.id)}
                  className="block w-full border-b border-line/70 px-5 py-3.5 text-left transition-colors last:border-0 active:bg-subtle"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <PriorityPill priority={finding.priority} />
                        <span className="truncate font-mono text-[11px] text-ink3">{finding.cveId}</span>
                      </div>
                      <p className="mt-1.5 line-clamp-2 text-[13px] font-medium leading-[19px] text-ink">
                        {finding.title}
                      </p>
                      <p className="mt-1 truncate text-[11.5px] text-ink3">
                        {finding.asset.hostname} · {finding.component.name} {finding.component.version}
                      </p>
                      <div className="mt-1.5 flex items-center gap-2">
                        <StatusPill status={finding.status} />
                        <span className="text-[11px] text-ink3">CVSS {finding.cvss.toFixed(1)}</span>
                        {finding.assignee && <span className="text-[11px] text-ink3">{finding.assignee}</span>}
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <p
                        className="text-[20px] font-semibold leading-6 tabular-nums"
                        style={{ color: priorityMeta[finding.priority].color }}
                      >
                        {finding.risk}
                      </p>
                      <p className="text-[10px] text-ink3">风险分</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>

            <div className="hidden overflow-x-auto sm:block">
            <table className="w-full min-w-[820px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th w-[84px] pl-5">优先级</th>
                  <th className="th">漏洞</th>
                  <th className="th w-[130px]">资产</th>
                  <th className="th w-[168px]">组件</th>
                  <th className="th hidden w-[64px] text-right 2xl:table-cell">CVSS</th>
                  <th className="th hidden w-[64px] text-right 2xl:table-cell">EPSS</th>
                  <th className="th w-[108px]">风险分</th>
                  <th className="th w-[96px]">状态</th>
                  <th className="th w-[84px] pr-5">责任人</th>
                </tr>
              </thead>
              <tbody>
                {items.map((finding) => (
                  <tr
                    key={finding.id}
                    className="row-hover border-b border-line/70 last:border-0"
                    onClick={() => setActiveId(finding.id)}
                  >
                    <td className="td pl-5">
                      <PriorityPill priority={finding.priority} />
                    </td>
                    <td className="td max-w-[330px]">
                      <span className="block font-mono text-[11.5px] text-ink3">{finding.cveId}</span>
                      <span className="mt-0.5 block truncate text-[12.5px] font-medium text-ink">
                        {finding.title}
                      </span>
                    </td>
                    <td className="td">
                      <span className="block whitespace-nowrap text-[12.5px] font-medium text-ink">
                        {finding.asset.hostname}
                      </span>
                      <span className="mt-0.5 flex items-center gap-1 whitespace-nowrap text-[11px] text-ink3">
                        {envMeta[finding.asset.env] ?? finding.asset.env}
                        <span className="h-2.5 w-px bg-line" />
                        {finding.asset.exposure === "public" ? "公网" : finding.asset.exposure === "internal" ? "内网" : "隔离"}
                      </span>
                    </td>
                    <td className="td">
                      <span className="block max-w-[180px] truncate text-[12.5px] text-ink">
                        {finding.component.name}
                      </span>
                      <span className="mt-0.5 block font-mono text-[11px] text-ink3">
                        {finding.component.version}
                        {finding.component.fixedVersion ? ` → ${finding.component.fixedVersion}` : ""}
                      </span>
                    </td>
                    <td className="td hidden text-right tabular-nums 2xl:table-cell">{finding.cvss.toFixed(1)}</td>
                    <td className="td hidden text-right tabular-nums text-ink2 2xl:table-cell">
                      {finding.epss ? finding.epss.toFixed(2) : "—"}
                    </td>
                    <td className="td">
                      <RiskMeter value={finding.risk} width={44} />
                    </td>
                    <td className="td">
                      <StatusPill status={finding.status} />
                    </td>
                    <td className="td pr-5 text-[12.5px] text-ink2">
                      {finding.assignee || <span className="text-ink3">未指派</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </>
        )}

        {!loading && !error && items.length > 0 && (
          <>
            <div className="divider" />
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              total={total}
              onChange={(next) => updateParams({ page: next }, false)}
            />
          </>
        )}
      </div>

      <p className="flex items-center gap-1.5 px-1 text-[11px] text-ink3">
        <ShieldAlert size={12} />
        风险分 = 100 ×（0.40·CVSS + 0.20·EPSS + 0.25·在野利用 + 0.15·资产权重），阈值可在「审计与设置」中调整
      </p>

      {activeId !== null && (
        <FindingDrawer
          findingId={activeId}
          onClose={() => setActiveId(null)}
          onChanged={() => void load(true)}
        />
      )}
    </div>
  );
}
