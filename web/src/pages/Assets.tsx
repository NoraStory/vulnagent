import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { RefreshCw, ScanSearch, Search, Server, Terminal } from "lucide-react";
import { api } from "../lib/api";
import type { AssetItem } from "../lib/types";
import { Badge, Dot, Empty, Pagination, RiskMeter, Skeleton } from "../components/ui";
import { agentMeta, envMeta, exposureMeta, sourceMeta, timeAgo } from "../lib/format";
import { SshScanDialog } from "../components/SshScanDialog";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const PAGE_SIZE = 12;

export function AssetsPage() {
  const navigate = useNavigate();
  const { canWrite } = useAuth();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const queryParam = params.get("q") ?? "";
  const page = Math.max(1, Number(params.get("page") ?? 1));

  const [search, setSearch] = useState(queryParam);
  const [items, setItems] = useState<AssetItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sshOpen, setSshOpen] = useState(false);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    if (search === queryParam) return;
    const timer = window.setTimeout(() => {
      const next = new URLSearchParams(params);
      if (search) next.set("q", search);
      else next.delete("q");
      next.delete("page");
      setParams(next, { replace: true });
    }, 320);
    return () => window.clearTimeout(timer);
  }, [search, queryParam, params, setParams]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.assets({ q: queryParam || undefined, page, pageSize: PAGE_SIZE });
      setItems(result.items ?? []);
      setTotal(result.total);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [queryParam, page]);

  useEffect(() => {
    void load();
  }, [load]);

  const runBatchScan = async () => {
    setScanning(true);
    try {
      const result = await api.scanAssets({ all: true });
      const changed = result.created + result.updated + result.verified + result.closed + result.reopened;
      const skipped = result.skipped > 0 ? ` · 跳过 ${result.skipped} 台（防抖窗口内）` : "";
      toast.push(
        `全量复扫完成：${result.scanned} 台 · 新增 ${result.created} · 更新 ${result.updated} · 验证 ${result.verified} · 关闭 ${result.closed} · 重开 ${result.reopened}${skipped}`,
        changed > 0 ? "success" : "info"
      );
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "批量复扫失败", "error");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
          <div className="flex flex-wrap items-center gap-2 text-[12px] text-ink2">
            <span className="inline-flex items-center gap-2 whitespace-nowrap">
              <Server size={14} className="text-ink3" />
              共 <span className="tabular-nums text-ink">{total}</span> 台资产
            </span>
            <span className="hidden h-3 w-px bg-line sm:block" />
            <span className="hidden text-ink3 sm:inline">Agent 采集为主，SSH 兜底复用同一套归一化管道</span>
          </div>
          <div className="flex items-center gap-2">
            <label className="relative">
              <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink3" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="搜索主机名或 IP"
                className="input h-8 w-[220px] pl-8 text-[12.5px]"
              />
            </label>
            <button type="button" className="btn btn-secondary h-8 px-2.5" onClick={() => void load()} aria-label="刷新">
              <RefreshCw size={13.5} />
            </button>
            {canWrite && (
              <button
                type="button"
                className="btn btn-secondary h-8"
                onClick={() => void runBatchScan()}
                disabled={scanning}
              >
                <ScanSearch size={13} className={scanning ? "animate-spin" : undefined} />
                {scanning ? "复扫中" : "全量复扫"}
              </button>
            )}
            {canWrite && (
              <button type="button" className="btn btn-primary h-8" onClick={() => setSshOpen(true)}>
                <Terminal size={13} />
                SSH 采集
              </button>
            )}
          </div>
        </div>

        <div className="divider" />

        {loading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2, 3, 4].map((key) => (
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
          <Empty title="没有匹配的资产" description="换一个关键词试试。" />
        ) : (
          <>
            <div className="sm:hidden">
              {items.map((asset) => (
                <button
                  key={asset.id}
                  type="button"
                  onClick={() => navigate(`/assets/${asset.id}`)}
                  className="block w-full border-b border-line/70 px-5 py-3.5 text-left transition-colors last:border-0 active:bg-subtle"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium text-ink">{asset.hostname}</p>
                      <p className="mt-0.5 font-mono text-[11px] text-ink3">{asset.ip}</p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                        <Badge tone={asset.env === "prod" ? "brand" : "neutral"}>
                          {envMeta[asset.env] ?? asset.env}
                        </Badge>
                        <span className="text-[11px] text-ink2">{exposureMeta[asset.exposure] ?? asset.exposure}</span>
                        <span className="inline-flex items-center gap-1 text-[11px] text-ink2">
                          <Dot color={(agentMeta[asset.agentStatus] ?? agentMeta.none).color} />
                          {(agentMeta[asset.agentStatus] ?? agentMeta.none).label}
                        </span>
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <p className="text-[11px] text-ink3">
                        {asset.components} 组件 · {asset.findings} 漏洞
                      </p>
                      <div className="mt-1 flex justify-end">
                        <RiskMeter value={asset.risk} width={44} />
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>

            <div className="hidden overflow-x-auto sm:block">
            <table className="w-full min-w-[940px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th pl-5">主机</th>
                  <th className="th w-[160px]">环境 / 暴露面</th>
                  <th className="th w-[170px] hidden lg:table-cell">系统</th>
                  <th className="th w-[120px] hidden xl:table-cell">采集来源</th>
                  <th className="th w-[100px]">Agent</th>
                  <th className="th w-[80px] text-right">组件</th>
                  <th className="th w-[96px] text-right">漏洞</th>
                  <th className="th w-[124px]">最高风险</th>
                  <th className="th w-[110px] pr-5">最近上报</th>
                </tr>
              </thead>
              <tbody>
                {items.map((asset) => (
                  <tr
                    key={asset.id}
                    className="row-hover border-b border-line/70 last:border-0"
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    <td className="td pl-5">
                      <span className="block whitespace-nowrap text-[12.5px] font-medium text-ink">{asset.hostname}</span>
                      <span className="mt-0.5 block font-mono text-[11px] text-ink3">{asset.ip}</span>
                    </td>
                    <td className="td">
                      <span className="flex items-center gap-1.5">
                        <Badge tone={asset.env === "prod" ? "brand" : "neutral"}>
                          {envMeta[asset.env] ?? asset.env}
                        </Badge>
                        <span className="text-[11.5px] text-ink2">{exposureMeta[asset.exposure] ?? asset.exposure}</span>
                      </span>
                    </td>
                    <td className="td hidden text-[12px] text-ink2 lg:table-cell">
                      {asset.os} {asset.osVersion}
                    </td>
                    <td className="td hidden text-[12px] text-ink2 xl:table-cell">{sourceMeta[asset.source] ?? asset.source}</td>
                    <td className="td">
                      <span className="inline-flex items-center gap-1.5 text-[12px] text-ink2">
                        <Dot color={(agentMeta[asset.agentStatus] ?? agentMeta.none).color} />
                        {(agentMeta[asset.agentStatus] ?? agentMeta.none).label}
                      </span>
                    </td>
                    <td className="td text-right tabular-nums text-ink2">{asset.components}</td>
                    <td className="td whitespace-nowrap text-right">
                      <span className="tabular-nums text-ink">{asset.findings}</span>
                      {asset.p0 > 0 && (
                        <span className="ml-1.5 text-[11px] font-medium text-[#C4170E]">· P0 {asset.p0}</span>
                      )}
                    </td>
                    <td className="td">
                      <RiskMeter value={asset.risk} />
                    </td>
                    <td className="td whitespace-nowrap pr-5 text-[11.5px] text-ink3">{timeAgo(asset.lastSeen)}</td>
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
              onChange={(next) => {
                const search2 = new URLSearchParams(params);
                if (next > 1) search2.set("page", String(next));
                else search2.delete("page");
                setParams(search2, { replace: true });
              }}
            />
          </>
        )}
      </div>

      <SshScanDialog
        open={sshOpen}
        onClose={() => setSshOpen(false)}
        onSuccess={(assetId) => navigate(`/assets/${assetId}`)}
      />
    </div>
  );
}
