import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Archive, ClipboardCheck, Loader2, RefreshCw, UserPlus } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { GovernanceItem, GovernanceSummary } from "../lib/types";
import { Empty, Pagination, Skeleton } from "../components/ui";
import { formatTime, timeAgo } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const PAGE_SIZE = 12;

type TodoType = GovernanceItem["type"];

const typeMeta: Record<TodoType, { label: string; hint: string; valueKey: keyof GovernanceSummary }> = {
  owner_missing: { label: "责任人缺失", hint: "补全责任人后可分配扫描与修复", valueKey: "ownerMissing" },
  stale: { label: "长期未上报", hint: "Agent 超过 7 天未上报，可归档或排查", valueKey: "stale" },
  duplicate: { label: "疑似重复", hint: "IP / MAC / 序列号相同的账号，需人工合并", valueKey: "duplicate" },
  exposure_changed: { label: "暴露面变化", hint: "最近 30 天暴露面字段发生变更", valueKey: "exposureChanged" }
};

const typeOrder: TodoType[] = ["owner_missing", "stale", "duplicate", "exposure_changed"];

export function GovernancePage() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const [summary, setSummary] = useState<GovernanceSummary | null>(null);
  const [type, setType] = useState<TodoType>("owner_missing");
  const [items, setItems] = useState<GovernanceItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<number[]>([]);
  const [ownerInput, setOwnerInput] = useState("");
  const [busy, setBusy] = useState<"" | "owner" | "archive">("");

  const loadSummary = useCallback(async () => {
    try {
      const result = await api.governanceSummary();
      setSummary(result.summary);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载治理汇总失败");
    }
  }, []);

  const loadItems = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.governanceTodos({ type, page, pageSize: PAGE_SIZE });
      setItems(result.items ?? []);
      setTotal(result.total);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载治理待办失败");
    } finally {
      setLoading(false);
    }
  }, [type, page]);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    setSelected([]);
    void loadItems();
  }, [loadItems]);

  const refresh = async () => {
    await Promise.all([loadSummary(), loadItems()]);
  };

  const selectable = type === "owner_missing" || type === "stale";
  const pageIds = items.map((item) => item.assetId);

  const applyBatch = async (patch: { owner?: string; status?: string }, mode: "owner" | "archive") => {
    if (selected.length === 0) {
      toast.push("请先选择资产", "error");
      return;
    }
    if (mode === "owner" && !patch.owner?.trim()) {
      toast.push("请输入责任人", "error");
      return;
    }
    setBusy(mode);
    try {
      const result = await api.batchUpdateAssets(selected, patch);
      const failed = result.failed.length > 0 ? `，失败 ${result.failed.length}` : "";
      toast.push(
        mode === "owner"
          ? `已为 ${result.updated} 台资产分配责任人${failed}`
          : `已归档 ${result.updated} 台资产${failed}`,
        result.failed.length > 0 ? "error" : "success"
      );
      setSelected([]);
      setOwnerInput("");
      await refresh();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "批量操作失败", "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {typeOrder.map((key) => {
          const meta = typeMeta[key];
          const active = type === key;
          return (
            <button
              key={key}
              type="button"
              onClick={() => {
                setType(key);
                setPage(1);
              }}
              className={`card px-4 py-3.5 text-left transition-colors ${active ? "border-brand bg-brand-soft/40" : "hover:bg-subtle/60"}`}
            >
              <span className="flex items-center justify-between text-[11.5px] text-ink3">
                {meta.label}
                <ClipboardCheck size={13} className={active ? "text-brand-strong" : "text-ink3"} />
              </span>
              <span className="mt-1 block text-[24px] font-semibold tabular-nums text-ink">
                {summary ? summary[meta.valueKey] : "—"}
              </span>
              <span className="mt-0.5 block text-[10.5px] leading-[15px] text-ink3">{meta.hint}</span>
            </button>
          );
        })}
      </div>

      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3.5">
          <div>
            <h3 className="text-[13.5px] font-semibold text-ink">{typeMeta[type].label}</h3>
            <p className="mt-0.5 text-[11px] text-ink3">共 {total} 条 · {typeMeta[type].hint}</p>
          </div>
          <button type="button" className="btn btn-secondary h-8" onClick={() => void refresh()}>
            <RefreshCw size={13} />
            刷新
          </button>
        </div>

        {selected.length > 0 && canWrite && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line bg-subtle/50 px-5 py-2.5">
            <span className="text-[11.5px] text-ink2">已选 {selected.length} 台</span>
            {type === "owner_missing" && (
              <>
                <input
                  className="input h-7 w-[140px] text-[11.5px]"
                  value={ownerInput}
                  onChange={(event) => setOwnerInput(event.target.value)}
                  placeholder="责任人姓名"
                />
                <button
                  type="button"
                  className="btn btn-primary h-7 text-[11px]"
                  onClick={() => void applyBatch({ owner: ownerInput }, "owner")}
                  disabled={busy !== ""}
                >
                  {busy === "owner" ? <Loader2 size={12} className="animate-spin" /> : <UserPlus size={12} />}
                  分配责任人
                </button>
              </>
            )}
            {type === "stale" && (
              <button
                type="button"
                className="btn btn-secondary h-7 text-[11px]"
                onClick={() => void applyBatch({ status: "retired" }, "archive")}
                disabled={busy !== ""}
              >
                {busy === "archive" ? <Loader2 size={12} className="animate-spin" /> : <Archive size={12} />}
                归档资产
              </button>
            )}
            <button type="button" className="btn btn-ghost h-7 text-[11px]" onClick={() => setSelected([])}>
              清除选择
            </button>
          </div>
        )}

        <div className="divider" />

        {loading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-11 w-full" />)}
          </div>
        ) : error ? (
          <Empty title="加载失败" description={error} action={
            <button type="button" className="btn btn-secondary h-8" onClick={() => void loadItems()}>重试</button>
          } />
        ) : items.length === 0 ? (
          <Empty title="没有待办" description="当前类型下没有需要治理的资产。" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  {selectable && (
                    <th className="th w-[44px] pl-5">
                      <input
                        type="checkbox"
                        aria-label="全选当前页"
                        checked={pageIds.length > 0 && pageIds.every((id) => selected.includes(id))}
                        onChange={(event) => setSelected(event.target.checked ? pageIds : [])}
                      />
                    </th>
                  )}
                  <th className={`th ${selectable ? "" : "pl-5"}`}>资产</th>
                  <th className="th w-[150px]">业务系统</th>
                  <th className="th w-[110px]">责任人</th>
                  <th className="th">待办详情</th>
                  <th className="th w-[130px]">时间</th>
                  <th className="th w-[90px] pr-5 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={`${item.type}-${item.assetId}-${item.updatedAt ?? ""}`} className="border-b border-line/70 last:border-0">
                    {selectable && (
                      <td className="td pl-5">
                        <input
                          type="checkbox"
                          aria-label={`选择 ${item.hostname}`}
                          checked={selected.includes(item.assetId)}
                          onChange={() =>
                            setSelected((prev) =>
                              prev.includes(item.assetId)
                                ? prev.filter((id) => id !== item.assetId)
                                : [...prev, item.assetId]
                            )
                          }
                        />
                      </td>
                    )}
                    <td className={`td ${selectable ? "" : "pl-5"}`}>
                      <Link to={`/assets/${item.assetId}`} className="block text-[12.5px] font-medium text-ink hover:underline">
                        {item.hostname}
                      </Link>
                      <span className="mt-0.5 block font-mono text-[10.5px] text-ink3">{item.ip || "—"}</span>
                    </td>
                    <td className="td text-[12px] text-ink2">{item.businessSystem || <span className="text-ink3">未归属</span>}</td>
                    <td className="td text-[12px] text-ink2">{item.owner || <span className="text-[#C4170E]">缺失</span>}</td>
                    <td className="td">
                      <span className="block text-[11.5px] text-ink2">{item.detail}</span>
                      {item.related && item.related.length > 0 && (
                        <span className="mt-1 flex flex-wrap gap-1">
                          {item.related.map((peer) => (
                            <Link key={peer.id} to={`/assets/${peer.id}`} className="pill bg-subtle text-[10px] text-ink2 hover:text-brand-strong">
                              #{peer.id} {peer.hostname}
                            </Link>
                          ))}
                        </span>
                      )}
                    </td>
                    <td className="td text-[11px] text-ink3">
                      {item.updatedAt ? formatTime(item.updatedAt) : item.lastSeen ? timeAgo(item.lastSeen) : "从未上报"}
                    </td>
                    <td className="td pr-5 text-right">
                      <Link to={`/assets/${item.assetId}`} className="btn btn-ghost h-7 px-2 text-[11px]">
                        查看
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {total > PAGE_SIZE && (
          <>
            <div className="divider" />
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onChange={setPage} />
          </>
        )}

        {!canWrite && (
          <p className="border-t border-line px-5 py-2 text-[10.5px] text-ink3">
            当前角色只读，批量分配与归档需要 operator 及以上权限。
          </p>
        )}
      </section>

      <p className="px-1 text-[11px] text-ink3">
        失联判定为 Agent 资产超过 7 天未上报；暴露面变化按最近 30 天的档案变更统计。疑似重复仅提示，不会自动合并。
      </p>
    </div>
  );
}
