import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Network, RefreshCw, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { BusinessSystem, Topology, TopologyAsset } from "../lib/types";
import { Empty, Skeleton } from "../components/ui";
import { envMeta, formatTime } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const relationColors: Record<string, string> = {
  depends_on: "#2A5BD7",
  runs_on: "#0E9F8A",
  member_of: "#9A5B00",
  manages: "#7C3AED",
  connects_to: "#8E8E93"
};

const relationLabels: Record<string, string> = {
  depends_on: "依赖",
  runs_on: "运行于",
  member_of: "成员",
  manages: "管理",
  connects_to: "连接"
};

const tierLabels: Record<string, string> = { core: "核心", important: "重要", normal: "一般" };

const NODE_WIDTH = 250;
const NODE_HEIGHT = 40;
const NODE_GAP = 12;
const ASSET_X = 360;
const GRAPH_WIDTH = 780;

interface BusinessGroup {
  name: string;
  tier: string;
  top: number;
  height: number;
  center: number;
  assets: TopologyAsset[];
}

export function TopologyPage() {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const toast = useToast();
  const [data, setData] = useState<Topology | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [businessFilter, setBusinessFilter] = useState("");
  const [envFilter, setEnvFilter] = useState("");
  const [updating, setUpdating] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.topology({
        businessSystem: businessFilter || undefined,
        env: envFilter || undefined
      });
      setData(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载拓扑失败");
    } finally {
      setLoading(false);
    }
  }, [businessFilter, envFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const groups = useMemo<BusinessGroup[]>(() => {
    if (!data) return [];
    const map = new Map<string, TopologyAsset[]>();
    data.assets.forEach((asset) => {
      const key = asset.businessSystem || "未归属业务系统";
      const list = map.get(key) ?? [];
      list.push(asset);
      map.set(key, list);
    });
    const tierOf = new Map<string, string>();
    data.businessSystems.forEach((item) => tierOf.set(item.name, item.tier));

    let cursor = 24;
    const out: BusinessGroup[] = [];
    Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0], "zh-CN"))
      .forEach(([name, list]) => {
        list.sort((a, b) => b.risk - a.risk || a.id - b.id);
        const height = list.length * NODE_HEIGHT + Math.max(0, list.length - 1) * NODE_GAP;
        out.push({
          name,
          tier: tierOf.get(name) ?? "normal",
          top: cursor,
          height,
          center: cursor + height / 2,
          assets: list
        });
        cursor += Math.max(height, 44) + 48;
      });
    return out;
  }, [data]);

  const positionOf = useMemo(() => {
    const positions = new Map<number, { x: number; y: number; center: number }>();
    groups.forEach((group) => {
      group.assets.forEach((asset, index) => {
        const y = group.top + index * (NODE_HEIGHT + NODE_GAP);
        positions.set(asset.id, { x: ASSET_X, y, center: y + NODE_HEIGHT / 2 });
      });
    });
    return positions;
  }, [groups]);

  const graphHeight = Math.max(320, groups.length > 0 ? groups[groups.length - 1].top + groups[groups.length - 1].height + 40 : 320);

  const changeTier = async (system: BusinessSystem, tier: string) => {
    setUpdating(system.name);
    try {
      const result = await api.updateBusinessSystem(system.name, { tier });
      toast.push(`「${system.name}」已设为${tierLabels[tier] ?? tier}业务，重算 ${result.recomputed} 条漏洞`, "success");
      await load();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "更新业务系统失败", "error");
    } finally {
      setUpdating("");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <Network size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">资产拓扑</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">
                按业务系统分组展示资产与显式关系，当前 {data?.assets.length ?? 0} 个节点
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="input h-8 w-[150px] text-[12px]"
              value={businessFilter}
              onChange={(event) => setBusinessFilter(event.target.value)}
              aria-label="按业务系统过滤"
            >
              <option value="">全部业务系统</option>
              {(data?.businessSystems ?? []).map((item) => (
                <option key={item.name} value={item.name}>{item.name}</option>
              ))}
            </select>
            <select
              className="input h-8 w-[100px] text-[12px]"
              value={envFilter}
              onChange={(event) => setEnvFilter(event.target.value)}
              aria-label="按环境过滤"
            >
              <option value="">全部环境</option>
              <option value="prod">生产</option>
              <option value="staging">预发</option>
              <option value="dev">开发</option>
            </select>
            <button type="button" className="btn btn-secondary h-8 px-2.5" onClick={() => void load()} aria-label="刷新">
              <RefreshCw size={13} />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t border-line px-5 py-2 text-[10.5px] text-ink3">
          <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#2A5BD7]" />依赖</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#0E9F8A]" />运行于</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#9A5B00]" />成员</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#7C3AED]" />管理</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#8E8E93]" />连接</span>
          <span className="ml-auto">点击资产进入详情；点击业务系统可筛选</span>
        </div>

        {loading ? (
          <div className="p-5"><Skeleton className="h-[320px] w-full" /></div>
        ) : error ? (
          <Empty title="拓扑加载失败" description={error} action={
            <button type="button" className="btn btn-secondary h-8" onClick={() => void load()}>重试</button>
          } />
        ) : groups.length === 0 ? (
          <Empty title="暂无可展示的资产" description="先通过 Agent、SSH 或网段发现纳管资产，并在档案中填写业务系统。" />
        ) : (
          <div className="overflow-auto border-t border-line bg-subtle/30 p-2" style={{ maxHeight: 560 }}>
            <svg width={GRAPH_WIDTH} height={graphHeight} role="img" aria-label="资产拓扑图">
              {groups.map((group) =>
                group.assets.map((asset) => {
                  const pos = positionOf.get(asset.id);
                  if (!pos) return null;
                  return (
                    <path
                      key={`belong-${group.name}-${asset.id}`}
                      d={`M240 ${group.center} C 300 ${group.center}, 300 ${pos.center}, ${ASSET_X} ${pos.center}`}
                      fill="none"
                      stroke="#D6DCE6"
                      strokeWidth={1}
                    />
                  );
                })
              )}

              {(data?.relations ?? []).map((edge) => {
                const from = positionOf.get(edge.fromAssetId);
                const to = positionOf.get(edge.toAssetId);
                if (!from || !to) return null;
                const x = ASSET_X + NODE_WIDTH;
                return (
                  <path
                    key={`rel-${edge.id}`}
                    d={`M${x} ${from.center} C 700 ${from.center}, 700 ${to.center}, ${x} ${to.center}`}
                    fill="none"
                    stroke={relationColors[edge.relation] ?? "#8E8E93"}
                    strokeWidth={1.4}
                    strokeDasharray={edge.relation === "member_of" ? "4 3" : undefined}
                  >
                    <title>{relationLabels[edge.relation] ?? edge.relation}</title>
                  </path>
                );
              })}

              {groups.map((group) => (
                <g key={`biz-${group.name}`} className="cursor-pointer" onClick={() => setBusinessFilter(group.name)}>
                  <rect
                    x={40}
                    y={group.center - 22}
                    width={200}
                    height={44}
                    rx={10}
                    fill={group.tier === "core" ? "#EAF1FF" : group.tier === "important" ? "#FFF3E0" : "#F4F5F7"}
                    stroke={group.tier === "core" ? "#BBD0FF" : group.tier === "important" ? "#F2D6A8" : "#E3E6EB"}
                  />
                  <text x={52} y={group.center - 4} fontSize={12} fontWeight={600} fill="#1D1D1F">
                    {group.name.length > 12 ? `${group.name.slice(0, 12)}…` : group.name}
                  </text>
                  <text x={52} y={group.center + 12} fontSize={10} fill="#8E8E93">
                    {tierLabels[group.tier] ?? "一般"}业务 · {group.assets.length} 台
                  </text>
                </g>
              ))}

              {groups.map((group) =>
                group.assets.map((asset) => {
                  const pos = positionOf.get(asset.id);
                  if (!pos) return null;
                  return (
                    <g
                      key={`asset-${asset.id}`}
                      className="cursor-pointer"
                      onClick={() => navigate(`/assets/${asset.id}`)}
                    >
                      <rect
                        x={ASSET_X}
                        y={pos.y}
                        width={NODE_WIDTH}
                        height={NODE_HEIGHT}
                        rx={8}
                        fill="#FFFFFF"
                        stroke={asset.risk >= 85 ? "#F3B4AE" : asset.risk >= 70 ? "#F2D6A8" : "#E3E6EB"}
                      />
                      <circle cx={ASSET_X + 14} cy={pos.center} r={4} fill={asset.env === "prod" ? "#2A5BD7" : "#C7CDD6"} />
                      <text x={ASSET_X + 26} y={pos.center + 4} fontSize={11.5} fill="#1D1D1F">
                        {asset.hostname.length > 20 ? `${asset.hostname.slice(0, 20)}…` : asset.hostname}
                      </text>
                      <text x={ASSET_X + NODE_WIDTH - 10} y={pos.center + 4} fontSize={10.5} textAnchor="end" fill={asset.risk >= 70 ? "#C4170E" : "#8E8E93"}>
                        {asset.risk}
                      </text>
                      <title>
                        {asset.hostname} · {asset.ip} · {envMeta[asset.env] ?? asset.env} · 风险 {asset.risk}
                      </title>
                    </g>
                  );
                })
              )}
            </svg>
          </div>
        )}
        {data?.truncated && (
          <p className="border-t border-line px-5 py-2 text-[10.5px] text-[#9A5B00]">
            仅展示前 {data.assets.length} 个节点（共 {data.total} 个），请使用业务系统或环境筛选缩小范围。
          </p>
        )}
      </section>

      {isAdmin && data && (
        <section className="card">
          <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3.5">
            <div>
              <h3 className="flex items-center gap-1.5 text-[13.5px] font-semibold text-ink">
                <ShieldCheck size={14} />
                业务系统重要性
              </h3>
              <p className="mt-0.5 text-[11px] text-ink3">
                重要性参与资产权重（核心 1.0 / 重要 0.9 / 一般 0.8），保存后即时重算全部漏洞风险分
              </p>
            </div>
          </div>
          <div className="divider" />
          {data.businessSystems.length === 0 ? (
            <Empty title="暂无业务系统" description="在资产档案中填写业务系统后会自动出现在这里。" />
          ) : (
            <div className="divide-y divide-line">
              {data.businessSystems.map((system) => (
                <div key={system.name} className="flex flex-wrap items-center justify-between gap-2 px-5 py-2.5">
                  <div className="min-w-0">
                    <span className="block truncate text-[12.5px] font-medium text-ink">{system.name}</span>
                    <span className="mt-0.5 block text-[10.5px] text-ink3">
                      {system.assetCount} 台资产{system.updatedAt ? ` · 更新于 ${formatTime(system.updatedAt)}` : ""}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {updating === system.name && <Loader2 size={12} className="animate-spin text-ink3" />}
                    <select
                      className="input h-8 w-[96px] text-[12px]"
                      value={system.tier}
                      disabled={updating === system.name}
                      onChange={(event) => void changeTier(system, event.target.value)}
                      aria-label={`${system.name} 重要性`}
                    >
                      <option value="core">核心</option>
                      <option value="important">重要</option>
                      <option value="normal">一般</option>
                    </select>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {!isAdmin && data && data.businessSystems.length > 0 && (
        <p className="px-1 text-[11px] text-ink3">
          业务系统重要性由管理员在拓扑页维护，当前按
          {" "}
          {data.businessSystems.map((item) => `${item.name}（${tierLabels[item.tier] ?? "一般"}）`).join("、")}
          {" "}
          参与风险分计算。
        </p>
      )}
    </div>
  );
}
