import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeftRight, ChevronLeft, Copy, Cpu, ShieldAlert, User } from "lucide-react";
import { api } from "../lib/api";
import type { AssetDetail } from "../lib/types";
import {
  Badge,
  Dot,
  Empty,
  PriorityPill,
  RiskMeter,
  Skeleton,
  StatusPill
} from "../components/ui";
import { FindingDrawer } from "../components/FindingDrawer";
import {
  agentMeta,
  envMeta,
  exposureMeta,
  formatTime,
  sourceMeta,
  timeAgo
} from "../lib/format";
import { useToast } from "../lib/toast";

type Tab = "components" | "findings";

export function AssetDetailPage() {
  const { id } = useParams();
  const toast = useToast();
  const [data, setData] = useState<AssetDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("components");
  const [activeFinding, setActiveFinding] = useState<number | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const result = await api.asset(id);
      setData(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-4 w-24" />
        <div className="card p-5">
          <Skeleton className="h-6 w-56" />
          <Skeleton className="mt-4 h-16 w-full" />
        </div>
        <div className="card p-5">
          <Skeleton className="h-5 w-32" />
          <Skeleton className="mt-4 h-40 w-full" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card flex flex-col items-center gap-3 p-10 text-center">
        <ShieldAlert size={22} className="text-ink3" />
        <p className="text-[13.5px] font-medium text-ink">资产加载失败</p>
        <p className="text-[12.5px] text-ink3">{error}</p>
        <Link to="/assets" className="btn btn-secondary mt-1">
          返回资产列表
        </Link>
      </div>
    );
  }

  const { asset, components, findings } = data;
  const agent = agentMeta[asset.agentStatus] ?? agentMeta.none;

  return (
    <div className="flex flex-col gap-4">
      <Link
        to="/assets"
        className="inline-flex w-fit items-center gap-1 text-[12px] text-ink2 transition-colors hover:text-ink"
      >
        <ChevronLeft size={14} />
        资产列表
      </Link>

      <section className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-[20px] font-semibold tracking-[-0.02em] text-ink">{asset.hostname}</h2>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText(asset.ip);
                  toast.push("IP 已复制", "info");
                }}
                className="inline-flex items-center gap-1 font-mono text-[11.5px] text-ink3 transition-colors hover:text-ink"
              >
                {asset.ip}
                <Copy size={11} />
              </button>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <Badge tone={asset.env === "prod" ? "brand" : "neutral"}>{envMeta[asset.env] ?? asset.env}</Badge>
              <Badge>{exposureMeta[asset.exposure] ?? asset.exposure}</Badge>
              <Badge>{asset.tier === "core" ? "核心业务" : asset.tier === "important" ? "重要业务" : "一般业务"}</Badge>
              <Badge>{sourceMeta[asset.source] ?? asset.source}</Badge>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-subtle px-2 py-1 text-[11px] text-ink2">
                <Dot color={agent.color} />
                Agent {agent.label}
              </span>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-3 text-[11.5px] text-ink3">
              <span className="inline-flex items-center gap-1">
                <Cpu size={12} />
                {asset.os} {asset.osVersion}
              </span>
              <span className="inline-flex items-center gap-1">
                <User size={12} />
                {asset.owner || "未设置责任人"}
              </span>
              <span>最近上报 {timeAgo(asset.lastSeen)}</span>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-5 rounded-panel bg-subtle px-5 py-3.5">
            <Stat label="组件" value={asset.components} />
            <Stat label="漏洞" value={asset.findings} />
            <Stat label="P0" value={asset.p0} tone={asset.p0 > 0 ? "#C4170E" : undefined} />
            <div className="col-span-3 border-t border-line pt-2.5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-[11px] text-ink3">最高风险</span>
                <RiskMeter value={asset.risk} width={72} />
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="card overflow-hidden">
        <div className="flex items-center gap-1 border-b border-line px-4 py-2.5">
          <TabButton active={tab === "components"} onClick={() => setTab("components")}>
            组件清单 <span className="text-[11px] text-ink3">{components.length}</span>
          </TabButton>
          <TabButton active={tab === "findings"} onClick={() => setTab("findings")}>
            关联漏洞 <span className="text-[11px] text-ink3">{findings.length}</span>
          </TabButton>
        </div>

        {tab === "components" ? (
          components.length === 0 ? (
            <Empty title="暂无组件数据" description="等待下一次采集上报。" />
          ) : (
            <>
              <div className="flex items-center gap-1.5 border-b border-line px-5 py-2 text-[11px] text-ink3 sm:hidden">
                <ArrowLeftRight size={12} />
                表格可左右滑动查看完整信息
              </div>
              <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] border-collapse">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th pl-5">组件</th>
                    <th className="th w-[180px]">版本</th>
                    <th className="th w-[110px]">生态</th>
                    <th className="th w-[220px]">CPE 映射</th>
                    <th className="th w-[100px] pr-5 text-right">关联漏洞</th>
                  </tr>
                </thead>
                <tbody>
                  {components.map((component) => (
                    <tr key={component.purl} className="border-b border-line/70 last:border-0 hover:bg-subtle/60">
                      <td className="td pl-5">
                        <span className="block text-[12.5px] font-medium text-ink">{component.name}</span>
                        <span className="mt-0.5 block max-w-[260px] truncate font-mono text-[10.5px] text-ink3">
                          {component.purl}
                        </span>
                      </td>
                      <td className="td font-mono text-[11.5px] text-ink2">{component.version}</td>
                      <td className="td">
                        <span className="pill bg-subtle text-ink2">{component.ecosystem}</span>
                      </td>
                      <td className="td text-[11.5px] text-ink2">
                        {component.vendor || component.product ? (
                          <span className="font-mono">
                            {component.vendor || "*"}:{component.product || "*"}
                          </span>
                        ) : (
                          <span className="text-ink3">未映射</span>
                        )}
                        {component.inferred && (
                          <span className="ml-1.5 pill bg-[#FFF3E0] text-[#9A5B00]">推断</span>
                        )}
                      </td>
                      <td className="td pr-5 text-right tabular-nums">
                        {component.findings > 0 ? (
                          <span className="font-medium text-[#C4170E]">{component.findings}</span>
                        ) : (
                          <span className="text-ink3">0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            </>
          )
        ) : findings.length === 0 ? (
          <Empty title="该资产暂无漏洞" description="最近一次匹配未命中 CVE。" />
        ) : (
          <>
            <div className="flex items-center gap-1.5 border-b border-line px-5 py-2 text-[11px] text-ink3 sm:hidden">
              <ArrowLeftRight size={12} />
              表格可左右滑动查看完整信息
            </div>
            <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th w-[92px] pl-5">优先级</th>
                  <th className="th">漏洞</th>
                  <th className="th w-[170px]">组件</th>
                  <th className="th hidden w-[80px] text-right lg:table-cell">CVSS</th>
                  <th className="th hidden w-[76px] text-right lg:table-cell">EPSS</th>
                  <th className="th w-[132px]">风险分</th>
                  <th className="th w-[112px]">状态</th>
                  <th className="th w-[100px] pr-5">责任人</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="row-hover border-b border-line/70 last:border-0"
                    onClick={() => setActiveFinding(finding.id)}
                  >
                    <td className="td pl-5">
                      <PriorityPill priority={finding.priority} />
                    </td>
                    <td className="td max-w-[320px]">
                      <span className="block font-mono text-[11.5px] text-ink3">{finding.cveId}</span>
                      <span className="mt-0.5 block truncate text-[12.5px] font-medium text-ink">{finding.title}</span>
                    </td>
                    <td className="td">
                      <span className="block truncate text-[12px] text-ink">{finding.component.name}</span>
                      <span className="mt-0.5 block font-mono text-[11px] text-ink3">
                        {finding.component.version}
                      </span>
                    </td>
                    <td className="td hidden text-right tabular-nums lg:table-cell">{finding.cvss.toFixed(1)}</td>
                    <td className="td hidden text-right tabular-nums text-ink2 lg:table-cell">
                      {finding.epss ? finding.epss.toFixed(2) : "—"}
                    </td>
                    <td className="td">
                      <RiskMeter value={finding.risk} />
                    </td>
                    <td className="td">
                      <StatusPill status={finding.status} />
                    </td>
                    <td className="td whitespace-nowrap pr-5 text-[12.5px] text-ink2">
                      {finding.assignee || <span className="text-ink3">未指派</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </>
        )}
      </section>

      <p className="px-1 text-[11px] text-ink3">
        最近一次采集：{formatTime(asset.lastSeen)} · 组件按 PURL 去重，CPE 映射失败会标记为“推断”
      </p>

      {activeFinding !== null && (
        <FindingDrawer
          findingId={activeFinding}
          onClose={() => setActiveFinding(null)}
          onChanged={() => void load()}
        />
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="text-center">
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className="mt-0.5 text-[20px] font-semibold tabular-nums" style={{ color: tone ?? "#1D1D1F" }}>
        {value}
      </p>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-[8px] px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
        active ? "bg-subtle text-ink" : "text-ink2 hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}
