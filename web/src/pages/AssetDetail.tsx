import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Activity,
  ArrowLeftRight,
  ChevronLeft,
  Copy,
  Cpu,
  HardDrive,
  Network,
  Server,
  ShieldAlert,
  User
} from "lucide-react";
import { api } from "../lib/api";
import type { AssetDetail, AssetTelemetry, HostTelemetry, MetricPoint } from "../lib/types";
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

type Tab = "components" | "findings" | "performance" | "hardware" | "services" | "ports";

export function AssetDetailPage() {
  const { id } = useParams();
  const toast = useToast();
  const [data, setData] = useState<AssetDetail | null>(null);
  const [telemetry, setTelemetry] = useState<AssetTelemetry | null>(null);
  const [telemetryError, setTelemetryError] = useState("");
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

  const loadTelemetry = useCallback(async () => {
    if (!id) return;
    try {
      const result = await api.assetTelemetry(id);
      setTelemetry(result);
      setTelemetryError("");
    } catch (err) {
      setTelemetryError(err instanceof Error ? err.message : "遥测加载失败");
    }
  }, [id]);

  useEffect(() => {
    void load();
    void loadTelemetry();
  }, [load, loadTelemetry]);

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
  const current = telemetry?.telemetry ?? null;
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
        <div className="flex flex-wrap items-center gap-1 border-b border-line px-4 py-2.5">
          <TabButton active={tab === "components"} onClick={() => setTab("components")}>
            组件清单 <span className="text-[11px] text-ink3">{components.length}</span>
          </TabButton>
          <TabButton active={tab === "findings"} onClick={() => setTab("findings")}>
            关联漏洞 <span className="text-[11px] text-ink3">{findings.length}</span>
          </TabButton>
          <TabButton active={tab === "performance"} onClick={() => setTab("performance")}>
            <span className="inline-flex items-center gap-1.5">
              <Activity size={12.5} />
              性能
            </span>
          </TabButton>
          <TabButton active={tab === "hardware"} onClick={() => setTab("hardware")}>
            <span className="inline-flex items-center gap-1.5">
              <HardDrive size={12.5} />
              硬件
            </span>
          </TabButton>
          <TabButton active={tab === "services"} onClick={() => setTab("services")}>
            <span className="inline-flex items-center gap-1.5">
              <Server size={12.5} />
              服务 <span className="text-[11px] text-ink3">{current?.services.length ?? 0}</span>
            </span>
          </TabButton>
          <TabButton active={tab === "ports"} onClick={() => setTab("ports")}>
            <span className="inline-flex items-center gap-1.5">
              <Network size={12.5} />
              端口 <span className="text-[11px] text-ink3">{current?.ports.length ?? 0}</span>
            </span>
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
        ) : tab === "findings" ? (
          findings.length === 0 ? (
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
          )
        ) : (
          <TelemetryPanel
            tab={tab}
            data={telemetry}
            error={telemetryError}
            onReload={() => void loadTelemetry()}
          />
        )}
      </section>

      <p className="px-1 text-[11px] text-ink3">
        最近一次采集：{formatTime(asset.lastSeen)}
        {current ? ` · 遥测采集于 ${formatTime(current.collectedAt)}` : " · 尚未上报主机遥测"}
        {" · "}组件按 PURL 去重，CPE 映射失败会标记为“推断”
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

function TelemetryPanel({
  tab,
  data,
  error,
  onReload
}: {
  tab: Tab;
  data: AssetTelemetry | null;
  error: string;
  onReload: () => void;
}) {
  if (error) {
    return (
      <Empty
        title="主机遥测加载失败"
        description={error}
        action={
          <button type="button" className="btn btn-secondary h-8" onClick={onReload}>
            重试
          </button>
        }
      />
    );
  }
  if (!data?.telemetry) {
    return (
      <Empty
        title="尚未采集主机遥测"
        description="在目标主机运行 vulnagent agent 上报后，这里会展示性能、硬件、服务与监听端口。"
        action={
          <button type="button" className="btn btn-secondary h-8" onClick={onReload}>
            重新读取
          </button>
        }
      />
    );
  }
  const telemetry = data.telemetry;
  switch (tab) {
    case "performance":
      return <PerformanceView data={telemetry} series={data.series} />;
    case "hardware":
      return <HardwareView data={telemetry} />;
    case "services":
      return <ServicesView data={telemetry} />;
    case "ports":
      return <PortsView data={telemetry} />;
    default:
      return null;
  }
}

function PanelHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line px-5 py-3">
      <span className="text-[13px] font-semibold text-ink">{title}</span>
      <span className="text-[11px] text-ink3">{subtitle}</span>
    </div>
  );
}

function PerformanceView({ data, series }: { data: HostTelemetry; series: MetricPoint[] }) {
  const metrics = data.metrics;
  const memPercent = metrics.memTotal ? Math.round((metrics.memUsed / metrics.memTotal) * 100) : 0;
  const loadAvailable = metrics.load1 > 0 || metrics.load5 > 0 || metrics.load15 > 0;
  return (
    <div>
      <PanelHeader title="性能概览" subtitle={`采集于 ${formatTime(data.collectedAt)}`} />
      <div className="grid grid-cols-2 gap-3 p-5 md:grid-cols-3 xl:grid-cols-4">
        <TelemetryStat label="CPU 使用率" value={`${metrics.cpuPercent.toFixed(1)}%`} tone="#2A5BD7" />
        <TelemetryStat
          label="内存使用"
          value={`${formatBytes(metrics.memUsed)} / ${formatBytes(metrics.memTotal)}`}
          hint={`${memPercent}%`}
          tone="#0E9F8A"
        />
        <TelemetryStat
          label="负载（1 / 5 / 15）"
          value={loadAvailable ? `${metrics.load1.toFixed(2)} / ${metrics.load5.toFixed(2)} / ${metrics.load15.toFixed(2)}` : "—"}
        />
        <TelemetryStat
          label="磁盘吞吐"
          value={`读 ${formatBps(metrics.diskReadBps)} · 写 ${formatBps(metrics.diskWriteBps)}`}
        />
        <TelemetryStat
          label="网络吞吐"
          value={`收 ${formatBps(metrics.netRxBps)} · 发 ${formatBps(metrics.netTxBps)}`}
        />
        <TelemetryStat label="进程数" value={String(metrics.processCount)} />
        <TelemetryStat label="运行时长" value={formatUptime(metrics.uptimeSec)} />
        <TelemetryStat
          label="交换分区"
          value={metrics.swapTotal ? `${formatBytes(metrics.swapUsed)} / ${formatBytes(metrics.swapTotal)}` : "未启用"}
        />
      </div>
      <div className="border-t border-line px-5 py-4">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-[12.5px] font-medium text-ink">最近 {series.length} 次采样</span>
          <div className="flex items-center gap-3 text-[11px] text-ink3">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-1.5 w-4 rounded-full" style={{ background: "#2A5BD7" }} /> CPU
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-1.5 w-4 rounded-full" style={{ background: "#0E9F8A" }} /> 内存
            </span>
          </div>
        </div>
        <Sparkline series={series} />
      </div>
    </div>
  );
}

function Sparkline({ series }: { series: MetricPoint[] }) {
  if (series.length < 2) {
    return (
      <div className="flex h-[120px] items-center justify-center rounded-panel bg-subtle text-[11.5px] text-ink3">
        采样点不足，至少需要两次上报才能绘制趋势
      </div>
    );
  }
  const width = 600;
  const height = 120;
  const pad = 8;
  const stepX = (width - pad * 2) / (series.length - 1);
  const point = (index: number, value: number) => {
    const clamped = Math.max(0, Math.min(100, value));
    const x = pad + index * stepX;
    const y = height - pad - (clamped / 100) * (height - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  };
  const cpu = series.map((item, index) => point(index, item.cpuPercent));
  const mem = series.map((item, index) =>
    point(index, item.memTotal ? (item.memUsed / item.memTotal) * 100 : 0)
  );
  const line = (coords: string[]) =>
    coords.map((coord, index) => `${index === 0 ? "M" : "L"}${coord}`).join(" ");
  return (
    <div className="rounded-panel border border-line bg-subtle/40 px-3 py-2">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[120px] w-full" preserveAspectRatio="none">
        {[25, 50, 75].map((value) => (
          <line
            key={value}
            x1={pad}
            x2={width - pad}
            y1={height - pad - (value / 100) * (height - pad * 2)}
            y2={height - pad - (value / 100) * (height - pad * 2)}
            stroke="rgba(16,24,40,0.08)"
            strokeWidth="1"
          />
        ))}
        <path d={line(mem)} fill="none" stroke="#0E9F8A" strokeWidth="2" strokeLinejoin="round" />
        <path d={line(cpu)} fill="none" stroke="#2A5BD7" strokeWidth="2" strokeLinejoin="round" />
      </svg>
      <div className="mt-1 flex justify-between text-[10.5px] text-ink3">
        <span>{formatTime(series[0].ts)}</span>
        <span>{formatTime(series[series.length - 1].ts)}</span>
      </div>
    </div>
  );
}

function HardwareView({ data }: { data: HostTelemetry }) {
  const hw = data.hardware;
  return (
    <div>
      <PanelHeader title="设备详情" subtitle={`采集于 ${formatTime(data.collectedAt)}`} />
      <div className="grid grid-cols-1 gap-x-8 gap-y-4 p-5 sm:grid-cols-2 xl:grid-cols-3">
        <Field label="CPU 型号" value={hw.cpuModel || "—"} wide />
        <Field label="核心 / 线程" value={`${hw.cpuCores || "—"} / ${hw.cpuThreads || "—"}`} />
        <Field label="内存总量" value={formatBytes(hw.memTotal)} />
        <Field label="内核版本" value={hw.kernel || "—"} />
        <Field label="虚拟化" value={hw.virtualization === "virtual" ? "虚拟化环境" : hw.virtualization === "physical" ? "物理机" : "—"} />
        <Field label="设备序列号" value={hw.serial || "—"} />
      </div>
      <div className="border-t border-line px-5 py-4">
        <p className="mb-2 text-[12px] font-medium text-ink">磁盘</p>
        {hw.disks.length === 0 ? (
          <p className="text-[11.5px] text-ink3">未采集到磁盘信息</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th pl-1">设备</th>
                  <th className="th">型号</th>
                  <th className="th">序列号</th>
                  <th className="th pr-1 text-right">容量</th>
                </tr>
              </thead>
              <tbody>
                {hw.disks.map((disk) => (
                  <tr key={disk.device || disk.model} className="border-b border-line/70 last:border-0">
                    <td className="td pl-1 font-mono text-[11.5px]">{disk.device || "—"}</td>
                    <td className="td text-[12px]">{disk.model || "—"}</td>
                    <td className="td font-mono text-[11px] text-ink3">{disk.serial || "—"}</td>
                    <td className="td pr-1 text-right tabular-nums">{formatBytes(disk.sizeBytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="border-t border-line px-5 py-4">
        <p className="mb-2 text-[12px] font-medium text-ink">网卡</p>
        {hw.nics.length === 0 ? (
          <p className="text-[11.5px] text-ink3">未采集到物理网卡</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[480px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th pl-1">名称</th>
                  <th className="th">MAC</th>
                  <th className="th pr-1 text-right">速率</th>
                </tr>
              </thead>
              <tbody>
                {hw.nics.map((nic) => (
                  <tr key={nic.name + nic.mac} className="border-b border-line/70 last:border-0">
                    <td className="td pl-1 text-[12px]">{nic.name}</td>
                    <td className="td font-mono text-[11px] text-ink2">{nic.mac}</td>
                    <td className="td pr-1 text-right tabular-nums">
                      {nic.speedMbps > 0 ? `${nic.speedMbps} Mbps` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function ServicesView({ data }: { data: HostTelemetry }) {
  if (data.services.length === 0) {
    return <Empty title="未采集到服务状态" description="请确认目标主机支持 systemd/OpenRC 或 Windows 服务查询。" />;
  }
  return (
    <div>
      <PanelHeader title="系统服务" subtitle={`${data.services.length} 项 · 采集于 ${formatTime(data.collectedAt)}`} />
      <div className="max-h-[520px] overflow-auto">
        <table className="w-full min-w-[560px] border-collapse">
          <thead className="sticky top-0 bg-surface">
            <tr className="border-b border-line">
              <th className="th pl-5">服务</th>
              <th className="th w-[110px]">状态</th>
              <th className="th w-[100px]">开机启动</th>
              <th className="th pr-5">说明</th>
            </tr>
          </thead>
          <tbody>
            {data.services.map((service) => (
              <tr key={service.name} className="border-b border-line/70 last:border-0">
                <td className="td pl-5 font-mono text-[11.5px] text-ink">{service.name}</td>
                <td className="td">
                  <span
                    className={`pill ${
                      service.state === "running" || service.state === "active"
                        ? "bg-[#E8F7EE] text-[#1E7B3C]"
                        : service.state === "failed"
                          ? "bg-[#FFECEA] text-[#C4170E]"
                          : "bg-subtle text-ink2"
                    }`}
                  >
                    {service.state || "unknown"}
                  </span>
                </td>
                <td className="td text-[11.5px] text-ink2">{service.enabled ? "是" : "否"}</td>
                <td className="td max-w-[360px] truncate pr-5 text-[11.5px] text-ink3">{service.detail || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PortsView({ data }: { data: HostTelemetry }) {
  if (data.ports.length === 0) {
    return <Empty title="未采集到监听端口" description="请确认目标主机允许读取 ss 或 /proc/net/tcp / Get-NetTCPConnection。" />;
  }
  return (
    <div>
      <PanelHeader title="监听端口" subtitle={`${data.ports.length} 项 · 采集于 ${formatTime(data.collectedAt)}`} />
      <div className="max-h-[520px] overflow-auto">
        <table className="w-full min-w-[560px] border-collapse">
          <thead className="sticky top-0 bg-surface">
            <tr className="border-b border-line">
              <th className="th w-[70px] pl-5">协议</th>
              <th className="th w-[150px]">监听地址</th>
              <th className="th w-[90px] text-right">端口</th>
              <th className="th">进程</th>
              <th className="th w-[90px] pr-5 text-right">PID</th>
            </tr>
          </thead>
          <tbody>
            {data.ports.map((port) => (
              <tr key={`${port.proto}-${port.addr}-${port.port}`} className="border-b border-line/70 last:border-0">
                <td className="td pl-5 font-mono text-[11px] uppercase text-ink2">{port.proto || "tcp"}</td>
                <td className="td font-mono text-[11.5px] text-ink2">{port.addr || "0.0.0.0"}</td>
                <td className="td text-right font-mono text-[12px] tabular-nums text-ink">{port.port}</td>
                <td className="td text-[12px]">{port.process || <span className="text-ink3">未知</span>}</td>
                <td className="td pr-5 text-right tabular-nums text-[11.5px] text-ink3">{port.pid || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Field({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={wide ? "sm:col-span-2 xl:col-span-3" : undefined}>
      <p className="text-[11px] text-ink3">{label}</p>
      <p className="mt-1 break-all text-[12.5px] text-ink">{value}</p>
    </div>
  );
}

function TelemetryStat({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-panel border border-line bg-subtle/50 px-3.5 py-3">
      <p className="text-[11px] text-ink3">{label}</p>
      <p className="mt-1 break-all text-[13px] font-semibold tabular-nums" style={{ color: tone ?? "#1D1D1F" }}>
        {value}
      </p>
      {hint && <p className="mt-0.5 text-[10.5px] text-ink3">{hint}</p>}
    </div>
  );
}

function formatBytes(value: number): string {
  if (!value || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let index = 0;
  let size = value;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 100 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
}

function formatBps(value: number): string {
  if (!value || value <= 0) return "0 B/s";
  return `${formatBytes(value)}/s`;
}

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${minutes} 分`;
  return `${minutes} 分钟`;
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
