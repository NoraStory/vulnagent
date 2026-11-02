import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Activity, ArrowLeft, Loader2, Pause, Play, RefreshCw } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { SshHostMetrics } from "../lib/types";
import { MetricTrend } from "../components/MetricTrend";
import { Empty } from "../components/ui";

const MAX_POINTS = 90;
const INTERVAL_OPTIONS = [2, 3, 5, 10];

interface MonitorPoint {
  time: number;
  cpu: number;
  mem: number;
  load1: number;
  load5: number;
  rx: number;
  tx: number;
}

function formatRate(value: number): string {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB/s`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB/s`;
  return `${Math.round(value)} B/s`;
}

function formatKB(value: number): string {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} GB`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} MB`;
  return `${Math.round(value)} KB`;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days > 0 ? `${days}天 ${hours}小时` : `${hours}小时 ${minutes}分`;
}

function formatClock(value: number): string {
  return new Date(value).toLocaleTimeString("zh-CN", { hour12: false });
}

function StatCard({ label, value, sub, tone }: {
  label: string;
  value: string;
  sub?: string;
  tone?: "normal" | "warn" | "danger";
}) {
  const toneClass = tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "text-ink";
  return (
    <div className="card px-3 py-2.5">
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className={`mt-1 truncate font-mono text-[20px] font-semibold leading-6 ${toneClass}`}>{value}</p>
      {sub && <p className="mt-0.5 truncate text-[10px] text-ink3">{sub}</p>}
    </div>
  );
}

export function HostMonitorPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const hostId = Number(id);
  const seq = useRef(0);

  const [metric, setMetric] = useState<SshHostMetrics | null>(null);
  const [history, setHistory] = useState<MonitorPoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [paused, setPaused] = useState(false);
  const [intervalSec, setIntervalSec] = useState(3);

  const load = useCallback(async () => {
    const current = ++seq.current;
    setLoading(true);
    try {
      const sample = await api.sshHostMetrics(hostId);
      if (seq.current !== current) return;
      setMetric(sample);
      setHistory((prev) =>
        [
          ...prev,
          {
            time: Date.now(),
            cpu: sample.cpuPercent,
            mem: sample.memPercent,
            load1: sample.load1,
            load5: sample.load5,
            rx: sample.netRxBps,
            tx: sample.netTxBps
          }
        ].slice(-MAX_POINTS)
      );
      setError("");
    } catch (err) {
      if (seq.current !== current) return;
      setError(err instanceof ApiError ? err.message : "读取主机性能失败");
    } finally {
      if (seq.current === current) setLoading(false);
    }
  }, [hostId]);

  useEffect(() => {
    setMetric(null);
    setHistory([]);
    setError("");
    seq.current++;
    if (!Number.isFinite(hostId) || hostId <= 0) {
      setError("无效的主机 ID");
    }
  }, [hostId]);

  useEffect(() => {
    if (!Number.isFinite(hostId) || hostId <= 0 || paused) return;
    void load();
    const timer = window.setInterval(() => void load(), intervalSec * 1000);
    return () => window.clearInterval(timer);
  }, [hostId, paused, intervalSec, load]);

  const cpuSeries = useMemo(() => [{ label: "CPU", values: history.map((p) => p.cpu), color: "var(--color-brand)", fill: true }], [history]);
  const memSeries = useMemo(() => [{ label: "内存", values: history.map((p) => p.mem), color: "var(--color-signal)", fill: true }], [history]);
  const loadSeries = useMemo(
    () => [
      { label: "1 分钟", values: history.map((p) => p.load1), color: "var(--color-brand)" },
      { label: "5 分钟", values: history.map((p) => p.load5), color: "var(--color-warn)" }
    ],
    [history]
  );
  const netSeries = useMemo(
    () => [
      { label: "下行", values: history.map((p) => p.rx), color: "var(--color-ok)", fill: true },
      { label: "上行", values: history.map((p) => p.tx), color: "var(--color-warn)" }
    ],
    [history]
  );

  const maxDiskPercent = metric && metric.disks.length > 0 ? Math.max(...metric.disks.map((item) => item.percent)) : 0;
  const cpuTone = !metric ? "normal" : metric.cpuPercent >= 85 ? "danger" : metric.cpuPercent >= 70 ? "warn" : "normal";
  const memTone = !metric ? "normal" : metric.memPercent >= 90 ? "danger" : metric.memPercent >= 75 ? "warn" : "normal";
  const diskTone = maxDiskPercent >= 90 ? "danger" : maxDiskPercent >= 80 ? "warn" : "normal";
  const recent = useMemo(() => [...history].reverse().slice(0, 20), [history]);
  const sampledAt = metric ? new Date(metric.sampledAt.replace(" ", "T")).toLocaleTimeString("zh-CN", { hour12: false }) : "";

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <button
            type="button"
            className="btn btn-secondary h-8 w-8 shrink-0 px-0"
            onClick={() => navigate("/terminal")}
            title="返回 SSH 终端"
            aria-label="返回 SSH 终端"
          >
            <ArrowLeft size={14} />
          </button>
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-ink text-white">
            <Activity size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-[15px] font-semibold leading-5 text-ink">
              性能监控{metric ? ` · ${metric.hostName}` : ""}
            </h2>
            <p className="truncate text-[11px] text-ink3">
              {metric ? `${metric.hostAddr} · 采样于 ${sampledAt} · 耗时 ${metric.elapsedMs} ms` : "正在连接主机并采集性能数据…"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="input h-8 w-[112px] text-[11.5px]"
            value={intervalSec}
            onChange={(event) => setIntervalSec(Number(event.target.value))}
            aria-label="采样间隔"
          >
            {INTERVAL_OPTIONS.map((value) => (
              <option key={value} value={value}>
                每 {value} 秒
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-secondary h-8 px-2.5 text-[12px]"
            onClick={() => setPaused((value) => !value)}
          >
            {paused ? <Play size={13} /> : <Pause size={13} />}
            {paused ? "继续" : "暂停"}
          </button>
          <button
            type="button"
            className="btn btn-secondary h-8 w-8 px-0"
            onClick={() => void load()}
            disabled={loading || paused}
            title="立即刷新"
            aria-label="立即刷新"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-card border border-line bg-dangerSoft px-3 py-2 text-[11.5px] text-danger">
          {error}
          <button type="button" className="ml-2 underline" onClick={() => void load()}>
            重试
          </button>
        </div>
      )}

      {!metric && !error && (
        <div className="card flex h-[240px] items-center justify-center gap-2 text-[12px] text-ink3">
          <Loader2 size={15} className="animate-spin" />
          正在采集主机性能数据…
        </div>
      )}

      {metric && (
        <>
          <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4 xl:grid-cols-5">
            <StatCard label="CPU 使用率" value={`${metric.cpuPercent.toFixed(1)}%`} sub={`${metric.cpuCores} 核`} tone={cpuTone} />
            <StatCard
              label="内存使用率"
              value={`${metric.memPercent.toFixed(1)}%`}
              sub={`${formatKB(metric.memUsedKb)} / ${formatKB(metric.memTotalKb)}`}
              tone={memTone}
            />
            <StatCard
              label="系统负载"
              value={metric.load1.toFixed(2)}
              sub={`5m ${metric.load5.toFixed(2)} · 15m ${metric.load15.toFixed(2)}`}
            />
            <StatCard
              label="磁盘最高占用"
              value={maxDiskPercent > 0 ? `${maxDiskPercent.toFixed(1)}%` : "—"}
              sub={metric.disks.length > 0 ? `${metric.disks.length} 个挂载点` : "无数据"}
              tone={diskTone}
            />
            <StatCard label="进程数" value={String(metric.processes)} sub={`运行 ${formatUptime(metric.uptimeSeconds)}`} />
            <StatCard
              label="网络下行"
              value={formatRate(metric.netRxBps)}
              sub="实时接收速率"
            />
            <StatCard label="网络上行" value={formatRate(metric.netTxBps)} sub="实时发送速率" />
            <StatCard
              label="Swap"
              value={metric.swapTotalKb > 0 ? `${metric.swapPercent.toFixed(1)}%` : "未启用"}
              sub={metric.swapTotalKb > 0 ? `${formatKB(metric.swapUsedKb)} / ${formatKB(metric.swapTotalKb)}` : ""}
            />
            <StatCard label="采样延迟" value={`${metric.elapsedMs} ms`} sub={`每 ${intervalSec} 秒刷新`} />
            <StatCard
              label="最近采样"
              value={sampledAt || "—"}
              sub={paused ? "已暂停" : loading ? "采集中" : "自动刷新中"}
            />
          </div>

          <div className="grid grid-cols-1 gap-2.5 xl:grid-cols-2">
            <MetricTrend title="CPU 使用率" hint="两次 /proc/stat 快照差值" unit="%" series={cpuSeries} max={100} height={120} />
            <MetricTrend
              title="内存使用率"
              hint={`已用 ${formatKB(metric.memUsedKb)} / 共 ${formatKB(metric.memTotalKb)}`}
              unit="%"
              series={memSeries}
              max={100}
              height={120}
            />
            <MetricTrend
              title="系统负载"
              hint={`${metric.cpuCores} 核 · 1m / 5m`}
              series={loadSeries}
              height={110}
              formatValue={(value) => value.toFixed(2)}
            />
            <MetricTrend
              title="网络吞吐"
              hint="接收 / 发送"
              series={netSeries}
              height={110}
              formatValue={formatRate}
            />
          </div>

          <div className="grid grid-cols-1 gap-2.5 xl:grid-cols-2">
            <div className="card overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-3 py-2">
                <p className="text-[12px] font-medium text-ink">磁盘挂载点</p>
                <span className="text-[10px] text-ink3">{metric.disks.length} 项</span>
              </div>
              {metric.disks.length === 0 ? (
                <Empty title="暂无磁盘数据" />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[420px] border-collapse text-[11.5px]">
                    <thead>
                      <tr className="border-b border-line bg-subtle/60 text-left text-[10px] text-ink3">
                        <th className="px-3 py-1.5 font-medium">挂载点</th>
                        <th className="px-3 py-1.5 font-medium">占用</th>
                        <th className="px-3 py-1.5 text-right font-medium">已用 / 总量</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metric.disks.map((disk) => (
                        <tr key={disk.mount} className="border-b border-line/60 last:border-0">
                          <td className="px-3 py-1.5 font-mono text-ink2">{disk.mount}</td>
                          <td className="px-3 py-1.5">
                            <div className="flex items-center gap-2">
                              <div className="h-1.5 w-24 overflow-hidden rounded-full bg-subtle">
                                <div
                                  className={`h-full rounded-full ${disk.percent >= 90 ? "bg-danger" : disk.percent >= 80 ? "bg-warn" : "bg-brand"}`}
                                  style={{ width: `${Math.min(100, disk.percent)}%` }}
                                />
                              </div>
                              <span className="font-mono text-[10.5px] text-ink2">{disk.percent.toFixed(1)}%</span>
                            </div>
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-[10.5px] text-ink2">
                            {formatKB(disk.usedKb)} / {formatKB(disk.totalKb)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="card overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-3 py-2">
                <p className="text-[12px] font-medium text-ink">CPU 占用 Top 5</p>
                <span className="text-[10px] text-ink3">ps --sort=-%cpu</span>
              </div>
              {metric.top.length === 0 ? (
                <Empty title="暂无进程数据" />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[420px] border-collapse text-[11.5px]">
                    <thead>
                      <tr className="border-b border-line bg-subtle/60 text-left text-[10px] text-ink3">
                        <th className="px-3 py-1.5 font-medium">PID</th>
                        <th className="px-3 py-1.5 font-medium">进程</th>
                        <th className="px-3 py-1.5 text-right font-medium">CPU</th>
                        <th className="px-3 py-1.5 text-right font-medium">内存</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metric.top.map((item) => (
                        <tr key={item.pid} className="border-b border-line/60 last:border-0">
                          <td className="px-3 py-1.5 font-mono text-ink3">{item.pid}</td>
                          <td className="max-w-[180px] truncate px-3 py-1.5 font-mono text-ink2">{item.command}</td>
                          <td className="px-3 py-1.5 text-right font-mono text-ink2">{item.cpuPercent.toFixed(1)}%</td>
                          <td className="px-3 py-1.5 text-right font-mono text-ink2">{item.memPercent.toFixed(1)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-3 py-2">
              <p className="text-[12px] font-medium text-ink">采样记录</p>
              <span className="text-[10px] text-ink3">最近 {recent.length} 条 · 最多保留 {MAX_POINTS} 条</span>
            </div>
            <div className="max-h-[280px] overflow-auto">
              <table className="w-full min-w-[560px] border-collapse text-[11px]">
                <thead className="sticky top-0 bg-subtle/90 backdrop-blur">
                  <tr className="border-b border-line text-left text-[10px] text-ink3">
                    <th className="px-3 py-1.5 font-medium">时间</th>
                    <th className="px-3 py-1.5 text-right font-medium">CPU</th>
                    <th className="px-3 py-1.5 text-right font-medium">内存</th>
                    <th className="px-3 py-1.5 text-right font-medium">负载 1m</th>
                    <th className="px-3 py-1.5 text-right font-medium">下行</th>
                    <th className="px-3 py-1.5 text-right font-medium">上行</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-3 py-6 text-center text-[11px] text-ink3">
                        等待采样…
                      </td>
                    </tr>
                  ) : (
                    recent.map((point) => (
                      <tr key={point.time} className="border-b border-line/60 last:border-0">
                        <td className="px-3 py-1.5 font-mono text-ink3">{formatClock(point.time)}</td>
                        <td className="px-3 py-1.5 text-right font-mono text-ink2">{point.cpu.toFixed(1)}%</td>
                        <td className="px-3 py-1.5 text-right font-mono text-ink2">{point.mem.toFixed(1)}%</td>
                        <td className="px-3 py-1.5 text-right font-mono text-ink2">{point.load1.toFixed(2)}</td>
                        <td className="px-3 py-1.5 text-right font-mono text-ink2">{formatRate(point.rx)}</td>
                        <td className="px-3 py-1.5 text-right font-mono text-ink2">{formatRate(point.tx)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
