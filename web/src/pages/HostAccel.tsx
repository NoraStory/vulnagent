import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  Gauge,
  Lightbulb,
  Loader2,
  RefreshCw,
  Server,
  TriangleAlert,
  Zap
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useToast } from "../lib/toast";
import type { AccelNode, AccelSuggestion, SshAccelComparison, SshAccelProfile } from "../lib/types";
import { Empty } from "../components/ui";

function formatKB(value: number): string {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} GB`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} MB`;
  return `${Math.round(value)} KB`;
}

function formatTime(value: string): string {
  if (!value) return "—";
  return value.replace("T", " ").slice(0, 19);
}

function StatCard({ label, value, sub, tone }: {
  label: string;
  value: string;
  sub?: string;
  tone?: "normal" | "ok" | "warn" | "danger";
}) {
  const toneClass =
    tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "text-ink";
  return (
    <div className="card px-3 py-2.5">
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className={`mt-1 truncate font-mono text-[18px] font-semibold leading-6 ${toneClass}`}>{value}</p>
      {sub && <p className="mt-0.5 truncate text-[10px] text-ink3">{sub}</p>}
    </div>
  );
}

function SuggestionItem({ item, onCopy }: { item: AccelSuggestion; onCopy: (command: string) => void }) {
  return (
    <div className="rounded-[9px] border border-line bg-surface px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <Lightbulb size={12} className="text-warn" />
        <span className="text-[12px] font-medium text-ink">{item.title}</span>
        <span className={`rounded-full px-1.5 py-0.5 text-[9.5px] ${item.risk === "medium" ? "bg-warnSoft text-warn" : "bg-subtle text-ink3"}`}>
          {item.risk === "medium" ? "需谨慎" : "低风险"}
        </span>
        {item.impact && <span className="text-[10px] text-ink3">预期：{item.impact}</span>}
      </div>
      <p className="mt-1 text-[11px] leading-[17px] text-ink2">{item.detail}</p>
      {item.command && (
        <div className="mt-1.5 flex items-start gap-2 rounded-[7px] bg-ink/[0.04] px-2 py-1.5">
          <code className="min-w-0 flex-1 break-all font-mono text-[10.5px] leading-[16px] text-ink2">{item.command}</code>
          <button
            type="button"
            className="shrink-0 rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={() => onCopy(item.command)}
            title="复制命令"
            aria-label="复制命令"
          >
            <Copy size={11} />
          </button>
        </div>
      )}
    </div>
  );
}

export function HostAccelPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const hostId = Number(id);

  const [profile, setProfile] = useState<SshAccelProfile | null>(null);
  const [nodes, setNodes] = useState<AccelNode[]>([]);
  const [comparison, setComparison] = useState<SshAccelComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [baselining, setBaselining] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!Number.isFinite(hostId) || hostId <= 0) {
      setError("无效的主机 ID");
      return;
    }
    setLoading(true);
    try {
      const [next, nodeList] = await Promise.all([api.sshHostAccel(hostId), api.accelHosts()]);
      setProfile(next);
      setNodes(nodeList.items);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "读取服务加速信息失败");
    } finally {
      setLoading(false);
    }
  }, [hostId]);

  useEffect(() => {
    setProfile(null);
    setComparison(null);
    void load();
  }, [load]);

  async function recordBaseline() {
    if (baselining) return;
    setBaselining(true);
    try {
      const result = await api.sshHostAccelBaseline(hostId);
      setProfile(result.profile);
      setComparison(null);
      toast.push(`已记录基线（${formatTime(result.createdAt)}）`, "success");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "记录基线失败", "error");
    } finally {
      setBaselining(false);
    }
  }

  async function compare() {
    if (comparing) return;
    setComparing(true);
    try {
      setComparison(await api.sshHostAccelCompare(hostId));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "对比失败", "error");
    } finally {
      setComparing(false);
    }
  }

  function copyCommand(command: string) {
    if (!command) return;
    void navigator.clipboard
      .writeText(command)
      .then(() => toast.push("命令已复制，请在目标机人工执行", "success"))
      .catch(() => toast.push("复制失败，请手动选择命令", "error"));
  }

  const gpu = profile && profile.gpus.length > 0 ? profile.gpus[0] : null;
  const persistOK = gpu && gpu.persistenceMode.toLowerCase() === "enabled";
  const powerLimited = gpu && gpu.powerDefaultW > 0 && gpu.powerLimitW > 0 && gpu.powerLimitW < gpu.powerDefaultW - 1;
  const sampledAt = profile ? formatTime(profile.sampledAt) : "";

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
            <Zap size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-[15px] font-semibold leading-5 text-ink">
              服务加速{profile ? ` · ${profile.hostName}` : ""}
            </h2>
            <p className="truncate text-[11px] text-ink3">
              {profile
                ? `${profile.hostAddr} · 检测于 ${sampledAt} · 耗时 ${profile.elapsedMs} ms`
                : "正在检测主机的 GPU 与服务加速能力…"}
            </p>
          </div>
        </div>
        <button
          type="button"
          className="btn btn-secondary h-8 px-2.5 text-[12px]"
          onClick={() => void load()}
          disabled={loading}
        >
          {loading ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
          重新检测
        </button>
      </div>

      {error && (
        <div className="rounded-card border border-line bg-dangerSoft px-3 py-2 text-[11.5px] text-danger">
          {error}
          <button type="button" className="ml-2 underline" onClick={() => void load()}>
            重试
          </button>
        </div>
      )}

      {!profile && !error && (
        <div className="card flex h-[200px] items-center justify-center gap-2 text-[12px] text-ink3">
          <Loader2 size={15} className="animate-spin" />
          正在读取 GPU、CUDA 与系统调频状态…
        </div>
      )}

      {profile && (
        <>
          <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-5">
            <StatCard
              label="GPU"
              value={gpu ? gpu.name.replace(/^NVIDIA\s+/, "") : "未检测到"}
              sub={profile.available ? `${profile.gpus.length} 块 · CUDA ${profile.cuda || "未知"}` : "NVIDIA 驱动不可用"}
              tone={profile.available ? "ok" : "danger"}
            />
            <StatCard
              label="显存"
              value={gpu ? `${formatKB(gpu.memoryUsedMb * 1024)} / ${formatKB(gpu.memoryMb * 1024)}` : "—"}
              sub={gpu ? `驱动 ${gpu.driver}` : ""}
            />
            <StatCard
              label="GPU 利用率"
              value={gpu ? `${gpu.utilization.toFixed(1)}%` : "—"}
              sub={gpu?.throttle ? `降频原因：${gpu.throttle}` : "实时采样"}
              tone={gpu && gpu.throttle && !/not active/i.test(gpu.throttle) ? "warn" : "normal"}
            />
            <StatCard
              label="持久化模式"
              value={gpu ? (persistOK ? "已开启" : gpu.persistenceMode || "未知") : "—"}
              sub="短任务启动更稳定"
              tone={persistOK ? "ok" : "warn"}
            />
            <StatCard
              label="功耗上限"
              value={gpu && gpu.powerLimitW > 0 ? `${gpu.powerLimitW.toFixed(0)} W` : "—"}
              sub={gpu && gpu.powerDefaultW > 0 ? `出厂 ${gpu.powerDefaultW.toFixed(0)} W` : ""}
              tone={powerLimited ? "warn" : "normal"}
            />
            <StatCard
              label="GPU 当前频率"
              value={gpu && gpu.clockMhz > 0 ? `${gpu.clockMhz.toFixed(0)} MHz` : "—"}
              sub={gpu && gpu.maxClockMhz > 0 ? `最高 ${gpu.maxClockMhz.toFixed(0)} MHz` : ""}
            />
            <StatCard
              label="CPU 调频"
              value={profile.cpuGovernor || "unknown"}
              sub={`${profile.cpuCores} 核 · ${profile.cpuModel || "未知型号"}`}
              tone={profile.cpuGovernor === "performance" ? "ok" : "warn"}
            />
            <StatCard label="内存" value={formatKB(profile.memTotalKb)} sub="总容量" />
            <StatCard
              label="Swap"
              value={profile.swapTotalKb > 0 ? formatKB(profile.swapTotalKb) : "未启用"}
              sub={profile.swapTotalKb > 0 ? "加速任务可能出现换页" : "无换页风险"}
              tone={profile.swapTotalKb > 0 ? "warn" : "normal"}
            />
            <StatCard
              label="服务加速"
              value={profile.accelEnabled ? "已启用" : "未启用"}
              sub={profile.endpointReady ? "推理端点就绪" : "未配置 AI 加速端点"}
              tone={profile.accelEnabled ? "ok" : "normal"}
            />
          </div>

          <div className="grid grid-cols-1 gap-2.5 xl:grid-cols-3">
            <div className="card px-3 py-2.5">
              <p className="flex items-center gap-1.5 text-[12px] font-medium text-ink">
                <Server size={12} className="text-brand" />
                服务端加速状态
              </p>
              <div className="mt-2 space-y-1.5 text-[11px] leading-[17px] text-ink2">
                <p className="flex items-center justify-between gap-2">
                  <span>GPU 可用</span>
                  <span className={profile.available ? "text-ok" : "text-danger"}>{profile.available ? "是" : "否"}</span>
                </p>
                <p className="flex items-center justify-between gap-2">
                  <span>加速开关</span>
                  <span className={profile.accelEnabled ? "text-ok" : "text-ink3"}>{profile.accelEnabled ? "已开启" : "已关闭"}</span>
                </p>
                <p className="flex items-center justify-between gap-2">
                  <span>AI 推理端点</span>
                  <span className={profile.endpointReady ? "text-ok" : "text-warn"}>{profile.endpointReady ? "已配置" : "未配置"}</span>
                </p>
                <p className="flex items-center justify-between gap-2">
                  <span>最近基线</span>
                  <span className="text-ink3">{profile.baselineAt ? formatTime(profile.baselineAt) : "未记录"}</span>
                </p>
                <p className="pt-1 text-[10.5px] text-ink3">
                  加速开关在 SSH 终端的主机编辑弹窗中修改；本页只做只读检测与建议，不会改动目标机。
                </p>
              </div>
            </div>

            <div className="card overflow-hidden xl:col-span-2">
              <div className="flex items-center justify-between border-b border-line px-3 py-2">
                <p className="text-[12px] font-medium text-ink">优化建议</p>
                <span className="text-[10px] text-ink3">{profile.suggestions.length} 项 · 仅建议</span>
              </div>
              <div className="max-h-[320px] space-y-2 overflow-y-auto px-3 py-2.5">
                {profile.suggestions.length === 0 ? (
                  <div className="flex items-center gap-2 rounded-[9px] bg-okSoft px-3 py-2 text-[11.5px] text-ok">
                    <CheckCircle2 size={13} />
                    当前配置已处于加速友好状态，未发现需要调整的项。
                  </div>
                ) : (
                  profile.suggestions.map((item) => (
                    <SuggestionItem key={item.id} item={item} onCopy={copyCommand} />
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-2.5 xl:grid-cols-2">
            <div className="card overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-3 py-2">
                <p className="text-[12px] font-medium text-ink">GPU 明细</p>
                <span className="text-[10px] text-ink3">nvidia-smi</span>
              </div>
              {profile.gpus.length === 0 ? (
                <Empty title="未检测到 NVIDIA GPU" description={profile.nvidiaSmi ? "驱动正常但无设备" : "未安装 nvidia-smi"} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] border-collapse text-[11.5px]">
                    <thead>
                      <tr className="border-b border-line bg-subtle/60 text-left text-[10px] text-ink3">
                        <th className="px-3 py-1.5 font-medium">设备</th>
                        <th className="px-3 py-1.5 text-right font-medium">显存</th>
                        <th className="px-3 py-1.5 text-right font-medium">利用率</th>
                        <th className="px-3 py-1.5 font-medium">持久化</th>
                        <th className="px-3 py-1.5 text-right font-medium">功耗</th>
                        <th className="px-3 py-1.5 text-right font-medium">频率</th>
                      </tr>
                    </thead>
                    <tbody>
                      {profile.gpus.map((item, index) => (
                        <tr key={`${item.name}-${index}`} className="border-b border-line/60 last:border-0">
                          <td className="max-w-[180px] truncate px-3 py-1.5">
                            <span className="font-mono text-ink3">{index}</span>{" "}
                            <span className="text-ink2">{item.name}</span>
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-[10.5px] text-ink2">
                            {formatKB(item.memoryUsedMb * 1024)} / {formatKB(item.memoryMb * 1024)}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-ink2">{item.utilization.toFixed(1)}%</td>
                          <td className={`px-3 py-1.5 ${/enabled/i.test(item.persistenceMode) ? "text-ok" : "text-warn"}`}>
                            {item.persistenceMode || "未知"}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-ink2">
                            {item.powerLimitW > 0 ? `${item.powerLimitW.toFixed(0)} W` : "—"}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono text-ink2">
                            {item.clockMhz > 0 ? `${item.clockMhz.toFixed(0)} MHz` : "—"}
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
                <p className="text-[12px] font-medium text-ink">加速节点</p>
                <span className="text-[10px] text-ink3">已开启加速的主机 · 服务端调度候选</span>
              </div>
              {nodes.length === 0 ? (
                <Empty title="暂无加速节点" description="在主机编辑弹窗中开启服务加速" />
              ) : (
                <div className="divide-y divide-line/60">
                  {nodes.map((node) => (
                    <button
                      key={node.hostId}
                      type="button"
                      className={`flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-subtle/60 ${
                        node.hostId === hostId ? "bg-brand-soft/40" : ""
                      }`}
                      onClick={() => navigate(`/terminal/accel/${node.hostId}`)}
                      disabled={node.hostId === hostId}
                    >
                      <Zap size={12} className={node.available ? "text-brand" : "text-ink3"} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[11.5px] font-medium text-ink">{node.hostName}</span>
                        <span className="block truncate text-[10px] text-ink3">
                          {node.gpuName || node.hostAddr}
                        </span>
                      </span>
                      <span
                        className={`shrink-0 rounded-full px-1.5 py-0.5 text-[9.5px] ${
                          node.available ? "bg-okSoft text-ok" : "bg-subtle text-ink3"
                        }`}
                      >
                        {node.available ? "就绪" : "未探测"}
                      </span>
                      <span className="shrink-0 font-mono text-[10px] text-ink3">{node.cuda || ""}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="card overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
              <p className="text-[12px] font-medium text-ink">加速前后对比</p>
              <span className="text-[10px] text-ink3">
                {profile.baselineAt ? `基线 ${formatTime(profile.baselineAt)}` : "先记录基线，调整配置后再对比"}
              </span>
              <span className="ml-auto flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-secondary h-7 px-2.5 text-[11px]"
                  onClick={() => void recordBaseline()}
                  disabled={baselining}
                >
                  {baselining ? <Loader2 size={12} className="animate-spin" /> : <Gauge size={12} />}
                  记录基线
                </button>
                <button
                  type="button"
                  className="btn btn-primary h-7 px-2.5 text-[11px]"
                  onClick={() => void compare()}
                  disabled={comparing || !profile.baselineAt}
                  title={profile.baselineAt ? "采样当前状态并与基线对比" : "请先记录基线"}
                >
                  {comparing ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  对比加速前后
                </button>
              </span>
            </div>

            {!comparison ? (
              <div className="flex items-center gap-2 px-3 py-4 text-[11px] text-ink3">
                <TriangleAlert size={12} />
                对比基于真实采样：记录基线后，人工调整 GPU/CPU 配置或负载，再点击对比。
              </div>
            ) : (
              <div className="space-y-2 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-ink3">
                  <span>基线：{formatTime(comparison.baselineAt)}</span>
                  <span>当前：{formatTime(comparison.currentAt)}</span>
                  <span>记录人：{comparison.baselineBy || "—"}</span>
                  <span>采样耗时：{comparison.elapsedMs} ms</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[520px] border-collapse text-[11.5px]">
                    <thead>
                      <tr className="border-b border-line text-left text-[10px] text-ink3">
                        <th className="px-2 py-1.5 font-medium">指标</th>
                        <th className="px-2 py-1.5 text-right font-medium">基线</th>
                        <th className="px-2 py-1.5 text-right font-medium">当前</th>
                        <th className="px-2 py-1.5 text-right font-medium">变化</th>
                      </tr>
                    </thead>
                    <tbody>
                      {comparison.metrics.map((item) => (
                        <tr key={item.key} className="border-b border-line/60 last:border-0">
                          <td className="px-2 py-1.5 text-ink2">{item.label}</td>
                          <td className="px-2 py-1.5 text-right font-mono text-[10.5px] text-ink3">
                            {item.before.toFixed(1)}
                            {item.unit}
                          </td>
                          <td className="px-2 py-1.5 text-right font-mono text-[10.5px] text-ink">
                            {item.after.toFixed(1)}
                            {item.unit}
                          </td>
                          <td
                            className={`px-2 py-1.5 text-right font-mono text-[10.5px] ${
                              item.better === "none" ? "text-ink3" : item.improved ? "text-ok" : item.delta === 0 ? "text-ink3" : "text-danger"
                            }`}
                          >
                            {item.delta > 0 ? "+" : ""}
                            {item.delta.toFixed(1)}
                            {item.unit}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {comparison.changes.length > 0 && (
                  <div className="rounded-[8px] bg-subtle/70 px-2.5 py-1.5 text-[10.5px] leading-[17px] text-ink2">
                    <span className="font-medium text-ink">检测到的配置变更：</span>
                    {comparison.changes.join("；")}
                  </div>
                )}
                {comparison.suggestions.length > 0 && (
                  <p className="text-[10.5px] text-ink3">
                    仍有 {comparison.suggestions.length} 项建议未处理，可在上方「优化建议」中查看。
                  </p>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
