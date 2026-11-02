import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bot,
  CheckCircle2,
  Copy,
  KeyRound,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Send,
  ShieldOff,
  Trash2,
  X
} from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";
import type { AgentCommandItem, AgentEnrollTokenItem, AgentItem, ClusterItem, ProjectItem } from "../lib/types";
import { Empty } from "../components/ui";
import { timeAgo } from "../lib/format";

const statusMeta: Record<string, { label: string; dot: string; text: string }> = {
  online: { label: "在线", dot: "bg-ok", text: "text-ok" },
  offline: { label: "离线", dot: "bg-ink3", text: "text-ink3" },
  revoked: { label: "已吊销", dot: "bg-danger", text: "text-danger" }
};

const tokenStatusMeta: Record<string, { label: string; className: string }> = {
  active: { label: "可用", className: "bg-okSoft text-ok" },
  used: { label: "已使用", className: "bg-subtle text-ink3" },
  expired: { label: "已过期", className: "bg-dangerSoft text-danger" }
};

const commandStatusMeta: Record<string, { label: string; className: string }> = {
  pending: { label: "待执行", className: "bg-subtle text-ink3" },
  claimed: { label: "执行中", className: "bg-brand-soft text-brand" },
  succeeded: { label: "成功", className: "bg-okSoft text-ok" },
  failed: { label: "失败", className: "bg-dangerSoft text-danger" }
};

function StatCard({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: "ok" | "danger" }) {
  return (
    <div className="card px-3 py-2.5">
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className={`mt-1 font-mono text-[20px] font-semibold leading-6 ${tone === "ok" ? "text-ok" : tone === "danger" ? "text-danger" : "text-ink"}`}>
        {value}
      </p>
      {sub && <p className="mt-0.5 truncate text-[10px] text-ink3">{sub}</p>}
    </div>
  );
}

export function AgentsPage() {
  const { canWrite } = useAuth();
  const toast = useToast();
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [online, setOnline] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [tokens, setTokens] = useState<AgentEnrollTokenItem[]>([]);
  const [tokensOpen, setTokensOpen] = useState(false);
  const [commandAgent, setCommandAgent] = useState<AgentItem | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.agents();
      setAgents(result.items ?? []);
      setOnline(result.online ?? 0);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "读取 Agent 失败", "error");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const loadTokens = useCallback(async () => {
    if (!canWrite) return;
    try {
      const result = await api.agentEnrollTokens();
      setTokens(result.items ?? []);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "读取注册令牌失败", "error");
    }
  }, [canWrite, toast]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    void loadTokens();
  }, [loadTokens]);

  async function sendCommand(agent: AgentItem, action: "ping" | "collect") {
    setBusy(`${agent.id}-${action}`);
    try {
      await api.createAgentCommand(agent.id, action);
      toast.push(action === "ping" ? "Ping 已下发" : "采集命令已下发", "success");
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "下发命令失败", "error");
    } finally {
      setBusy("");
    }
  }

  async function revoke(agent: AgentItem) {
    if (!window.confirm(`吊销 Agent「${agent.name}」？吊销后该身份无法继续上报或拉取命令。`)) return;
    setBusy(`${agent.id}-revoke`);
    try {
      await api.revokeAgent(agent.id);
      toast.push("Agent 已吊销", "success");
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "吊销失败", "error");
    } finally {
      setBusy("");
    }
  }

  async function removeToken(token: AgentEnrollTokenItem) {
    try {
      await api.deleteAgentEnrollToken(token.id);
      toast.push("注册令牌已删除", "success");
      await loadTokens();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "删除令牌失败", "error");
    }
  }

  const activeTokens = useMemo(() => tokens.filter((token) => token.status === "active"), [tokens]);
  const revokedCount = agents.filter((agent) => agent.status === "revoked").length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-ink text-white">
            <Bot size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-[15px] font-semibold leading-5 text-ink">Agent 管理</h2>
            <p className="truncate text-[11px] text-ink3">单机身份注册、心跳在线与双向命令通道</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {canWrite && (
            <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => setTokensOpen((value) => !value)}>
              <KeyRound size={13} />
              注册令牌{activeTokens.length > 0 ? ` · ${activeTokens.length}` : ""}
            </button>
          )}
          {canWrite && (
            <button type="button" className="btn btn-primary h-8 px-2.5 text-[12px]" onClick={() => setEnrollOpen(true)}>
              <Plus size={13} />
              新增 Agent
            </button>
          )}
          <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={13} className={loading ? "animate-spin" : undefined} />
            刷新
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4">
        <StatCard label="Agent 总数" value={String(agents.length)} sub="已注册的单机身份" />
        <StatCard label="在线" value={String(online)} sub="3 分钟内有心跳" tone={online > 0 ? "ok" : undefined} />
        <StatCard label="离线" value={String(agents.length - online - revokedCount)} sub="超过 3 分钟无心跳" />
        <StatCard label="已吊销" value={String(revokedCount)} sub="身份已失效" tone={revokedCount > 0 ? "danger" : undefined} />
      </div>

      {tokensOpen && canWrite && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <p className="text-[12px] font-medium text-ink">一次性注册令牌</p>
            <span className="text-[10px] text-ink3">默认 60 分钟有效，仅可使用一次</span>
          </div>
          {tokens.length === 0 ? (
            <Empty title="暂无注册令牌" description="点击「新增 Agent」生成一次性令牌" />
          ) : (
            <div className="divide-y divide-line/60">
              {tokens.map((token) => {
                const meta = tokenStatusMeta[token.status] ?? tokenStatusMeta.expired;
                return (
                  <div key={token.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-[11px]">
                    <span className="font-medium text-ink">{token.nameHint || "未命名"}</span>
                    <span className={`rounded-full px-1.5 py-0.5 text-[9.5px] ${meta.className}`}>{meta.label}</span>
                    <span className="text-ink3">
                      {token.projectName || "未绑定项目"}
                      {token.clusterName ? ` / ${token.clusterName}` : ""}
                    </span>
                    <span className="text-ink3">到期 {token.expiresAt}</span>
                    {token.usedByAgent && <span className="text-ink3">→ {token.usedByAgent}</span>}
                    <span className="ml-auto text-ink3">{token.createdBy} · {token.createdAt}</span>
                    {token.status === "active" && (
                      <button
                        type="button"
                        className="rounded p-1 text-ink3 hover:bg-dangerSoft hover:text-danger"
                        onClick={() => void removeToken(token)}
                        title="删除令牌"
                        aria-label="删除令牌"
                      >
                        <Trash2 size={11} />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <p className="text-[12px] font-medium text-ink">已注册 Agent</p>
          <span className="text-[10px] text-ink3">心跳、命令与归属集群</span>
        </div>
        {loading && agents.length === 0 ? (
          <div className="px-3 py-8 text-center text-[11.5px] text-ink3">加载中…</div>
        ) : agents.length === 0 ? (
          <Empty title="暂无 Agent" description="生成一次性令牌，在目标主机执行 vulnagent agent --enroll-token … --watch" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] border-collapse text-[11.5px]">
              <thead>
                <tr className="border-b border-line bg-subtle/60 text-left text-[10px] text-ink3">
                  <th className="px-3 py-1.5 font-medium">Agent</th>
                  <th className="px-3 py-1.5 font-medium">状态</th>
                  <th className="px-3 py-1.5 font-medium">归属</th>
                  <th className="px-3 py-1.5 font-medium">系统</th>
                  <th className="px-3 py-1.5 font-medium">版本</th>
                  <th className="px-3 py-1.5 font-medium">最近心跳</th>
                  <th className="px-3 py-1.5 text-right font-medium">命令</th>
                  <th className="px-3 py-1.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => {
                  const meta = statusMeta[agent.status] ?? statusMeta.offline;
                  const revoked = agent.status === "revoked";
                  return (
                    <tr key={agent.id} className={`border-b border-line/60 last:border-0 ${revoked ? "opacity-60" : ""}`}>
                      <td className="px-3 py-1.5">
                        <span className="block text-[11.5px] font-medium text-ink">{agent.name}</span>
                        <span className="block font-mono text-[10px] text-ink3">
                          {agent.hostname}{agent.lastIp ? ` · ${agent.lastIp}` : ""}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <span className={`inline-flex items-center gap-1.5 text-[10.5px] ${meta.text}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-[10.5px] text-ink2">
                        {agent.projectName || agent.clusterName
                          ? `${agent.projectName}${agent.clusterName ? ` / ${agent.clusterName}` : ""}`
                          : "未绑定"}
                      </td>
                      <td className="px-3 py-1.5 text-[10.5px] text-ink3">
                        {agent.os || "—"} {agent.osVersion ? `· ${agent.osVersion}` : ""}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[10.5px] text-ink3">{agent.version || "—"}</td>
                      <td className="px-3 py-1.5 text-[10.5px] text-ink3" title={agent.lastSeenAt}>
                        {agent.lastSeenAt ? timeAgo(agent.lastSeenAt) : "从未"}
                      </td>
                      <td className="px-3 py-1.5 text-right text-[10.5px] text-ink3">
                        {agent.pendingCommands > 0 ? (
                          <span className="rounded-full bg-brand-soft px-1.5 py-0.5 text-brand">待执行 {agent.pendingCommands}</span>
                        ) : (
                          `累计 ${agent.totalCommands}`
                        )}
                      </td>
                      <td className="px-3 py-1.5 text-right">
                        <span className="inline-flex items-center gap-1">
                          {canWrite && !revoked && (
                            <button
                              type="button"
                              className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                              onClick={() => void sendCommand(agent, "ping")}
                              disabled={busy !== ""}
                              title="Ping"
                              aria-label="Ping"
                            >
                              {busy === `${agent.id}-ping` ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />}
                            </button>
                          )}
                          {canWrite && !revoked && (
                            <button
                              type="button"
                              className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                              onClick={() => void sendCommand(agent, "collect")}
                              disabled={busy !== ""}
                              title="立即采集并上报"
                              aria-label="立即采集"
                            >
                              {busy === `${agent.id}-collect` ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
                            </button>
                          )}
                          <button
                            type="button"
                            className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                            onClick={() => setCommandAgent(agent)}
                            title="命令历史"
                            aria-label="命令历史"
                          >
                            <CheckCircle2 size={11} />
                          </button>
                          {canWrite && !revoked && (
                            <button
                              type="button"
                              className="rounded p-1 text-ink3 hover:bg-dangerSoft hover:text-danger"
                              onClick={() => void revoke(agent)}
                              disabled={busy !== ""}
                              title="吊销"
                              aria-label="吊销"
                            >
                              {busy === `${agent.id}-revoke` ? <Loader2 size={11} className="animate-spin" /> : <ShieldOff size={11} />}
                            </button>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {enrollOpen && (
        <EnrollDialog
          onClose={() => setEnrollOpen(false)}
          onCreated={async () => {
            await loadTokens();
            await load();
          }}
        />
      )}
      {commandAgent && <CommandsDialog agent={commandAgent} onClose={() => setCommandAgent(null)} />}
    </div>
  );
}

function ModalShell({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 px-4" onClick={onClose}>
      <div className="w-full max-w-[560px] overflow-hidden rounded-card border border-line bg-surface shadow-float" onClick={(event) => event.stopPropagation()}>
        <header className="flex items-center gap-2 border-b border-line px-5 py-3.5">
          <h3 className="text-[14px] font-semibold text-ink">{title}</h3>
          <button type="button" className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink" onClick={onClose} aria-label="关闭">
            <X size={15} />
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}

function EnrollDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => Promise<void> }) {
  const toast = useToast();
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [clusters, setClusters] = useState<ClusterItem[]>([]);
  const [nameHint, setNameHint] = useState("");
  const [projectId, setProjectId] = useState(0);
  const [clusterId, setClusterId] = useState(0);
  const [ttl, setTtl] = useState("60");
  const [saving, setSaving] = useState(false);
  const [token, setToken] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  useEffect(() => {
    void api.projects().then((result) => setProjects(result.items)).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!projectId) {
      setClusters([]);
      setClusterId(0);
      return;
    }
    void api.clusters(projectId).then((result) => {
      setClusters(result.items);
      setClusterId(0);
    }).catch(() => undefined);
  }, [projectId]);

  async function submit() {
    setSaving(true);
    try {
      const result = await api.createAgentEnrollToken({
        nameHint: nameHint.trim(),
        projectId: projectId || undefined,
        clusterId: clusterId || undefined,
        ttlMinutes: Number(ttl) || 60
      });
      setToken(result.token);
      setExpiresAt(result.expiresAt);
      await onCreated();
      toast.push("注册令牌已生成，仅显示一次", "success");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "生成注册令牌失败", "error");
    } finally {
      setSaving(false);
    }
  }

  const command = token
    ? `vulnagent agent --server ${window.location.origin} --enroll-token ${token} --watch`
    : "";

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.push(`${label}已复制`, "success");
    } catch {
      toast.push("复制失败，请手动选择", "error");
    }
  }

  return (
    <ModalShell title="新增 Agent" onClose={onClose}>
      <div className="space-y-3 px-5 py-4">
        {!token ? (
          <>
            <div className="grid grid-cols-2 gap-3">
              <label className="col-span-2 block">
                <span className="mb-1 block text-[11px] text-ink2">用途备注</span>
                <input className="input h-9 text-[12.5px]" value={nameHint} onChange={(event) => setNameHint(event.target.value)} placeholder="例如 华东生产-应用机" />
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] text-ink2">绑定项目</span>
                <select className="input h-9 text-[12.5px]" value={projectId} onChange={(event) => setProjectId(Number(event.target.value))}>
                  <option value={0}>不绑定</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] text-ink2">绑定集群</span>
                <select
                  className="input h-9 text-[12.5px]"
                  value={clusterId}
                  onChange={(event) => setClusterId(Number(event.target.value))}
                  disabled={!projectId}
                >
                  <option value={0}>不绑定</option>
                  {clusters.map((cluster) => (
                    <option key={cluster.id} value={cluster.id}>{cluster.name}</option>
                  ))}
                </select>
              </label>
              <label className="col-span-2 block">
                <span className="mb-1 block text-[11px] text-ink2">有效期（分钟）</span>
                <input className="input h-9 font-mono text-[11.5px]" value={ttl} onChange={(event) => setTtl(event.target.value)} inputMode="numeric" />
              </label>
            </div>
            <p className="rounded-[8px] bg-subtle px-2.5 py-2 text-[10.5px] leading-[16px] text-ink3">
              令牌仅可使用一次，绑定集群后 Agent 上报的资产会自动归入该集群。生成后请立即在目标主机执行接入命令。
            </p>
          </>
        ) : (
          <>
            <div className="rounded-[8px] border border-line bg-subtle/50 px-3 py-2.5">
              <p className="text-[10.5px] text-ink3">注册令牌（仅显示一次）</p>
              <div className="mt-1 flex items-center gap-2">
                <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-ink">{token}</code>
                <button type="button" className="btn btn-secondary h-7 px-2 text-[10.5px]" onClick={() => void copy(token, "令牌")}>
                  <Copy size={11} />
                  复制
                </button>
              </div>
              <p className="mt-1.5 text-[10px] text-ink3">有效期至 {expiresAt}</p>
            </div>
            <div className="rounded-[8px] border border-line px-3 py-2.5">
              <p className="text-[10.5px] text-ink3">在目标主机执行</p>
              <div className="mt-1 flex items-start gap-2">
                <code className="min-w-0 flex-1 break-all font-mono text-[10.5px] leading-[16px] text-ink">{command}</code>
                <button type="button" className="btn btn-secondary h-7 shrink-0 px-2 text-[10.5px]" onClick={() => void copy(command, "接入命令")}>
                  <Copy size={11} />
                  复制
                </button>
              </div>
            </div>
            <p className="text-[10.5px] leading-[16px] text-ink3">
              首次运行会换取 Agent ID 与密钥并保存为本机身份文件，后续启动无需再次输入令牌。
            </p>
          </>
        )}
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          {token ? "关闭" : "取消"}
        </button>
        {!token && (
          <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void submit()} disabled={saving}>
            {saving ? <Loader2 size={13} className="animate-spin" /> : <KeyRound size={13} />}
            生成令牌
          </button>
        )}
      </footer>
    </ModalShell>
  );
}

function CommandsDialog({ agent, onClose }: { agent: AgentItem; onClose: () => void }) {
  const toast = useToast();
  const [items, setItems] = useState<AgentCommandItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.agentCommands(agent.id);
      setItems(result.items ?? []);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "读取命令失败", "error");
    } finally {
      setLoading(false);
    }
  }, [agent.id, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function send(action: "ping" | "collect") {
    setBusy(action);
    try {
      await api.createAgentCommand(agent.id, action);
      toast.push("命令已下发", "success");
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "下发命令失败", "error");
    } finally {
      setBusy("");
    }
  }

  return (
    <ModalShell title={`命令历史 · ${agent.name}`} onClose={onClose}>
      <div className="space-y-2 px-5 py-4">
        <div className="flex items-center gap-2">
          <button type="button" className="btn btn-secondary h-7 px-2 text-[11px]" onClick={() => void send("ping")} disabled={busy !== ""}>
            {busy === "ping" ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />}
            Ping
          </button>
          <button type="button" className="btn btn-secondary h-7 px-2 text-[11px]" onClick={() => void send("collect")} disabled={busy !== ""}>
            {busy === "collect" ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
            立即采集
          </button>
          <button type="button" className="btn btn-secondary ml-auto h-7 px-2 text-[11px]" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={11} className={loading ? "animate-spin" : ""} />
            刷新
          </button>
        </div>
        {items.length === 0 ? (
          <Empty title="暂无命令记录" description="下发 Ping 或采集命令后在此查看结果" />
        ) : (
          <div className="max-h-[360px] space-y-1.5 overflow-auto">
            {items.map((item) => {
              const meta = commandStatusMeta[item.status] ?? commandStatusMeta.pending;
              return (
                <div key={item.id} className="rounded-[8px] border border-line px-2.5 py-2 text-[10.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-ink">{item.action}</span>
                    <span className={`rounded-full px-1.5 py-0.5 text-[9.5px] ${meta.className}`}>{meta.label}</span>
                    <span className="text-ink3">{item.requestedBy || "系统"}</span>
                    <span className="ml-auto text-ink3">{item.createdAt}</span>
                  </div>
                  {(item.output || item.error) && (
                    <p className={`mt-1 break-all font-mono text-[10px] ${item.error ? "text-danger" : "text-ink2"}`}>
                      {item.error || item.output}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
      <footer className="flex items-center justify-end border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          关闭
        </button>
      </footer>
    </ModalShell>
  );
}
