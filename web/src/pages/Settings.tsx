import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Bell, History, KeyRound, Lock, Network, Plus, Power, RefreshCw, Save, Send, Settings2, ShieldCheck, Trash2, Upload, UserPlus, Users, X } from "lucide-react";
import { api } from "../lib/api";
import type { AuditItem, ProductMapping, RiskPolicy, SettingsData, SyncSource } from "../lib/types";
import { Badge, Empty, Pagination, Skeleton } from "../components/ui";
import { compactNumber, formatTime, roleMeta, timeAgo } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

type Tab = "policy" | "users" | "sync" | "map" | "notify" | "audit";

const weightMeta: Array<{ key: keyof RiskPolicy["weights"]; label: string; hint: string; color: string }> = [
  { key: "cvss", label: "CVSS 基础分", hint: "漏洞本身严重程度", color: "#FF3B30" },
  { key: "epss", label: "EPSS 利用概率", hint: "未来 30 天被利用概率", color: "#FF9F0A" },
  { key: "exploit", label: "在野利用", hint: "POC / KEV 情报", color: "#0064D6" },
  { key: "asset", label: "资产权重", hint: "暴露面 × 业务等级", color: "#34C759" }
];

export function SettingsPage() {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("policy");
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const [weights, setWeights] = useState<RiskPolicy["weights"]>({ cvss: 0.4, epss: 0.2, exploit: 0.25, asset: 0.15 });
  const [thresholds, setThresholds] = useState<RiskPolicy["thresholds"]>({ p0: 85, p1: 70, p2: 50 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.settings();
      setSettings(result);
      setWeights(result.riskPolicy.weights);
      setThresholds(result.riskPolicy.thresholds);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    void load();
  }, [isAdmin, load]);

  const sum = useMemo(
    () => Number((weights.cvss + weights.epss + weights.exploit + weights.asset).toFixed(3)),
    [weights]
  );
  const valid = Math.abs(sum - 1) < 0.001;

  async function save() {
    if (!valid) {
      toast.push("权重之和必须等于 100%", "error");
      return;
    }
    setSaving(true);
    try {
      const result = await api.updateRiskPolicy({ weights, thresholds });
      toast.push(`策略已保存，已重算 ${result.recomputed} 条漏洞`);
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  }

  if (!isAdmin) {
    return (
      <div className="card">
        <Empty
          title="需要管理员权限"
          description="账号权限、风险策略与审计日志仅对管理员开放。当前账号为只读或运维角色。"
          action={
            <Link to="/" className="btn btn-secondary">
              返回概览
            </Link>
          }
        />
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <div className="card p-5">
          <Skeleton className="h-8 w-56" />
        </div>
        <div className="card p-5">
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  }

  if (error || !settings) {
    return (
      <div className="card">
        <Empty
          title="设置加载失败"
          description={error}
          action={
            <button type="button" className="btn btn-secondary" onClick={() => void load()}>
              重试
            </button>
          }
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card flex items-center gap-1 px-4 py-2.5">
        <TabButton active={tab === "policy"} onClick={() => setTab("policy")} icon={<Settings2 size={14} />}>
          风险策略
        </TabButton>
        <TabButton active={tab === "users"} onClick={() => setTab("users")} icon={<Users size={14} />}>
          账号与角色
        </TabButton>
        <TabButton active={tab === "sync"} onClick={() => setTab("sync")} icon={<RefreshCw size={14} />}>
          情报同步
        </TabButton>
        <TabButton active={tab === "map"} onClick={() => setTab("map")} icon={<Network size={14} />}>
          产品映射
        </TabButton>
        <TabButton active={tab === "notify"} onClick={() => setTab("notify")} icon={<Bell size={14} />}>
          通知
        </TabButton>
        <TabButton active={tab === "audit"} onClick={() => setTab("audit")} icon={<History size={14} />}>
          审计日志
        </TabButton>

        <span className="ml-auto hidden items-center gap-1.5 text-[11px] text-ink3 sm:flex">
          <Lock size={11} />
          仅管理员可见 · 所有修改写审计
        </span>
      </div>

      {tab === "policy" && (
        <div className="grid grid-cols-12 gap-4">
          <section className="card col-span-12 p-5 xl:col-span-7">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-[14px] font-semibold text-ink">风险权重</h2>
                <p className="mt-0.5 text-[11.5px] text-ink3">四项权重之和必须为 100%，调整后立即重算全部漏洞</p>
              </div>
              <span
                className={`pill ${valid ? "bg-[#E9F9EE] text-[#1E7B3C]" : "bg-[#FFECEA] text-[#C4170E]"}`}
              >
                合计 {Math.round(sum * 100)}%
              </span>
            </div>

            <div className="mt-5 flex flex-col gap-4">
              {weightMeta.map((meta) => {
                const value = weights[meta.key];
                return (
                  <div key={meta.key}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="flex items-center gap-2 text-[12.5px] text-ink">
                        <span className="h-2 w-2 rounded-[3px]" style={{ backgroundColor: meta.color }} />
                        {meta.label}
                        <span className="text-[10.5px] text-ink3">{meta.hint}</span>
                      </span>
                      <span className="tabular-nums text-[12.5px] font-semibold text-ink">
                        {Math.round(value * 100)}%
                      </span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={100}
                      step={5}
                      value={Math.round(value * 100)}
                      onChange={(event) =>
                        setWeights((current) => ({ ...current, [meta.key]: Number(event.target.value) / 100 }))
                      }
                      className="range mt-2"
                      style={{
                        background: `linear-gradient(to right, ${meta.color} ${value * 100}%, #E5E5EA ${value * 100}%)`
                      }}
                    />
                  </div>
                );
              })}
            </div>

            <div className="mt-6 border-t border-line pt-4">
              <h3 className="text-[12.5px] font-semibold text-ink">优先级阈值</h3>
              <div className="mt-2.5 grid grid-cols-3 gap-3">
                {(
                  [
                    { key: "p0" as const, label: "P0 严重", color: "#FF3B30" },
                    { key: "p1" as const, label: "P1 高危", color: "#FF9F0A" },
                    { key: "p2" as const, label: "P2 中危", color: "#FFCC00" }
                  ]
                ).map((item) => (
                  <label key={item.key} className="block">
                    <span className="mb-1 flex items-center gap-1.5 text-[11px] text-ink2">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.label} ≥
                    </span>
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={thresholds[item.key]}
                      onChange={(event) =>
                        setThresholds((current) => ({ ...current, [item.key]: Number(event.target.value) }))
                      }
                      className="input h-9 tabular-nums"
                    />
                  </label>
                ))}
              </div>
            </div>

            <div className="mt-5 flex items-center justify-between gap-3">
              <p className="text-[10.5px] leading-[16px] text-ink3">
                公式：100 ×（权重 × 归一化因子）。P0 另有硬规则：CVSS ≥ 9.0 且存在 POC、或 KEV 且公网暴露。
              </p>
              <button type="button" className="btn btn-primary h-9 shrink-0" onClick={() => void save()} disabled={saving || !valid}>
                <Save size={13} />
                {saving ? "保存中…" : "保存并重算"}
              </button>
            </div>
          </section>

          <div className="col-span-12 flex flex-col gap-4 xl:col-span-5">
            <section className="card p-5">
              <h2 className="text-[14px] font-semibold text-ink">当前公式预览</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">按当前权重，P0 的典型构成</p>
              <div className="mt-3 flex flex-col gap-2">
                <PreviewRow label="CVSS 10.0" weight={weights.cvss} raw={1} color="#FF3B30" />
                <PreviewRow label="EPSS 0.94" weight={weights.epss} raw={0.94} color="#FF9F0A" />
                <PreviewRow label="在野利用 KEV" weight={weights.exploit} raw={1} color="#0064D6" />
                <PreviewRow label="资产权重 0.8" weight={weights.asset} raw={0.8} color="#34C759" />
              </div>
              <div className="mt-3 flex items-center justify-between rounded-[10px] bg-subtle px-3 py-2">
                <span className="text-[11.5px] text-ink2">示例综合分</span>
                <span className="text-[15px] font-semibold tabular-nums text-ink">
                  {Math.round(
                    100 *
                      (weights.cvss * 1 + weights.epss * 0.94 + weights.exploit * 1 + weights.asset * 0.8)
                  )}
                </span>
              </div>
            </section>

            <section className="card p-5">
              <h2 className="flex items-center gap-1.5 text-[14px] font-semibold text-ink">
                <ShieldCheck size={14} className="text-ok" />
                构建信息
              </h2>
              <dl className="mt-3 grid grid-cols-2 gap-y-2.5 text-[11.5px]">
                <dt className="text-ink3">版本</dt>
                <dd className="text-right font-mono text-ink">{settings.build.version}</dd>
                <dt className="text-ink3">提交</dt>
                <dd className="text-right font-mono text-ink">{settings.build.commit}</dd>
                <dt className="text-ink3">构建时间</dt>
                <dd className="text-right text-ink">{formatTime(settings.build.builtAt)}</dd>
                <dt className="text-ink3">自身 SBOM</dt>
                <dd className="truncate text-right font-mono text-ink">{settings.build.sbomDigest}</dd>
              </dl>
              <p className="mt-3 border-t border-line pt-3 text-[10.5px] leading-[16px] text-ink3">
                自身依赖同样进入扫描范围，平台自身漏洞会在「自检 · 平台自身」中体现。
              </p>
            </section>
          </div>
        </div>
      )}

      {tab === "users" && <UsersPanel users={settings.users} onChanged={load} />}

      {tab === "audit" && <AuditPanel />}
      {tab === "sync" && <SyncPanel />}
      {tab === "map" && <ProductMapPanel />}
      {tab === "notify" && <NotifyPanel />}
    </div>
  );
}

const notifyLabels: Record<string, string> = {
  "finding.new": "新增 P0/P1 漏洞",
  "ticket.created": "创建工单",
  "sync.failed": "情报同步失败",
  "selfcheck.failed": "平台自检失败"
};

function NotifyPanel() {
  const toast = useToast();
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [secretSet, setSecretSet] = useState(false);
  const [clearSecret, setClearSecret] = useState(false);
  const [events, setEvents] = useState<string[]>([]);
  const [catalog, setCatalog] = useState<string[]>([]);
  const [meta, setMeta] = useState({ lastEvent: "", lastStatus: "", lastError: "", lastSentAt: "" });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await api.notifySettings();
      setUrl(cfg.url);
      setSecretSet(cfg.secretSet);
      setEvents(cfg.events);
      setCatalog(cfg.catalog);
      setMeta({ lastEvent: cfg.lastEvent, lastStatus: cfg.lastStatus, lastError: cfg.lastError, lastSentAt: cfg.lastSentAt });
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "加载通知设置失败", "error");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      await api.updateNotifySettings({
        url: url.trim(),
        secret: secret || undefined,
        clearSecret,
        events
      });
      toast.push("通知设置已保存");
      setSecret("");
      setClearSecret(false);
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    setTesting(true);
    try {
      const result = await api.testNotify();
      toast.push(`测试推送成功（${result.elapsedMs} ms）`);
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "测试推送失败", "error");
      await load();
    } finally {
      setTesting(false);
    }
  }

  function toggleEvent(name: string) {
    setEvents((current) =>
      current.includes(name) ? current.filter((item) => item !== name) : [...current, name]
    );
  }

  if (loading) {
    return (
      <section className="card p-5">
        <Skeleton className="h-40 w-full" />
      </section>
    );
  }

  return (
    <section className="card p-5">
      <header>
        <h2 className="text-[14px] font-semibold text-ink">Webhook 通知</h2>
        <p className="mt-1 text-[11.5px] leading-[18px] text-ink3">
          事件以 JSON POST 推送，带 `X-VulnAgent-Event`；配置密钥后附带
          `X-VulnAgent-Signature: sha256=HMAC(secret, body)`。失败重试 3 次，最后一次结果记录在下方。
        </p>
      </header>

      <div className="mt-4 flex flex-col gap-4">
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">Webhook 地址</span>
          <input
            className="input h-9"
            placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
            value={url}
            onChange={(event) => setUrl(event.target.value)}
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">
            签名密钥{secretSet && !clearSecret ? "（已设置，留空保持不变）" : "（可选）"}
          </span>
          <input
            type="password"
            className="input h-9"
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            placeholder={secretSet ? "••••••••" : "留空则不带签名"}
            autoComplete="new-password"
          />
        </label>
        {secretSet && (
          <label className="flex items-center gap-2 text-[12px] text-ink2">
            <input
              type="checkbox"
              checked={clearSecret}
              onChange={(event) => {
                setClearSecret(event.target.checked);
                if (event.target.checked) setSecret("");
              }}
            />
            清除已保存的密钥
          </label>
        )}

        <div>
          <p className="text-[12px] text-ink2">订阅事件</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {catalog.map((name) => {
              const active = events.includes(name);
              return (
                <button
                  key={name}
                  type="button"
                  onClick={() => toggleEvent(name)}
                  className={`inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[12px] transition-colors ${
                    active
                      ? "border-brand bg-brand-soft text-brand-strong"
                      : "border-line text-ink2 hover:bg-subtle"
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${active ? "bg-brand" : "bg-line"}`} />
                  {notifyLabels[name] ?? name}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn btn-primary h-8" onClick={() => void save()} disabled={saving}>
            <Save size={13} />
            {saving ? "保存中" : "保存设置"}
          </button>
          <button
            type="button"
            className="btn btn-secondary h-8"
            onClick={() => void test()}
            disabled={testing || !url.trim()}
          >
            <Send size={13} />
            {testing ? "推送中" : "发送测试"}
          </button>
          {meta.lastStatus && (
            <span className={`text-[11.5px] ${meta.lastStatus === "ok" ? "text-[#1E7B3C]" : "text-danger"}`}>
              最近推送：{meta.lastEvent} · {meta.lastStatus === "ok" ? "成功" : "失败"} · {formatTime(meta.lastSentAt)}
              {meta.lastError ? ` · ${meta.lastError}` : ""}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

function UsersPanel({
  users,
  onChanged
}: {
  users: SettingsData["users"];
  onChanged: () => Promise<void>;
}) {
  const { user } = useAuth();
  const toast = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [tokenInfo, setTokenInfo] = useState<{ token: string; file: string } | null>(null);

  async function patchUser(username: string, patch: { role?: string; disabled?: boolean }) {
    try {
      await api.updateUser(username, patch);
      toast.push("账号已更新");
      await onChanged();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "更新账号失败", "error");
    }
  }

  async function rotateToken() {
    setRotating(true);
    try {
      const result = await api.rotateAgentToken();
      setTokenInfo({ token: result.token, file: result.file });
      setConfirmRotate(false);
      toast.push("Agent 令牌已轮换，旧令牌立即失效");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "轮换令牌失败", "error");
    } finally {
      setRotating(false);
    }
  }

  async function copyToken() {
    if (!tokenInfo) return;
    try {
      await navigator.clipboard.writeText(tokenInfo.token);
      toast.push("新令牌已复制");
    } catch {
      toast.push("复制失败，请手动选择文本", "error");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="card overflow-hidden">
        <header className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5">
          <div>
            <h2 className="text-[14px] font-semibold text-ink">账号与角色</h2>
            <p className="mt-0.5 text-[11.5px] text-ink3">
              管理员可配置策略与账号；运维可处置漏洞与触发扫描；只读仅可查看。停用或重置口令会立即踢下线。
            </p>
          </div>
          <button type="button" className="btn btn-primary h-8" onClick={() => setCreateOpen(true)}>
            <UserPlus size={13} />
            新建账号
          </button>
        </header>
        <div className="divider" />
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className="th pl-5">姓名</th>
                <th className="th w-[150px]">账号</th>
                <th className="th w-[130px]">角色</th>
                <th className="th w-[160px]">最近登录</th>
                <th className="th w-[90px]">状态</th>
                <th className="th w-[190px] pr-5">操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map((item) => {
                const isSelf = item.username === user?.username;
                return (
                  <tr key={item.username} className="border-b border-line/70 last:border-0">
                    <td className="td pl-5 font-medium">{item.name}</td>
                    <td className="td font-mono text-[11.5px] text-ink2">{item.username}</td>
                    <td className="td">
                      <select
                        className="input h-7 w-[104px] text-[12px]"
                        value={item.role}
                        disabled={isSelf}
                        onChange={(event) => void patchUser(item.username, { role: event.target.value })}
                      >
                        <option value="admin">管理员</option>
                        <option value="operator">运维</option>
                        <option value="viewer">只读</option>
                      </select>
                    </td>
                    <td className="td text-[12px] text-ink2">{formatTime(item.lastLogin)}</td>
                    <td className="td">
                      <span className={`text-[12px] ${item.disabled ? "text-ink3" : "text-[#1E7B3C]"}`}>
                        {item.disabled ? "已停用" : "正常"}
                      </span>
                    </td>
                    <td className="td pr-5">
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          className="btn btn-secondary h-7 px-2 text-[11.5px]"
                          onClick={() => setResetTarget(item.username)}
                        >
                          <KeyRound size={12} />
                          重置口令
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary h-7 px-2 text-[11.5px]"
                          disabled={isSelf}
                          title={isSelf ? "不能停用当前登录账号" : undefined}
                          onClick={() => void patchUser(item.username, { disabled: !item.disabled })}
                        >
                          <Power size={12} />
                          {item.disabled ? "启用" : "停用"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-[14px] font-semibold text-ink">Agent 接入令牌</h2>
            <p className="mt-1 max-w-[560px] text-[11.5px] leading-[18px] text-ink3">
              明文仅保存在数据目录的 <code className="font-mono">agent.token</code>（0600），控制面只存 SHA-256 摘要。
              轮换后旧令牌立即失效，需要同步更新到所有 Agent；通过环境变量 <code className="font-mono">VA_AGENT_TOKEN</code> 指定时不可在控制台轮换。
            </p>
          </div>
          {!confirmRotate && (
            <button type="button" className="btn btn-secondary h-8" onClick={() => setConfirmRotate(true)}>
              <RefreshCw size={13} />
              轮换令牌
            </button>
          )}
        </div>

        {confirmRotate && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-[10px] border border-[#F5C2C0] bg-[#FFF3F2] px-3 py-2.5 text-[12px] text-[#8C1D14]">
            轮换后所有 Agent 需要使用新令牌才能上报，确认继续？
            <button type="button" className="btn btn-primary h-7 px-2.5 text-[11.5px]" disabled={rotating} onClick={() => void rotateToken()}>
              {rotating ? "轮换中" : "确认轮换"}
            </button>
            <button type="button" className="btn btn-secondary h-7 px-2.5 text-[11.5px]" onClick={() => setConfirmRotate(false)}>
              取消
            </button>
          </div>
        )}

        {tokenInfo && (
          <div className="mt-3 rounded-[10px] border border-line bg-subtle px-3 py-2.5">
            <p className="text-[11.5px] text-ink2">新令牌（仅本次展示，请立即保存）</p>
            <div className="mt-1.5 flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded-[6px] bg-surface px-2 py-1 font-mono text-[11.5px] text-ink">
                {tokenInfo.token}
              </code>
              <button type="button" className="btn btn-secondary h-7 px-2 text-[11.5px]" onClick={() => void copyToken()}>
                复制
              </button>
            </div>
            <p className="mt-1.5 font-mono text-[11px] text-ink3">{tokenInfo.file}</p>
          </div>
        )}
      </section>

      {createOpen && (
        <CreateUserDialog
          onClose={() => setCreateOpen(false)}
          onCreated={async () => {
            setCreateOpen(false);
            await onChanged();
          }}
        />
      )}
      {resetTarget && (
        <ResetPasswordDialog
          username={resetTarget}
          onClose={() => setResetTarget(null)}
          onDone={() => setResetTarget(null)}
        />
      )}
    </div>
  );
}

function CreateUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => Promise<void> }) {
  const toast = useToast();
  const [form, setForm] = useState({ username: "", name: "", role: "operator", password: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(form.username)) {
      setError("账号需 3–32 位，仅含字母、数字、点、下划线或短横线");
      return;
    }
    if (!form.name.trim()) {
      setError("姓名不能为空");
      return;
    }
    if (form.password.length < 10 || !/[a-zA-Z]/.test(form.password) || !/[0-9]/.test(form.password)) {
      setError("初始口令至少 10 位，且同时包含字母与数字");
      return;
    }
    setBusy(true);
    try {
      await api.createUser({ ...form, name: form.name.trim() });
      toast.push("账号已创建");
      await onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建账号失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalShell title="新建账号" subtitle="创建后请通过安全渠道交付初始口令" onClose={onClose} busy={busy}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">账号</span>
          <input className="input h-9" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} required />
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">姓名</span>
          <input className="input h-9" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">角色</span>
          <select className="input h-9" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
            <option value="admin">管理员</option>
            <option value="operator">运维</option>
            <option value="viewer">只读</option>
          </select>
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">初始口令</span>
          <input
            type="password"
            className="input h-9"
            value={form.password}
            onChange={(event) => setForm({ ...form, password: event.target.value })}
            autoComplete="new-password"
            required
          />
        </label>
        {error && <p className="text-[12px] text-danger">{error}</p>}
        <div className="mt-1 flex justify-end gap-2">
          <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button type="submit" className="btn btn-primary h-8" disabled={busy}>
            {busy ? "创建中" : "创建"}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

function ResetPasswordDialog({ username, onClose, onDone }: { username: string; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (password.length < 10 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      setError("口令至少 10 位，且同时包含字母与数字");
      return;
    }
    setBusy(true);
    try {
      await api.resetUserPassword(username, password);
      toast.push(`已重置 ${username} 的口令，该账号会话已下线`);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "重置口令失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalShell title={`重置口令 · ${username}`} subtitle="重置后该账号所有会话立即失效" onClose={onClose} busy={busy}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-ink2">新口令</span>
          <input
            type="password"
            className="input h-9"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
            required
          />
        </label>
        {error && <p className="text-[12px] text-danger">{error}</p>}
        <div className="mt-1 flex justify-end gap-2">
          <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button type="submit" className="btn btn-primary h-8" disabled={busy}>
            {busy ? "提交中" : "确认重置"}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

function ModalShell({
  title,
  subtitle,
  busy,
  onClose,
  children
}: {
  title: string;
  subtitle: string;
  busy: boolean;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-[65] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="关闭"
        className="animate-fade absolute inset-0 bg-[#1D1D1F]/25 backdrop-blur-[2px]"
        onClick={() => !busy && onClose()}
      />
      <div className="animate-rise relative w-full max-w-[400px] overflow-hidden rounded-card border border-line bg-surface shadow-float">
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div>
            <h2 className="text-[14.5px] font-semibold text-ink">{title}</h2>
            <p className="mt-0.5 text-[11.5px] text-ink3">{subtitle}</p>
          </div>
          <button
            type="button"
            onClick={() => !busy && onClose()}
            className="rounded-[8px] p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
            aria-label="关闭"
          >
            <X size={15} />
          </button>
        </header>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  );
}

function PreviewRow({
  label,
  weight,
  raw,
  color
}: {
  label: string;
  weight: number;
  raw: number;
  color: string;
}) {
  const contribution = weight * raw * 100;
  return (
    <div className="flex items-center gap-2.5">
      <span className="w-[104px] shrink-0 text-[11.5px] text-ink2">{label}</span>
      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-line">
        <span
          className="block h-full rounded-full"
          style={{ width: `${Math.min(100, contribution * 2.5)}%`, backgroundColor: color }}
        />
      </span>
      <span className="w-8 text-right text-[11px] tabular-nums text-ink2">{contribution.toFixed(1)}</span>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
  icon
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  icon: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex h-8 items-center gap-1.5 rounded-[8px] px-3 text-[12.5px] font-medium transition-colors ${
        active ? "bg-subtle text-ink" : "text-ink2 hover:text-ink"
      }`}
    >
      {icon}
      {children}
    </button>
  );
}

const ecoOptions = ["deb", "rpm", "apk", "npm", "maven", "golang", "pypi", "nuget", "oci", "generic"];

function ProductMapPanel() {
  const toast = useToast();
  const [items, setItems] = useState<ProductMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [eco, setEco] = useState("deb");
  const [name, setName] = useState("");
  const [product, setProduct] = useState("");
  const [confidence, setConfidence] = useState("1.0");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async (keyword: string) => {
    setLoading(true);
    try {
      const result = await api.productMap(keyword || undefined);
      setItems(result.items ?? []);
    } catch {
      /* 保留上次结果 */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(q.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [q, load]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim() || !product.trim()) {
      toast.push("组件名与映射产品不能为空", "error");
      return;
    }
    const value = Number(confidence);
    if (Number.isNaN(value) || value < 0 || value > 1) {
      toast.push("置信度需在 0 与 1 之间", "error");
      return;
    }
    setSaving(true);
    try {
      const result = await api.upsertProductMap({
        eco,
        name: name.trim(),
        product: product.trim(),
        confidence: value
      });
      toast.push(`映射已保存，重新匹配 ${result.rematched} 台资产`);
      setName("");
      setProduct("");
      await load(q.trim());
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  }

  async function remove(item: ProductMapping) {
    try {
      const result = await api.deleteProductMap(item.eco, item.name);
      toast.push(`已删除映射，重新匹配 ${result.rematched} 台资产`);
      await load(q.trim());
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "删除失败", "error");
    }
  }

  return (
    <section className="card overflow-hidden">
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5">
        <div>
          <h2 className="text-[14px] font-semibold text-ink">产品映射</h2>
          <p className="mt-0.5 text-[11.5px] leading-[17px] text-ink3">
            把发行版包名映射到漏洞库产品名（如 <code className="font-mono">python3-requests → requests</code>），保存后自动重新匹配全部资产。
          </p>
        </div>
        <label className="relative">
          <input
            value={q}
            onChange={(event) => setQ(event.target.value)}
            placeholder="搜索组件 / 产品 / 生态"
            className="input h-8 w-[220px] text-[12.5px]"
          />
        </label>
      </header>

      <div className="border-y border-line bg-subtle/40 px-5 py-3">
        <form onSubmit={save} className="flex flex-wrap items-end gap-2">
          <label className="block">
            <span className="mb-1 block text-[10.5px] text-ink3">生态</span>
            <select
              value={eco}
              onChange={(event) => setEco(event.target.value)}
              className="input h-8 w-[104px] appearance-none text-[12.5px]"
            >
              {ecoOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-[10.5px] text-ink3">组件名</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="python3-requests"
              className="input h-8 w-[180px] font-mono text-[11.5px]"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[10.5px] text-ink3">映射产品</span>
            <input
              value={product}
              onChange={(event) => setProduct(event.target.value)}
              placeholder="requests"
              className="input h-8 w-[160px] font-mono text-[11.5px]"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[10.5px] text-ink3">置信度</span>
            <input
              value={confidence}
              onChange={(event) => setConfidence(event.target.value)}
              className="input h-8 w-[76px] tabular-nums text-[12px]"
            />
          </label>
          <button type="submit" className="btn btn-primary h-8" disabled={saving}>
            <Plus size={13} />
            {saving ? "保存中…" : "保存映射"}
          </button>
        </form>
      </div>

      {loading ? (
        <div className="flex flex-col gap-2 p-5">
          {[0, 1, 2].map((key) => (
            <Skeleton key={key} className="h-9 w-full" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <Empty title="没有匹配的映射" description="调整搜索条件，或在上方新增一条映射。" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className="th w-[90px] pl-5">生态</th>
                <th className="th">组件名</th>
                <th className="th">映射产品</th>
                <th className="th w-[90px] text-right">置信度</th>
                <th className="th w-[100px]">来源</th>
                <th className="th w-[90px] pr-5 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={`${item.eco}-${item.name}`} className="border-b border-line/70 last:border-0 hover:bg-subtle/60">
                  <td className="td pl-5">
                    <span className="pill bg-subtle text-ink2">{item.eco}</span>
                  </td>
                  <td className="td font-mono text-[11.5px] text-ink">{item.name}</td>
                  <td className="td font-mono text-[11.5px] text-ink2">{item.product}</td>
                  <td className="td text-right tabular-nums text-ink2">{item.confidence.toFixed(1)}</td>
                  <td className="td">
                    <Badge tone={item.source === "builtin" ? "neutral" : "brand"}>
                      {item.source === "builtin" ? "内置" : "手动"}
                    </Badge>
                  </td>
                  <td className="td pr-5 text-right">
                    <button
                      type="button"
                      onClick={() => void remove(item)}
                      className="inline-flex items-center gap-1 rounded-[7px] px-1.5 py-1 text-[11.5px] text-ink3 transition-colors hover:bg-[#FFECEA] hover:text-[#C4170E]"
                    >
                      <Trash2 size={12} />
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="px-5 py-3 text-[10.5px] leading-[16px] text-ink3">
        命中映射的结论会标记为「映射推断」，可在漏洞详情中查看；删除内置映射后重启不会自动恢复。
      </p>
    </section>
  );
}

function SyncPanel() {
  const toast = useToast();
  const [sources, setSources] = useState<SyncSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [osvScanning, setOsvScanning] = useState(false);
  const [importing, setImporting] = useState(false);
  const [refreshingEPSS, setRefreshingEPSS] = useState(false);
  const [fileName, setFileName] = useState("");
  const fileRef = useRef<HTMLInputElement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.syncStatus();
      setSources(result.sources ?? []);
    } catch {
      /* 保留上次结果 */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function syncCVE() {
    if (syncing) return;
    setSyncing(true);
    try {
      const result = await api.triggerSync("cve");
      toast.push(`CVE 情报同步完成：新增 ${result.inserted} 条 · 更新 ${result.updated} 条`);
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "同步失败", "error");
    } finally {
      setSyncing(false);
    }
  }

  async function importEPSS() {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      toast.push("请先选择 EPSS CSV 文件", "error");
      return;
    }
    setImporting(true);
    try {
      const result = await api.uploadEPSS(file);
      toast.push(
        `EPSS 导入完成：命中 ${result.matched} 条 · 未命中 ${result.unmatched} 条 · 重算 ${result.recomputed} 条`
      );
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "导入失败", "error");
    } finally {
      setImporting(false);
    }
  }

  async function refreshEPSS() {
    if (refreshingEPSS) return;
    setRefreshingEPSS(true);
    try {
      const result = await api.refreshEPSS();
      toast.push(
        `EPSS 在线刷新完成：读取 ${result.rows} 行 · 命中 ${result.matched} 条 · 重算 ${result.recomputed} 条`
      );
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "EPSS 在线刷新失败", "error");
    } finally {
      setRefreshingEPSS(false);
    }
  }

  async function scanOSV() {
    if (osvScanning) return;
    setOsvScanning(true);
    try {
      const result = await api.triggerOSV({ all: true });
      toast.push(
        `OSV 匹配完成：${result.assets} 台资产 · ${result.queried} 个组件 · 命中 ${result.vulns} 条 · 新增 ${result.created} 条`
      );
      await load();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "OSV 匹配失败", "error");
    } finally {
      setOsvScanning(false);
    }
  }

  return (
    <div className="grid grid-cols-12 gap-4">
      <section className="card col-span-12 p-5 xl:col-span-7">
        <h2 className="text-[14px] font-semibold text-ink">情报源状态</h2>
        <p className="mt-0.5 text-[11.5px] text-ink3">同步成功后会自动刷新概览与自检中的滞后判断</p>

        <div className="mt-4 flex flex-col">
          {loading && sources.length === 0
            ? [0, 1, 2].map((key) => <Skeleton key={key} className="mb-3 h-10 w-full" />)
            : sources.map((source) => {
                const color =
                  source.status === "ok" ? "#34C759" : source.status === "warn" ? "#FF9F0A" : "#FF3B30";
                const label =
                  source.source === "cve" ? "CVE 情报" : source.source === "poc" ? "POC 情报" : "EPSS";
                return (
                  <div
                    key={source.source}
                    className="flex items-center justify-between gap-3 border-b border-line/70 py-3 last:border-0"
                  >
                    <span className="inline-flex items-center gap-2 text-[12.5px] text-ink">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                      {label}
                      {source.status !== "ok" && (
                        <span className="text-[10.5px] text-ink3">{source.status === "warn" ? "告警" : "失败"}</span>
                      )}
                    </span>
                    <span className="flex items-center gap-2 text-[11.5px] text-ink3">
                      <span className="tabular-nums">{compactNumber(source.count)} 条</span>
                      <span className="h-3 w-px bg-line" />
                      <span>{source.lastRunAt ? timeAgo(source.lastRunAt) : "从未"}</span>
                    </span>
                  </div>
                );
              })}
        </div>

        <div className="mt-4 border-t border-line pt-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-[12.5px] font-semibold text-ink">在线增量同步 · CVE / POC</h3>
              <p className="mt-0.5 text-[11px] leading-[17px] text-ink3">
                情报平台公开接口免费，无需 Key；若平台后续要求鉴权，可在服务端配置{" "}
                <code className="font-mono">VULNAGENT_CVE_API_KEY</code>。按更新时间游标翻页，失败自动退避重试。
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                className="btn btn-secondary h-8"
                onClick={() => void scanOSV()}
                disabled={osvScanning}
                title="对 Go / npm / PyPI / Maven / NuGet / Debian / Alpine 组件做精确版本匹配"
              >
                <RefreshCw size={12.5} className={osvScanning ? "animate-spin" : ""} />
                {osvScanning ? "匹配中…" : "OSV 匹配"}
              </button>
              <button type="button" className="btn btn-secondary h-8 shrink-0" onClick={() => void syncCVE()} disabled={syncing}>
                <RefreshCw size={12.5} className={syncing ? "animate-spin" : ""} />
                {syncing ? "同步中…" : "同步 CVE"}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="card col-span-12 p-5 xl:col-span-5">
        <h2 className="text-[14px] font-semibold text-ink">导入 EPSS</h2>
        <p className="mt-0.5 text-[11.5px] leading-[17px] text-ink3">
          FIRST 格式 CSV（<code className="font-mono">cve,epss,percentile</code>）。导入后把最新分值同步到漏洞快照，并按当前风险策略重算排序。
        </p>

        <div className="mt-3 flex items-center justify-between gap-3 rounded-[10px] border border-line bg-subtle px-3 py-2.5">
          <div>
            <p className="text-[12px] text-ink">从 FIRST 在线刷新</p>
            <p className="mt-0.5 text-[10.5px] text-ink3">下载全量 EPSS（gzip CSV），耗时取决于网络</p>
          </div>
          <button
            type="button"
            className="btn btn-secondary h-7 shrink-0 px-2.5 text-[11.5px]"
            onClick={() => void refreshEPSS()}
            disabled={refreshingEPSS}
          >
            <RefreshCw size={12} className={refreshingEPSS ? "animate-spin" : ""} />
            {refreshingEPSS ? "拉取中" : "在线刷新"}
          </button>
        </div>

        <input
          ref={fileRef}
          type="file"
          accept=".csv,text/csv"
          className="sr-only"
          onChange={(event) => setFileName(event.target.files?.[0]?.name ?? "")}
        />

        <div className="mt-4 rounded-panel border border-dashed border-lineStrong px-3 py-4 text-center">
          <Upload size={18} className="mx-auto text-ink3" />
          <p className="mt-1.5 text-[12px] text-ink2">{fileName || "选择一个 .csv 文件"}</p>
          <div className="mt-2.5 flex items-center justify-center gap-2">
            <button type="button" className="btn btn-secondary h-8" onClick={() => fileRef.current?.click()}>
              选择文件
            </button>
            <button type="button" className="btn btn-primary h-8" onClick={() => void importEPSS()} disabled={importing || !fileName}>
              {importing ? "导入中…" : "开始导入"}
            </button>
          </div>
        </div>

        <p className="mt-3 text-[10.5px] leading-[16px] text-ink3">
          仅更新库内已存在的 CVE；未知 CVE 会被跳过并在结果中计数。文件上限 64MB。
        </p>
      </section>
    </div>
  );
}

function AuditPanel() {
  const [items, setItems] = useState<AuditItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const pageSize = 14;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.auditLogs({ page, pageSize });
      setItems(result.items ?? []);
      setTotal(result.total);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="card overflow-hidden">
      <header className="flex items-center justify-between px-5 py-3.5">
        <div>
          <h2 className="text-[14px] font-semibold text-ink">审计日志</h2>
          <p className="mt-0.5 text-[11.5px] text-ink3">登录、扫描、状态变更、导出与策略调整全部留痕</p>
        </div>
        <span className="text-[11px] text-ink3">共 {total} 条</span>
      </header>
      <div className="divider" />

      {loading ? (
        <div className="flex flex-col gap-2 p-5">
          {[0, 1, 2, 3, 4, 5].map((key) => (
            <Skeleton key={key} className="h-10 w-full" />
          ))}
        </div>
      ) : error ? (
        <Empty title="审计日志加载失败" description={error} action={
          <button type="button" className="btn btn-secondary" onClick={() => void load()}>
            重试
          </button>
        } />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className="th w-[150px] pl-5">时间</th>
                <th className="th w-[150px]">操作人</th>
                <th className="th w-[90px]">角色</th>
                <th className="th w-[150px]">动作</th>
                <th className="th">对象</th>
                <th className="th w-[130px]">来源 IP</th>
                <th className="th w-[200px] pr-5">说明</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-b border-line/70 last:border-0 hover:bg-subtle/60">
                  <td className="td pl-5 text-[11.5px] text-ink2">{formatTime(item.time)}</td>
                  <td className="td whitespace-nowrap text-[12px]">{item.actor}</td>
                  <td className="td text-[11.5px] text-ink3">{roleMeta[item.role] ?? item.role}</td>
                  <td className="td">
                    <span className="font-mono text-[11px] text-ink2">{item.action}</span>
                  </td>
                  <td className="td max-w-[240px] truncate text-[12px] text-ink">{item.target}</td>
                  <td className="td font-mono text-[11px] text-ink3">{item.ip}</td>
                  <td className="td max-w-[220px] truncate pr-5 text-[11.5px] text-ink3">{item.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && items.length > 0 && (
        <>
          <div className="divider" />
          <Pagination page={page} pageSize={pageSize} total={total} onChange={setPage} />
        </>
      )}
    </section>
  );
}
