import { useCallback, useEffect, useState } from "react";
import {
  Check,
  CloudCog,
  Database,
  FlaskConical,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  X
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { IntegrationSource, IntegrationTestResult } from "../lib/types";
import { Badge, Empty, Skeleton } from "../components/ui";
import { timeAgo } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const kindMeta: Record<string, { label: string; hint: string; icon: typeof CloudCog }> = {
  cloud_aliyun: { label: "阿里云 ECS", hint: "DescribeInstances 只读拉取", icon: CloudCog },
  cloud_aws: { label: "AWS EC2", hint: "DescribeInstances 只读拉取", icon: CloudCog },
  cloud_azure: { label: "Azure VM", hint: "ARM 虚拟机列表只读拉取", icon: CloudCog },
  cmdb_api: { label: "外部 CMDB API", hint: "JSON API 只读拉取", icon: Database }
};

const statusMeta: Record<string, { label: string; tone: "neutral" | "success" | "warn" | "danger" }> = {
  "": { label: "未同步", tone: "neutral" },
  ok: { label: "成功", tone: "success" },
  partial: { label: "部分失败", tone: "warn" },
  failed: { label: "失败", tone: "danger" }
};

interface CredentialField {
  key: string;
  label: string;
}

function credentialFields(kind: string, authType: string): CredentialField[] {
  switch (kind) {
    case "cloud_aliyun":
      return [
        { key: "accessKeyId", label: "AccessKey ID" },
        { key: "accessKeySecret", label: "AccessKey Secret" }
      ];
    case "cloud_aws":
      return [
        { key: "accessKeyId", label: "AccessKey ID" },
        { key: "secretAccessKey", label: "Secret Access Key" }
      ];
    case "cloud_azure":
      return [
        { key: "tenantId", label: "Tenant ID" },
        { key: "clientId", label: "Client ID" },
        { key: "clientSecret", label: "Client Secret" }
      ];
    case "cmdb_api":
      if (authType === "bearer") return [{ key: "token", label: "Bearer Token" }];
      if (authType === "basic") {
        return [
          { key: "username", label: "用户名" },
          { key: "password", label: "口令" }
        ];
      }
      return [];
    default:
      return [];
  }
}

function configSummary(source: IntegrationSource): string {
  const config = source.config ?? {};
  if (source.kind === "cmdb_api") {
    return String(config.url ?? "");
  }
  const parts = [String(config.region ?? ""), String(config.subscriptionId ?? "")].filter(Boolean);
  return parts.join(" · ") || "未配置区域";
}

export function IntegrationsPage() {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const [items, setItems] = useState<IntegrationSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<IntegrationSource | null>(null);
  const [busy, setBusy] = useState("");
  const [deleting, setDeleting] = useState<number | null>(null);
  const [testResults, setTestResults] = useState<Record<number, IntegrationTestResult>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.integrations();
      setItems(result.items ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载集成源失败");
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

  const toggleEnabled = async (source: IntegrationSource, enabled: boolean) => {
    setBusy(`toggle-${source.id}`);
    try {
      await api.updateIntegration(source.id, { enabled });
      await load();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "更新失败", "error");
    } finally {
      setBusy("");
    }
  };

  const runTest = async (source: IntegrationSource) => {
    setBusy(`test-${source.id}`);
    try {
      const result = await api.testIntegration(source.id);
      setTestResults((prev) => ({ ...prev, [source.id]: result }));
      if (result.ok) {
        toast.push(`连接成功：读取 ${result.count ?? 0} 台`, "success");
      } else {
        toast.push(result.error || "连接失败", "error");
      }
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "连接测试失败", "error");
    } finally {
      setBusy("");
    }
  };

  const runSync = async (source: IntegrationSource) => {
    setBusy(`sync-${source.id}`);
    try {
      const result = await api.syncIntegration(source.id);
      if (result.ok && result.stats) {
        toast.push(
          `同步完成：拉取 ${result.stats.fetched} · 新增 ${result.stats.created} · 更新 ${result.stats.updated} · 未变 ${result.stats.unchanged}`,
          "success"
        );
      } else {
        toast.push(result.error || (result.stats?.failed ? `${result.stats.failed} 台处理失败` : "同步失败"), "error");
      }
      await load();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "同步失败", "error");
    } finally {
      setBusy("");
    }
  };

  const remove = async (id: number) => {
    setBusy(`delete-${id}`);
    try {
      await api.deleteIntegration(id);
      toast.push("集成源已删除", "info");
      setDeleting(null);
      await load();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "删除失败", "error");
    } finally {
      setBusy("");
    }
  };

  if (!isAdmin) {
    return (
      <div className="card">
        <Empty title="仅管理员可配置集成" description="云厂商与外部 CMDB 同步涉及凭据管理，请使用 admin 账号。" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <CloudCog size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">云厂商与外部 CMDB</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">
                只读拉取实例与资产标签，按实例 ID / 序列号 / MAC / 主机名 / IP 归并到资产台账；凭据 AES-256-GCM 加密存储
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" className="btn btn-secondary h-8 px-2.5" onClick={() => void load()} aria-label="刷新">
              <RefreshCw size={13} />
            </button>
            <button type="button" className="btn btn-primary h-8" onClick={() => { setEditing(null); setModalOpen(true); }}>
              <Plus size={13} />
              新增集成
            </button>
          </div>
        </div>
        <div className="divider" />

        {loading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2].map((key) => <Skeleton key={key} className="h-16 w-full" />)}
          </div>
        ) : error ? (
          <Empty title="加载失败" description={error} action={
            <button type="button" className="btn btn-secondary h-8" onClick={() => void load()}>重试</button>
          } />
        ) : items.length === 0 ? (
          <Empty
            title="尚未配置集成源"
            description="添加阿里云 / AWS / Azure 账号或外部 CMDB 的 JSON API，即可定时把实例同步为资产。"
            action={
              <button type="button" className="btn btn-primary h-8" onClick={() => { setEditing(null); setModalOpen(true); }}>
                <Plus size={13} />
                新增集成
              </button>
            }
          />
        ) : (
          <div className="divide-y divide-line">
            {items.map((source) => {
              const meta = kindMeta[source.kind] ?? kindMeta.cmdb_api;
              const Icon = meta.icon;
              const status = statusMeta[source.lastStatus] ?? statusMeta[""];
              const test = testResults[source.id];
              return (
                <div key={source.id} className="px-5 py-3.5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-2.5">
                      <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-subtle text-ink2">
                        <Icon size={15} />
                      </span>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[13px] font-semibold text-ink">{source.name}</span>
                          <Badge tone="neutral">{meta.label}</Badge>
                          <Badge tone={status.tone}>{status.label}</Badge>
                          {!source.enabled && <span className="text-[10.5px] text-ink3">已停用</span>}
                        </div>
                        <p className="mt-0.5 truncate font-mono text-[10.5px] text-ink3">{configSummary(source)}</p>
                        <p className="mt-1 text-[10.5px] text-ink3">
                          每 {source.intervalMinutes} 分钟 ·{" "}
                          {source.lastRunAt ? `${timeAgo(source.lastRunAt)}同步 ${source.lastCount} 台` : "尚未同步"}
                          {source.lastError ? ` · ${source.lastError}` : ""}
                        </p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <label className="mr-1 inline-flex items-center gap-1.5 text-[11px] text-ink2">
                        <input
                          type="checkbox"
                          checked={source.enabled}
                          disabled={busy === `toggle-${source.id}`}
                          onChange={(event) => void toggleEnabled(source, event.target.checked)}
                        />
                        启用
                      </label>
                      <button
                        type="button"
                        className="btn btn-secondary h-7 px-2 text-[11px]"
                        onClick={() => void runTest(source)}
                        disabled={Boolean(busy)}
                      >
                        {busy === `test-${source.id}` ? <Loader2 size={11} className="animate-spin" /> : <FlaskConical size={11} />}
                        测试
                      </button>
                      <button
                        type="button"
                        className="btn btn-primary h-7 px-2 text-[11px]"
                        onClick={() => void runSync(source)}
                        disabled={Boolean(busy)}
                      >
                        {busy === `sync-${source.id}` ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
                        同步
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost h-7 px-2 text-[11px]"
                        onClick={() => { setEditing(source); setModalOpen(true); }}
                      >
                        <Pencil size={11} />
                        编辑
                      </button>
                      {deleting === source.id ? (
                        <>
                          <button
                            type="button"
                            className="btn btn-secondary h-7 px-2 text-[11px] text-[#C4170E]"
                            onClick={() => void remove(source.id)}
                            disabled={busy === `delete-${source.id}`}
                          >
                            确认删除
                          </button>
                          <button type="button" className="btn btn-ghost h-7 px-2 text-[11px]" onClick={() => setDeleting(null)}>
                            取消
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-ghost h-7 px-2 text-[11px] text-ink3"
                          onClick={() => setDeleting(source.id)}
                        >
                          <Trash2 size={11} />
                        </button>
                      )}
                    </div>
                  </div>

                  {test && (
                    <div className={`mt-2 rounded-[8px] px-3 py-2 text-[11px] ${test.ok ? "bg-[#E8F7EE] text-[#1E7B3C]" : "bg-[#FFECEA] text-[#C4170E]"}`}>
                      {test.ok ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex items-center gap-1">
                            <Check size={11} /> 读取 {test.count ?? 0} 台
                          </span>
                          <span className="text-[10px] opacity-70">{test.elapsedMs ?? 0} ms</span>
                          {(test.sample ?? []).slice(0, 5).map((sample) => (
                            <span key={`${sample.instanceId}-${sample.hostname}`} className="pill bg-white/70 text-[10px] text-[#1E7B3C]">
                              {sample.hostname || sample.name || sample.instanceId}
                              {sample.privateIp ? ` · ${sample.privateIp}` : ""}
                            </span>
                          ))}
                        </div>
                      ) : (
                        test.error
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      <p className="px-1 text-[11px] text-ink3">
        同步只读取云端实例列表，不会创建、修改或删除云资源；资产侧以 <code className="font-mono">source=cloud</code> 落库，
        显式关系与人工维护的字段不会被覆盖为空值。定时任务每 5 分钟检查一次到期集成源。
      </p>

      <IntegrationDialog
        open={modalOpen}
        editing={editing}
        onClose={() => setModalOpen(false)}
        onSaved={() => {
          setModalOpen(false);
          void load();
        }}
      />
    </div>
  );
}

function IntegrationDialog({
  open,
  editing,
  onClose,
  onSaved
}: {
  open: boolean;
  editing: IntegrationSource | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [kind, setKind] = useState("cloud_aliyun");
  const [name, setName] = useState("");
  const [region, setRegion] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [url, setUrl] = useState("");
  const [authType, setAuthType] = useState("none");
  const [pagination, setPagination] = useState("auto");
  const [pageParam, setPageParam] = useState("page");
  const [pageSize, setPageSize] = useState("200");
  const [cursorParam, setCursorParam] = useState("cursor");
  const [maxPages, setMaxPages] = useState("50");
  const [intervalMinutes, setIntervalMinutes] = useState("360");
  const [enabled, setEnabled] = useState(true);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [clearSecret, setClearSecret] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    const config = editing?.config ?? {};
    setKind(editing?.kind ?? "cloud_aliyun");
    setName(editing?.name ?? "");
    setRegion(String(config.region ?? ""));
    setEndpoint(String(config.endpoint ?? ""));
    setSubscriptionId(String(config.subscriptionId ?? ""));
    setUrl(String(config.url ?? ""));
    setAuthType(String(config.authType ?? "none"));
    setPagination(String(config.pagination ?? "auto"));
    setPageParam(String(config.pageParam ?? "page"));
    setPageSize(String(config.pageSize ?? 200));
    setCursorParam(String(config.cursorParam ?? "cursor"));
    setMaxPages(String(config.maxPages ?? 50));
    setIntervalMinutes(String(editing?.intervalMinutes ?? 360));
    setEnabled(editing?.enabled ?? true);
    setCredentials({});
    setClearSecret(false);
    setError("");
  }, [open, editing]);

  if (!open) return null;

  const fields = credentialFields(kind, authType);

  const submit = async () => {
    if (!name.trim()) {
      setError("请填写名称");
      return;
    }
    const config: Record<string, unknown> = {};
    if (kind === "cmdb_api") {
      if (!url.trim()) {
        setError("请填写 JSON API 地址");
        return;
      }
      config.url = url.trim();
      config.authType = authType;
      if (pagination !== "auto") config.pagination = pagination;
      if (pagination === "page") {
        config.pageParam = pageParam.trim() || "page";
        config.pageSize = Number(pageSize) || 200;
      }
      if (pagination === "auto" || pagination === "cursor") {
        if (cursorParam.trim() && cursorParam.trim() !== "cursor") config.cursorParam = cursorParam.trim();
      }
      const pages = Number(maxPages);
      if (Number.isFinite(pages) && pages > 0 && pages !== 50) config.maxPages = pages;
    } else {
      if (!region.trim()) {
        setError("请填写 region");
        return;
      }
      config.region = region.trim();
      if (endpoint.trim()) config.endpoint = endpoint.trim();
      if (kind === "cloud_azure") {
        if (!subscriptionId.trim()) {
          setError("请填写 subscriptionId");
          return;
        }
        config.subscriptionId = subscriptionId.trim();
      }
    }
    const filled: Record<string, string> = {};
    Object.entries(credentials).forEach(([key, value]) => {
      if (value.trim() !== "") filled[key] = value.trim();
    });
    if (!editing || (!editing.hasCredential && Object.keys(filled).length === 0)) {
      if (fields.length > 0 && Object.keys(filled).length === 0) {
        setError("请填写凭据");
        return;
      }
    }
    setSaving(true);
    setError("");
    try {
      if (editing) {
        await api.updateIntegration(editing.id, {
          name: name.trim(),
          config,
          credentials: Object.keys(filled).length > 0 ? filled : undefined,
          enabled,
          intervalMinutes: Number(intervalMinutes) || 360,
          clearSecret
        });
        toast.push("集成源已更新", "success");
      } else {
        await api.createIntegration({
          kind,
          name: name.trim(),
          config,
          credentials: Object.keys(filled).length > 0 ? filled : undefined,
          enabled,
          intervalMinutes: Number(intervalMinutes) || 360
        });
        toast.push("集成源已创建", "success");
      }
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <button type="button" aria-label="关闭" className="animate-fade absolute inset-0 bg-[#1D1D1F]/25 backdrop-blur-[2px]" onClick={onClose} />
      <div className="animate-rise relative flex max-h-[calc(100vh-48px)] w-full max-w-[560px] flex-col overflow-hidden rounded-card border border-line bg-surface shadow-float">
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <ShieldCheck size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">{editing ? "编辑集成源" : "新增集成源"}</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">凭据加密存储，仅用于只读拉取</p>
            </div>
          </div>
          <button type="button" className="rounded-full p-1.5 text-ink3 hover:bg-subtle hover:text-ink" onClick={onClose} aria-label="关闭">
            <X size={16} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">类型</span>
              <select className="input h-9 text-[12.5px]" value={kind} disabled={Boolean(editing)}
                onChange={(event) => { setKind(event.target.value); setCredentials({}); }}>
                {Object.entries(kindMeta).map(([value, meta]) => (
                  <option key={value} value={value}>{meta.label}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">名称</span>
              <input className="input h-9 text-[12.5px]" value={name} onChange={(event) => setName(event.target.value)} placeholder="生产账号" />
            </label>

            {kind !== "cmdb_api" && (
              <>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">Region</span>
                  <input className="input h-9 font-mono text-[12px]" value={region} onChange={(event) => setRegion(event.target.value)} placeholder="cn-hangzhou / us-east-1" />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">Endpoint（可选）</span>
                  <input className="input h-9 font-mono text-[12px]" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="私有云 / 代理地址" />
                </label>
              </>
            )}
            {kind === "cloud_azure" && (
              <label className="block sm:col-span-2">
                <span className="mb-1 block text-[11px] text-ink3">Subscription ID</span>
                <input className="input h-9 font-mono text-[12px]" value={subscriptionId} onChange={(event) => setSubscriptionId(event.target.value)} />
              </label>
            )}
            {kind === "cmdb_api" && (
              <>
                <label className="block sm:col-span-2">
                  <span className="mb-1 block text-[11px] text-ink3">JSON API 地址</span>
                  <input className="input h-9 font-mono text-[12px]" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://cmdb.example.com/api/assets" />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">认证方式</span>
                  <select className="input h-9 text-[12.5px]" value={authType} onChange={(event) => { setAuthType(event.target.value); setCredentials({}); }}>
                    <option value="none">无</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="basic">Basic Auth</option>
                  </select>
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">分页方式</span>
                  <select className="input h-9 text-[12.5px]" value={pagination} onChange={(event) => setPagination(event.target.value)}>
                    <option value="auto">自动（跟随 next）</option>
                    <option value="none">单页</option>
                    <option value="page">页码</option>
                    <option value="cursor">游标</option>
                  </select>
                </label>
                {pagination === "page" && (
                  <>
                    <label className="block">
                      <span className="mb-1 block text-[11px] text-ink3">页码参数</span>
                      <input className="input h-9 font-mono text-[12px]" value={pageParam} onChange={(event) => setPageParam(event.target.value)} placeholder="page" />
                    </label>
                    <label className="block">
                      <span className="mb-1 block text-[11px] text-ink3">每页条数</span>
                      <input className="input h-9 font-mono text-[12px]" inputMode="numeric" value={pageSize}
                        onChange={(event) => setPageSize(event.target.value.replace(/[^0-9]/g, ""))} placeholder="200" />
                    </label>
                  </>
                )}
                {(pagination === "auto" || pagination === "cursor") && (
                  <label className="block">
                    <span className="mb-1 block text-[11px] text-ink3">游标参数</span>
                    <input className="input h-9 font-mono text-[12px]" value={cursorParam} onChange={(event) => setCursorParam(event.target.value)} placeholder="cursor" />
                  </label>
                )}
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">最大翻页数</span>
                  <input className="input h-9 font-mono text-[12px]" inputMode="numeric" value={maxPages}
                    onChange={(event) => setMaxPages(event.target.value.replace(/[^0-9]/g, ""))} placeholder="50" />
                </label>
                <p className="text-[11px] leading-relaxed text-ink3 sm:col-span-2">
                  自动模式会读取响应中的 next 字段继续拉取：同源完整地址、相对地址或游标值均可；跨域地址会被拒绝。
                </p>
              </>
            )}

            {fields.map((field) => (
              <label key={field.key} className="block">
                <span className="mb-1 block text-[11px] text-ink3">{field.label}</span>
                <input
                  className="input h-9 text-[12px]"
                  type="password"
                  autoComplete="new-password"
                  value={credentials[field.key] ?? ""}
                  onChange={(event) => setCredentials((prev) => ({ ...prev, [field.key]: event.target.value }))}
                  placeholder={editing?.hasCredential ? "已保存，留空不修改" : "必填"}
                />
              </label>
            ))}

            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">同步间隔（分钟）</span>
              <input className="input h-9 text-[12px]" inputMode="numeric" value={intervalMinutes}
                onChange={(event) => setIntervalMinutes(event.target.value.replace(/[^0-9]/g, ""))} />
            </label>
            <label className="flex items-end gap-2 pb-2 text-[12px] text-ink2">
              <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
              启用定时同步
            </label>

            {editing?.hasCredential && (
              <label className="flex items-center gap-2 text-[11.5px] text-ink2 sm:col-span-2">
                <input type="checkbox" checked={clearSecret} onChange={(event) => setClearSecret(event.target.checked)} />
                清除已保存的凭据
              </label>
            )}
          </div>

          {error && <p className="mt-3 text-[11.5px] text-[#C4170E]">{error}</p>}
          <p className="mt-3 text-[10.5px] leading-[16px] text-ink3">
            同步只读取实例列表；外部 CMDB 返回数组或 <code className="font-mono">{"{items:[...]}"}</code> 即可，
            支持 hostname / ip / privateIp / os / businessSystem / owner / tags 等字段。
          </p>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3.5">
          <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={saving}>取消</button>
          <button type="button" className="btn btn-primary h-8" onClick={() => void submit()} disabled={saving}>
            {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
            保存
          </button>
        </footer>
      </div>
    </div>
  );
}
