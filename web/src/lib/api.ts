import type {
  AssetChange,
  AssetDetail,
  AssetImportReport,
  AssetItem,
  AssetJobs,
  AssetMergeStats,
  AssetRelation,
  AssetTelemetry,
  AuditItem,
  BusinessSystem,
  DiscoveryCandidate,
  DiscoveryJob,
  DiscoveryPolicy,
  GovernanceItem,
  GovernanceSummary,
  IntegrationSource,
  IntegrationSyncResult,
  IntegrationTestResult,
  Topology,
  Finding,
  FindingDetail,
  HarnessApproval,
  HarnessApprovalMode,
  HarnessEvent,
  HarnessMessagesResponse,
  HarnessSession,
  HarnessSkill,
  HarnessToolSpec,
  LoginResponse,
  OpsPolicy,
  Overview,
  Paged,
  ProductMapping,
  RiskPolicy,
  SelfCheckHistoryItem,
  SelfCheckRun,
  SettingsData,
  RuntimeSettingItem,
  RuntimeSettingUpdateResult,
  ProjectItem,
  ClusterItem,
  ClusterNodeItem,
  ClusterDetailData,
  ClusterScanResult,
  ClusterJob,
  AgentItem,
  AgentEnrollTokenItem,
  AgentCommandItem,
  SyncSource,
  Ticket,
  TrajectoryItem,
  User,
  SshHost,
  SshHostInput,
  SshHostMetrics,
  SshHostScanResult,
  SshHostTestResult,
  SshGpuInfo,
  SshGpuBenchmark,
  SshAccelProfile,
  SshAccelLive,
  SshAccelComparison,
  AccelBaselineResult,
  AccelNode,
  HashcatAuditInput,
  HashcatAuditResult,
  HashcatBenchmark,
  SshSessionItem,
  SshAssistantReply,
  SshAgentEvent,
  SshAgentMode,
  SshAgentRun,
  SshAgentRunDetail,
  SshRecording,
  SshShareCreated,
  SshShareInfo,
  SshShareLink,
  SshSharePermission,
  SshSnippet,
  SshSnippetInput,
  SftpList,
  SftpPreview
} from "./types";

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(init.headers || {})
      },
      ...init
    });
  } catch (err) {
    throw new ApiError(0, "network_error", networkMessage(err));
  }

  if (!response.ok) {
    let code = "http_error";
    let message = `请求失败（${response.status}）`;
    try {
      const body = await response.json();
      if (body?.error) {
        code = body.error.code || code;
        message = body.error.message || message;
      }
    } catch {
      /* 非 JSON 错误响应，保留默认文案 */
    }
    throw new ApiError(response.status, code, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return await readJSON<T>(response);
}

async function toApiError(response: Response, fallback: string): Promise<ApiError> {
  let code = "http_error";
  let message = `${fallback}（${response.status}）`;
  try {
    const body = await response.json();
    if (body?.error) {
      code = body.error.code || code;
      message = body.error.message || message;
    }
  } catch {
    /* 非 JSON 错误响应，保留默认文案 */
  }
  return new ApiError(response.status, code, message);
}

// readJSON 校验响应确实是 JSON；避免把 SPA 回退的 index.html 当 JSON 解析，
// 抛出 "Unexpected token '<'" 这类无法定位的底层异常。
async function readJSON<T>(response: Response): Promise<T> {
  const type = (response.headers.get("content-type") || "").toLowerCase();
  if (!type.includes("application/json") && !type.includes("+json")) {
    const hint = type.includes("text/html")
      ? "服务端返回了页面而不是 JSON，请确认后端已启动且前后端版本一致"
      : "服务端返回了非 JSON 响应，请检查接口地址与服务状态";
    throw new ApiError(response.status || 0, "invalid_response", `${hint}（HTTP ${response.status}）`);
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "" && value !== null) {
      search.set(key, String(value));
    }
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

// networkMessage 把浏览器的 TypeError("Failed to fetch") 翻译成可操作提示
export function networkMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  if (/failed to fetch|networkerror|load failed/i.test(raw)) {
    const origin = typeof window === "undefined" ? "" : window.location.origin;
    return origin
      ? `无法连接控制面（当前页面 ${origin}），请确认服务已启动后重试`
      : "无法连接控制面，请确认服务已启动后重试";
  }
  return raw || "网络请求失败";
}

// streamSSE 读取 text/event-stream，逐条回调事件
async function streamSSE(
  path: string,
  body: unknown,
  onEvent: (event: HarnessEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
      signal
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw err;
    }
    throw new ApiError(0, "network_error", networkMessage(err));
  }
  if (!response.ok) {
    throw await toApiError(response, "请求失败");
  }
  if (!response.body) {
    throw new ApiError(500, "no_stream", "当前浏览器不支持流式响应");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let index = buffer.indexOf("\n\n");
    while (index >= 0) {
      const chunk = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      const line = chunk.split("\n").find((item) => item.startsWith("data:"));
      if (line) {
        const payload = line.slice(5).trim();
        if (payload && payload !== "{}") {
          try {
            onEvent(JSON.parse(payload) as HarnessEvent);
          } catch {
            /* 忽略无法解析的片段 */
          }
        }
      }
      index = buffer.indexOf("\n\n");
    }
  }
}

// 概览接口在首屏会被 AppShell 与概览页同时调用；短窗口内复用同一请求，避免重复开销
let overviewInflight: Promise<Overview> | null = null;
let overviewFetchedAt = 0;

export const api = {
  health(): Promise<{ ok: boolean; version: string; demo: boolean }> {
    return request("/healthz");
  },

  login(username: string, password: string): Promise<LoginResponse> {
    return request<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
  },

  logout(): Promise<{ ok: boolean }> {
    return request("/auth/logout", { method: "POST" });
  },

  me(): Promise<{ user: User }> {
    return request("/me");
  },

  changePassword(oldPassword: string, newPassword: string): Promise<{ ok: boolean }> {
    return request("/me/password", {
      method: "POST",
      body: JSON.stringify({ oldPassword, newPassword })
    });
  },

  users(): Promise<{ items: Array<{ username: string; name: string; role: User["role"]; lastLogin: string; disabled: boolean }> }> {
    return request("/users");
  },

  createUser(payload: { username: string; name: string; role: string; password: string }): Promise<{ ok: boolean }> {
    return request("/users", { method: "POST", body: JSON.stringify(payload) });
  },

  updateUser(username: string, patch: { name?: string; role?: string; disabled?: boolean }): Promise<{ ok: boolean }> {
    return request(`/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify(patch) });
  },

  resetUserPassword(username: string, password: string): Promise<{ ok: boolean }> {
    return request(`/users/${encodeURIComponent(username)}/reset-password`, {
      method: "POST",
      body: JSON.stringify({ password })
    });
  },

  rotateAgentToken(): Promise<{ ok: boolean; token: string; file: string; rotatedAt: string }> {
    return request("/agent/token/rotate", { method: "POST" });
  },

  overview(): Promise<Overview> {
    const now = Date.now();
    if (overviewInflight && now - overviewFetchedAt < 1500) {
      return overviewInflight;
    }
    overviewFetchedAt = now;
    overviewInflight = request<Overview>("/overview").catch((err) => {
      overviewInflight = null;
      throw err;
    });
    return overviewInflight;
  },

  findings(params: {
    priority?: string;
    status?: string;
    q?: string;
    clusterId?: number;
    page?: number;
    pageSize?: number;
  }): Promise<Paged<Finding>> {
    return request(`/findings${query(params)}`);
  },

  finding(id: number | string): Promise<FindingDetail> {
    return request(`/findings/${id}`);
  },

  patchFinding(id: number, patch: { status?: string; assignee?: string }): Promise<{ ok: boolean; finding: Finding }> {
    return request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
  },

  createTicket(id: number): Promise<{ ok: boolean; ticketId: string; status: string; created: boolean; ticket: Ticket }> {
    return request(`/findings/${id}/ticket`, { method: "POST" });
  },

  rescan(id: number): Promise<{
    ok: boolean;
    skipped: boolean;
    scanId: string;
    assetId: number;
    created: number;
    updated: number;
    verified: number;
    closed: number;
    reopened: number;
    status: string;
  }> {
    return request(`/findings/${id}/rescan`, { method: "POST" });
  },

  scanAssets(payload: { assetIds?: number[]; all?: boolean }): Promise<{
    ok: boolean;
    scanned: number;
    skipped: number;
    created: number;
    updated: number;
    verified: number;
    closed: number;
    reopened: number;
  }> {
    return request("/scans", { method: "POST", body: JSON.stringify(payload) });
  },

  async reportFindings(params: { priority?: string; status?: string; q?: string; clusterId?: number }): Promise<Blob> {
    const response = await fetch(`${BASE}/reports/findings.pdf${query(params)}`, {
      credentials: "include"
    });
    if (!response.ok) {
      throw await toApiError(response, "生成报告失败");
    }
    return response.blob();
  },

  async reportFindingsCSV(params: { priority?: string; status?: string; q?: string; clusterId?: number }): Promise<Blob> {
    const response = await fetch(`${BASE}/reports/findings.csv${query(params)}`, {
      credentials: "include"
    });
    if (!response.ok) {
      throw await toApiError(response, "导出失败");
    }
    return response.blob();
  },

  notifySettings(): Promise<{
    url: string;
    secretSet: boolean;
    events: string[];
    catalog: string[];
    lastEvent: string;
    lastStatus: string;
    lastError: string;
    lastSentAt: string;
  }> {
    return request("/notify-settings");
  },

  updateNotifySettings(payload: {
    url: string;
    secret?: string;
    clearSecret?: boolean;
    events: string[];
  }): Promise<{ ok: boolean }> {
    return request("/notify-settings", { method: "PUT", body: JSON.stringify(payload) });
  },

  testNotify(): Promise<{ ok: boolean; elapsedMs: number }> {
    return request("/notify-settings/test", { method: "POST" });
  },

  refreshEPSS(): Promise<{
    ok: boolean;
    mode: string;
    rows: number;
    matched: number;
    unmatched: number;
    invalid: number;
    recomputed: number;
    cursor: string;
  }> {
    return request("/sync/epss/refresh", { method: "POST" });
  },

  assets(params: {
    q?: string;
    env?: string;
    exposure?: string;
    tier?: string;
    status?: string;
    assetType?: string;
    businessSystem?: string;
    owner?: string;
    cloudProvider?: string;
    clusterId?: number;
    page?: number;
    pageSize?: number;
  }): Promise<Paged<AssetItem>> {
    return request(`/assets${query(params)}`);
  },

  updateAsset(
    id: number | string,
    payload: Record<string, unknown>
  ): Promise<{ ok: boolean; asset: AssetItem; changes?: AssetChange[] }> {
    return request(`/assets/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  },

  setAssetTags(id: number | string, tags: string[]): Promise<{ ok: boolean; tags: string[] }> {
    return request(`/assets/${id}/tags`, { method: "PUT", body: JSON.stringify({ tags }) });
  },

  assetChanges(id: number | string, limit = 100): Promise<{ items: AssetChange[] }> {
    return request(`/assets/${id}/changes${query({ limit })}`);
  },

  mergeAsset(sourceId: number, targetId: number): Promise<{ ok: boolean; stats: AssetMergeStats }> {
    return request("/assets/merge", {
      method: "POST",
      body: JSON.stringify({ sourceId, targetId })
    });
  },

  async importAssets(
    file: File,
    params: { strategy: "skip" | "update" | "create"; dryRun?: boolean }
  ): Promise<AssetImportReport> {
    const form = new FormData();
    form.append("file", file);
    form.append("strategy", params.strategy);
    if (params.dryRun) form.append("dryRun", "true");
    const response = await fetch(`${BASE}/assets/import`, {
      method: "POST",
      credentials: "include",
      body: form
    });
    if (!response.ok) {
      throw await toApiError(response, "导入失败");
    }
    return await readJSON<AssetImportReport>(response);
  },

  async exportAssets(params: {
    q?: string;
    env?: string;
    status?: string;
    assetType?: string;
    businessSystem?: string;
    tier?: string;
    exposure?: string;
    clusterId?: number;
  }): Promise<Blob> {
    const response = await fetch(`${BASE}/assets/export${query(params)}`, {
      credentials: "include"
    });
    if (!response.ok) {
      throw await toApiError(response, "导出失败");
    }
    return response.blob();
  },

  discoveryJobs(params: { status?: string; page?: number; pageSize?: number } = {}): Promise<Paged<DiscoveryJob>> {
    return request(`/discovery/jobs${query(params)}`);
  },

  createDiscoveryJob(payload: {
    name?: string;
    cidrs: string[];
    ports?: number[];
    concurrency?: number;
    timeoutMs?: number;
    reverseDns?: boolean;
  }): Promise<{ ok: boolean; job: DiscoveryJob }> {
    return request("/discovery/jobs", { method: "POST", body: JSON.stringify(payload) });
  },

  discoveryJob(id: number): Promise<{ job: DiscoveryJob; counts: Record<string, number> }> {
    return request(`/discovery/jobs/${id}`);
  },

  cancelDiscoveryJob(id: number): Promise<{ ok: boolean }> {
    return request(`/discovery/jobs/${id}/cancel`, { method: "POST" });
  },

  discoveryCandidates(params: {
    jobId?: number;
    decision?: string;
    q?: string;
    page?: number;
    pageSize?: number;
  } = {}): Promise<Paged<DiscoveryCandidate>> {
    return request(`/discovery/candidates${query(params)}`);
  },

  decideDiscoveryCandidate(
    id: number,
    action: "approve" | "ignore" | "merge",
    body?: { assetId?: number }
  ): Promise<{ ok: boolean; assetId?: number; decision?: string }> {
    return request(`/discovery/candidates/${id}/${action}`, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined
    });
  },

  batchDiscoveryCandidates(
    ids: number[],
    action: "approve" | "ignore"
  ): Promise<{ ok: boolean; processed: number; failed: { id: number; error: string }[] }> {
    return request("/discovery/candidates/batch", {
      method: "POST",
      body: JSON.stringify({ ids, action })
    });
  },

  discoveryPolicy(): Promise<{ policy: DiscoveryPolicy }> {
    return request("/settings/discovery");
  },

  updateDiscoveryPolicy(policy: DiscoveryPolicy): Promise<{ ok: boolean; policy: DiscoveryPolicy }> {
    return request("/settings/discovery", { method: "PUT", body: JSON.stringify(policy) });
  },

  assetRelations(id: number | string): Promise<{ items: AssetRelation[] }> {
    return request(`/assets/${id}/relations`);
  },

  createAssetRelation(
    id: number | string,
    payload: { toAssetId: number; relation: string }
  ): Promise<{ ok: boolean; id: number }> {
    return request(`/assets/${id}/relations`, { method: "POST", body: JSON.stringify(payload) });
  },

  deleteAssetRelation(id: number): Promise<{ ok: boolean }> {
    return request(`/assets/relations/${id}`, { method: "DELETE" });
  },

  topology(params: {
    businessSystem?: string;
    env?: string;
    status?: string;
    assetType?: string;
  } = {}): Promise<Topology> {
    return request(`/topology${query(params)}`);
  },

  businessSystems(): Promise<{ items: BusinessSystem[] }> {
    return request("/business-systems");
  },

  updateBusinessSystem(
    name: string,
    payload: { tier: string; owner?: string; description?: string }
  ): Promise<{ ok: boolean; businessSystem: BusinessSystem; recomputed: number }> {
    return request(`/business-systems/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(payload)
    });
  },

  deleteBusinessSystem(name: string): Promise<{ ok: boolean; recomputed: number }> {
    return request(`/business-systems/${encodeURIComponent(name)}`, { method: "DELETE" });
  },

  governanceSummary(params: { days?: number; changeDays?: number } = {}): Promise<{
    summary: GovernanceSummary;
    staleCutoff: string;
    changeCutoff: string;
  }> {
    return request(`/governance/summary${query(params)}`);
  },

  governanceTodos(params: {
    type: string;
    page?: number;
    pageSize?: number;
    days?: number;
    changeDays?: number;
  }): Promise<{ type: string; total: number; page: number; pageSize: number; items: GovernanceItem[] }> {
    return request(`/governance/todos${query(params)}`);
  },

  batchUpdateAssets(
    ids: number[],
    patch: {
      owner?: string;
      ownerEmail?: string;
      department?: string;
      businessSystem?: string;
      status?: string;
      tier?: string;
      env?: string;
    }
  ): Promise<{ ok: boolean; updated: number; unchanged: number; failed: { id: number; error: string }[] }> {
    return request("/assets/batch", {
      method: "POST",
      body: JSON.stringify({ ids, patch })
    });
  },

  integrations(): Promise<{ items: IntegrationSource[]; kinds: string[] }> {
    return request("/integrations");
  },

  createIntegration(payload: {
    kind: string;
    name: string;
    config: Record<string, unknown>;
    credentials?: Record<string, string>;
    enabled: boolean;
    intervalMinutes: number;
  }): Promise<{ ok: boolean; item: IntegrationSource }> {
    return request("/integrations", { method: "POST", body: JSON.stringify(payload) });
  },

  updateIntegration(
    id: number,
    payload: {
      name?: string;
      config?: Record<string, unknown>;
      credentials?: Record<string, string>;
      enabled?: boolean;
      intervalMinutes?: number;
      clearSecret?: boolean;
    }
  ): Promise<{ ok: boolean; item: IntegrationSource }> {
    return request(`/integrations/${id}`, { method: "PUT", body: JSON.stringify(payload) });
  },

  deleteIntegration(id: number): Promise<{ ok: boolean }> {
    return request(`/integrations/${id}`, { method: "DELETE" });
  },

  testIntegration(id: number): Promise<IntegrationTestResult> {
    return request(`/integrations/${id}/test`, { method: "POST" });
  },

  syncIntegration(id: number): Promise<IntegrationSyncResult> {
    return request(`/integrations/${id}/sync`, { method: "POST" });
  },

  asset(id: number | string): Promise<AssetDetail> {
    return request(`/assets/${id}`);
  },

  assetTelemetry(id: number | string, limit = 48): Promise<AssetTelemetry> {
    return request(`/assets/${id}/telemetry${query({ limit })}`);
  },

  assetJobs(id: number | string, limit = 50): Promise<AssetJobs> {
    return request(`/assets/${id}/jobs${query({ limit })}`);
  },

  assetSshHost(id: number | string): Promise<{ host: SshHost; matchedBy: string }> {
    return request(`/assets/${id}/ssh-host`);
  },

  assetSshLink(
    id: number | string,
    input: SshHostInput
  ): Promise<{ host: SshHost; created: boolean; matchedBy: string }> {
    return request(`/assets/${id}/ssh-host`, { method: "POST", body: JSON.stringify(input) });
  },

  sshScan(payload: {
    host: string;
    port: number;
    username: string;
    password?: string;
    privateKey?: string;
    passphrase?: string;
    hostKeyFingerprint?: string;
  }): Promise<{
    ok: boolean;
    assetId: number;
    components: number;
    created: number;
    updated: number;
    verified: number;
    closed: number;
    reopened: number;
    os: string;
    osVersion: string;
    hostKeyFingerprint: string;
    elapsedMs: number;
  }> {
    return request("/assets/ssh-scan", { method: "POST", body: JSON.stringify(payload) });
  },

  runSelfCheck(): Promise<SelfCheckRun> {
    return request("/selfcheck/run", { method: "POST" });
  },

  latestSelfCheck(): Promise<{ demo: boolean; run: SelfCheckRun | null }> {
    return request("/selfcheck/latest");
  },

  selfCheckHistory(): Promise<{ demo: boolean; items: SelfCheckHistoryItem[] }> {
    return request("/selfcheck/history");
  },

  auditLogs(params: {
    page?: number;
    pageSize?: number;
    action?: string;
    actor?: string;
    q?: string;
    from?: string;
    to?: string;
  }): Promise<Paged<AuditItem>> {
    return request(`/audit-logs${query(params)}`);
  },

  trajectory(params: { kind?: string; limit?: number } = {}): Promise<{ items: TrajectoryItem[]; total: number }> {
    return request(`/trajectory${query(params)}`);
  },

  settings(): Promise<SettingsData> {
    return request("/settings");
  },

  runtimeSettings(): Promise<{ items: RuntimeSettingItem[] }> {
    return request("/settings/runtime");
  },

  updateRuntimeSettings(values: Record<string, string>): Promise<RuntimeSettingUpdateResult> {
    return request("/settings/runtime", { method: "PUT", body: JSON.stringify({ values }) });
  },

  projects(): Promise<{ items: ProjectItem[] }> {
    return request("/projects");
  },

  createProject(input: { name: string; description?: string; owner?: string }): Promise<{ ok: boolean; id: number }> {
    return request("/projects", { method: "POST", body: JSON.stringify(input) });
  },

  updateProject(id: number, input: { name?: string; description?: string; owner?: string }): Promise<{ ok: boolean }> {
    return request(`/projects/${id}`, { method: "PATCH", body: JSON.stringify(input) });
  },

  deleteProject(id: number): Promise<{ ok: boolean }> {
    return request(`/projects/${id}`, { method: "DELETE" });
  },

  clusters(projectId?: number): Promise<{ items: ClusterItem[] }> {
    return request(`/clusters${projectId ? query({ projectId }) : ""}`);
  },

  createCluster(input: {
    projectId: number;
    name: string;
    environment: string;
    provider?: string;
    region?: string;
    description?: string;
  }): Promise<{ ok: boolean; id: number }> {
    return request("/clusters", { method: "POST", body: JSON.stringify(input) });
  },

  clusterDetail(id: number): Promise<ClusterDetailData> {
    return request(`/clusters/${id}`);
  },

  updateCluster(id: number, input: Partial<Pick<ClusterItem, "name" | "environment" | "provider" | "region" | "description">>): Promise<{ ok: boolean }> {
    return request(`/clusters/${id}`, { method: "PATCH", body: JSON.stringify(input) });
  },

  deleteCluster(id: number): Promise<{ ok: boolean }> {
    return request(`/clusters/${id}`, { method: "DELETE" });
  },

  createClusterNode(clusterId: number, input: {
    name: string;
    role: string;
    host?: string;
    port?: number;
    url?: string;
    sshHostId?: number;
    checkType?: string;
    path?: string;
    note?: string;
  }): Promise<{ ok: boolean; id: number }> {
    return request(`/clusters/${clusterId}/nodes`, { method: "POST", body: JSON.stringify(input) });
  },

  updateClusterNode(id: number, input: Record<string, unknown>): Promise<{ ok: boolean }> {
    return request(`/cluster-nodes/${id}`, { method: "PATCH", body: JSON.stringify(input) });
  },

  deleteClusterNode(id: number): Promise<{ ok: boolean }> {
    return request(`/cluster-nodes/${id}`, { method: "DELETE" });
  },

  checkClusterNode(id: number): Promise<ClusterNodeItem> {
    return request(`/cluster-nodes/${id}/check`, { method: "POST", body: "{}" });
  },

  scanClusterNode(id: number): Promise<{ ok: boolean; result: unknown }> {
    return request(`/cluster-nodes/${id}/scan`, { method: "POST", body: "{}" });
  },

  checkCluster(id: number): Promise<{ items: ClusterNodeItem[] }> {
    return request(`/clusters/${id}/check`, { method: "POST", body: "{}" });
  },

  scanCluster(id: number): Promise<ClusterScanResult> {
    return request(`/clusters/${id}/scan`, { method: "POST", body: "{}" });
  },
  createClusterJob(id: number, kind: "check" | "scan"): Promise<{ job: ClusterJob }> {
    return request(`/clusters/${id}/jobs`, { method: "POST", body: JSON.stringify({ kind }) });
  },
  clusterJobs(id: number): Promise<{ items: ClusterJob[] }> {
    return request(`/clusters/${id}/jobs`);
  },
  clusterJob(id: string): Promise<ClusterJob> {
    return request(`/cluster-jobs/${id}`);
  },
  cancelClusterJob(id: string): Promise<{ ok: boolean; status: string }> {
    return request(`/cluster-jobs/${id}/cancel`, { method: "POST", body: "{}" });
  },

  agents(): Promise<{ items: AgentItem[]; total: number; online: number }> {
    return request("/agents");
  },
  createAgentEnrollToken(input: {
    nameHint?: string;
    projectId?: number;
    clusterId?: number;
    ttlMinutes?: number;
  }): Promise<{ id: string; token: string; expiresAt: string }> {
    return request("/agents/enroll-tokens", { method: "POST", body: JSON.stringify(input) });
  },
  agentEnrollTokens(): Promise<{ items: AgentEnrollTokenItem[] }> {
    return request("/agents/enroll-tokens");
  },
  deleteAgentEnrollToken(id: string): Promise<{ ok: boolean }> {
    return request(`/agents/enroll-tokens/${id}`, { method: "DELETE" });
  },
  revokeAgent(id: string): Promise<{ ok: boolean }> {
    return request(`/agents/${id}/revoke`, { method: "POST", body: "{}" });
  },
  createAgentCommand(id: string, action: "ping" | "collect"): Promise<{ ok: boolean; id: string }> {
    return request(`/agents/${id}/commands`, { method: "POST", body: JSON.stringify({ action }) });
  },
  agentCommands(id: string): Promise<{ items: AgentCommandItem[] }> {
    return request(`/agents/${id}/commands`);
  },

  linkClusterAssets(id: number, assetIds: number[]): Promise<{ ok: boolean; count: number }> {
    return request(`/clusters/${id}/assets`, { method: "POST", body: JSON.stringify({ assetIds }) });
  },

  unlinkClusterAsset(id: number, assetId: number): Promise<{ ok: boolean }> {
    return request(`/clusters/${id}/assets/${assetId}`, { method: "DELETE" });
  },

  updateRiskPolicy(policy: RiskPolicy): Promise<{ ok: boolean; riskPolicy: RiskPolicy; recomputed: number }> {
    return request("/settings/risk-policy", {
      method: "PATCH",
      body: JSON.stringify(policy)
    });
  },

  opsPolicy(): Promise<{ policy: OpsPolicy }> {
    return request("/settings/ops-policy");
  },

  updateOpsPolicy(policy: OpsPolicy): Promise<{ ok: boolean; policy: OpsPolicy }> {
    return request("/settings/ops-policy", { method: "PUT", body: JSON.stringify(policy) });
  },

  syncStatus(): Promise<{ demo: boolean; sources: SyncSource[] }> {
    return request("/sync/status");
  },

  triggerSync(source: string): Promise<{
    ok: boolean;
    mode: string;
    fetched: number;
    inserted: number;
    updated: number;
    startedAt: string;
  }> {
    return request(`/sync/${source}`, { method: "POST" });
  },

  triggerOSV(payload: { assetIds?: number[]; all?: boolean } = { all: true }): Promise<{
    ok: boolean;
    assets: number;
    components: number;
    queried: number;
    vulns: number;
    created: number;
    updated: number;
    errors: number;
  }> {
    return request("/sync/osv", { method: "POST", body: JSON.stringify(payload) });
  },

  async uploadEPSS(file: File): Promise<{
    ok: boolean;
    rows: number;
    matched: number;
    unmatched: number;
    invalid: number;
    recomputed: number;
    cursor: string;
  }> {
    const response = await fetch(`${BASE}/sync/epss`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "text/csv" },
      body: file
    });
    if (!response.ok) {
      let code = "http_error";
      let message = `导入失败（${response.status}）`;
      try {
        const body = await response.json();
        if (body?.error) {
          code = body.error.code || code;
          message = body.error.message || message;
        }
      } catch {
        /* 保留默认文案 */
      }
      throw new ApiError(response.status, code, message);
    }
    return await readJSON<{
      ok: boolean;
      rows: number;
      matched: number;
      unmatched: number;
      invalid: number;
      recomputed: number;
      cursor: string;
    }>(response);
  },

  productMap(q?: string): Promise<{ demo: boolean; total: number; items: ProductMapping[] }> {
    return request(`/product-map${query({ q })}`);
  },

  upsertProductMap(payload: {
    eco: string;
    name: string;
    product: string;
    confidence: number;
  }): Promise<{ ok: boolean; mapping: ProductMapping; rematched: number }> {
    return request("/product-map", { method: "PUT", body: JSON.stringify(payload) });
  },

  deleteProductMap(eco: string, name: string): Promise<{ ok: boolean; rematched: number }> {
    return request(`/product-map?eco=${encodeURIComponent(eco)}&name=${encodeURIComponent(name)}`, {
      method: "DELETE"
    });
  },

  harnessTools(): Promise<{ enabled: boolean; model: string; tools: HarnessToolSpec[] }> {
    return request("/agent/tools");
  },

  harnessSkills(): Promise<{ skills: HarnessSkill[] }> {
    return request("/agent/skills");
  },

  harnessSessions(): Promise<{ sessions: HarnessSession[] }> {
    return request("/agent/sessions");
  },

  harnessCreateSession(
    title: string,
    approvalMode?: HarnessApprovalMode
  ): Promise<{ session: HarnessSession }> {
    return request("/agent/sessions", {
      method: "POST",
      body: JSON.stringify({ title, approvalMode: approvalMode ?? "" })
    });
  },

  harnessUpdateSession(
    id: string,
    approvalMode: HarnessApprovalMode
  ): Promise<{ session: HarnessSession }> {
    return request(`/agent/sessions/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ approvalMode })
    });
  },

  harnessMessages(id: string): Promise<HarnessMessagesResponse> {
    return request(`/agent/sessions/${encodeURIComponent(id)}/messages`);
  },

  harnessChat(
    id: string,
    content: string,
    skillId: string | undefined,
    onEvent: (event: HarnessEvent) => void,
    signal?: AbortSignal
  ): Promise<void> {
    return streamSSE(
      `/agent/sessions/${encodeURIComponent(id)}/messages`,
      { content, skillId: skillId ?? "" },
      onEvent,
      signal
    );
  },

  harnessResume(id: string, onEvent: (event: HarnessEvent) => void, signal?: AbortSignal): Promise<void> {
    return streamSSE(`/agent/sessions/${encodeURIComponent(id)}/resume`, {}, onEvent, signal);
  },

  harnessDecision(
    approvalId: string,
    decision: "approve" | "reject",
    password?: string
  ): Promise<{ ok: boolean; approval: HarnessApproval; result: unknown }> {
    return request(`/agent/approvals/${encodeURIComponent(approvalId)}`, {
      method: "POST",
      body: JSON.stringify({ decision, password: password ?? "" })
    });
  },

  // ---------- SSH 终端面板 ----------

  sshHosts(): Promise<{ items: SshHost[] }> {
    return request("/ssh/hosts");
  },

  sshCreateHost(input: SshHostInput): Promise<{ host: SshHost }> {
    return request("/ssh/hosts", { method: "POST", body: JSON.stringify(input) });
  },

  sshUpdateHost(id: number, input: SshHostInput): Promise<{ host: SshHost }> {
    return request(`/ssh/hosts/${id}`, { method: "PATCH", body: JSON.stringify(input) });
  },

  sshDeleteHost(id: number): Promise<{ ok: boolean }> {
    return request(`/ssh/hosts/${id}`, { method: "DELETE" });
  },

  sshTestHost(id: number): Promise<SshHostTestResult> {
    return request(`/ssh/hosts/${id}/test`, { method: "POST", body: "{}" });
  },

  sshScanHost(id: number): Promise<SshHostScanResult> {
    return request(`/ssh/hosts/${id}/scan`, { method: "POST", body: "{}" });
  },

  sshHostMetrics(id: number): Promise<SshHostMetrics> {
    return request(`/ssh/hosts/${id}/metrics`);
  },

  sshHostGPU(id: number): Promise<SshGpuInfo> {
    return request(`/ssh/hosts/${id}/gpu`);
  },

  sshHostGPUBenchmark(id: number, rounds = 2): Promise<SshGpuBenchmark> {
    return request(`/ssh/hosts/${id}/gpu/benchmark${query({ rounds })}`, { method: "POST", body: "{}" });
  },

  sshHostAccel(id: number, refresh = false): Promise<SshAccelProfile> {
    return request(`/ssh/hosts/${id}/accel${refresh ? "?refresh=1" : ""}`);
  },

  sshHostAccelLive(id: number, refresh = false): Promise<SshAccelLive> {
    return request(`/ssh/hosts/${id}/accel/live${refresh ? "?refresh=1" : ""}`);
  },

  sshHostAccelBaseline(id: number): Promise<AccelBaselineResult> {
    return request(`/ssh/hosts/${id}/accel/baseline`, { method: "POST", body: "{}" });
  },

  sshHostAccelCompare(id: number): Promise<SshAccelComparison> {
    return request(`/ssh/hosts/${id}/accel/compare`, { method: "POST", body: "{}" });
  },

  accelHosts(): Promise<{ items: AccelNode[] }> {
    return request("/accel/hosts");
  },

  sshHostHashcatBenchmark(id: number): Promise<HashcatBenchmark> {
    return request(`/ssh/hosts/${id}/hashcat/benchmark`, { method: "POST", body: "{}" });
  },

  sshHostHashcatAudit(id: number, input: HashcatAuditInput): Promise<HashcatAuditResult> {
    return request(`/ssh/hosts/${id}/hashcat/audit`, { method: "POST", body: JSON.stringify(input) });
  },

  sshSessions(limit = 50): Promise<{ items: SshSessionItem[] }> {
    return request(`/ssh/sessions${query({ limit })}`);
  },

  sshRecording(sessionId: string): Promise<SshRecording> {
    return request(`/ssh/sessions/${encodeURIComponent(sessionId)}/recording`);
  },

  sshCreateShare(
    sessionId: string,
    permission: SshSharePermission,
    ttlMinutes: number
  ): Promise<SshShareCreated> {
    return request(`/ssh/sessions/${encodeURIComponent(sessionId)}/share`, {
      method: "POST",
      body: JSON.stringify({ permission, ttlMinutes })
    });
  },

  sshShares(sessionId: string): Promise<{ items: SshShareLink[] }> {
    return request(`/ssh/sessions/${encodeURIComponent(sessionId)}/shares`);
  },

  sshRevokeShare(id: number): Promise<{ ok: boolean }> {
    return request(`/ssh/shares/${id}`, { method: "DELETE" });
  },

  sshShareInfo(token: string): Promise<SshShareInfo> {
    return request(`/ssh/shared/${encodeURIComponent(token)}/info`);
  },

  sshSnippets(limit = 100): Promise<{ items: SshSnippet[] }> {
    return request(`/ssh/snippets${query({ limit })}`);
  },

  sshCreateSnippet(input: SshSnippetInput): Promise<{ snippet: SshSnippet }> {
    return request("/ssh/snippets", { method: "POST", body: JSON.stringify(input) });
  },

  sshUpdateSnippet(id: number, input: SshSnippetInput): Promise<{ snippet: SshSnippet }> {
    return request(`/ssh/snippets/${id}`, { method: "PATCH", body: JSON.stringify(input) });
  },

  sshDeleteSnippet(id: number): Promise<{ ok: boolean }> {
    return request(`/ssh/snippets/${id}`, { method: "DELETE" });
  },

  sshUseSnippet(id: number, hostNames: string[], broadcast: boolean): Promise<{ ok: boolean; usageCount: number }> {
    return request(`/ssh/snippets/${id}/use`, {
      method: "POST",
      body: JSON.stringify({ hostNames, broadcast })
    });
  },

  sshAssistant(input: {
    hostId: number;
    question: string;
    context: string;
    sessionId?: string;
    search?: boolean;
    history?: Array<{ role: "user" | "assistant"; content: string }>;
  }): Promise<SshAssistantReply> {
    return request("/ssh/assistant", { method: "POST", body: JSON.stringify(input) });
  },

  sshAgentRun(
    hostId: number,
    goal: string,
    mode: SshAgentMode,
    search: boolean,
    onEvent: (event: SshAgentEvent) => void,
    signal?: AbortSignal
  ): Promise<void> {
    return streamSSE("/ssh/agent/run", { hostId, goal, mode, search }, onEvent, signal);
  },

  sshAgentDecision(approvalId: string, decision: "approve" | "reject"): Promise<{ ok: boolean }> {
    return request(`/ssh/agent/approvals/${encodeURIComponent(approvalId)}`, {
      method: "POST",
      body: JSON.stringify({ decision })
    });
  },

  sshAgentRuns(params: { hostId?: number; limit?: number } = {}): Promise<{ items: SshAgentRun[] }> {
    return request(`/ssh/agent/runs${query(params)}`);
  },

  sshAgentRunDetail(id: string): Promise<SshAgentRunDetail> {
    return request(`/ssh/agent/runs/${encodeURIComponent(id)}`);
  },

  // ---------- SFTP 文件管理 ----------

  sftpList(hostId: number, path: string): Promise<SftpList> {
    return request(`/ssh/files/list${query({ hostId, path })}`);
  },

  sftpPreview(hostId: number, path: string): Promise<SftpPreview> {
    return request(`/ssh/files/preview${query({ hostId, path })}`);
  },

  sftpMkdir(hostId: number, path: string): Promise<{ ok: boolean; path: string }> {
    return request("/ssh/files/mkdir", { method: "POST", body: JSON.stringify({ hostId, path }) });
  },

  sftpRename(hostId: number, from: string, to: string): Promise<{ ok: boolean }> {
    return request("/ssh/files/rename", { method: "POST", body: JSON.stringify({ hostId, from, to }) });
  },

  sftpDelete(hostId: number, path: string, recursive = false): Promise<{ ok: boolean }> {
    return request(`/ssh/files${query({ hostId, path, recursive: recursive ? "true" : undefined })}`, {
      method: "DELETE"
    });
  },

  sftpSave(hostId: number, path: string, content: string): Promise<{ ok: boolean; path: string; size: number }> {
    return request("/ssh/files/save", { method: "POST", body: JSON.stringify({ hostId, path, content }) });
  },

  async sftpUpload(hostId: number, path: string, file: File): Promise<{ ok: boolean; path: string; size: number }> {
    const form = new FormData();
    form.set("path", path);
    form.set("file", file);
    const response = await fetch(`/api/v1/ssh/files/upload?hostId=${hostId}`, {
      method: "POST",
      credentials: "include",
      body: form
    });
    if (!response.ok) {
      throw await toApiError(response, "上传失败");
    }
    return await readJSON<{ ok: boolean; path: string; size: number }>(response);
  },

  sftpDownloadURL(hostId: number, path: string): string {
    return `/api/v1/ssh/files/download${query({ hostId, path })}`;
  }
};

// sshTerminalURL 生成终端 WebSocket 地址，生产与开发代理共用同源路径
export function sshTerminalURL(hostId: number, cols: number, rows: number): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/v1/ssh/terminal?hostId=${hostId}&cols=${cols}&rows=${rows}`;
}

export function sshSharedTerminalURL(token: string, cols: number, rows: number): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/v1/ssh/shared/${encodeURIComponent(token)}?cols=${cols}&rows=${rows}`;
}
