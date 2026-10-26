import type {
  AssetDetail,
  AssetItem,
  AssetJobs,
  AssetTelemetry,
  AuditItem,
  Finding,
  FindingDetail,
  HarnessApproval,
  HarnessApprovalMode,
  HarnessEvent,
  HarnessMessagesResponse,
  HarnessSession,
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
  SyncSource,
  Ticket,
  TrajectoryItem,
  User
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
  return (await response.json()) as T;
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
    return "无法连接控制面，请确认服务已启动（默认 :8787）后重试";
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
    return request("/overview");
  },

  findings(params: {
    priority?: string;
    status?: string;
    q?: string;
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

  async reportFindings(params: { priority?: string; status?: string; q?: string }): Promise<Blob> {
    const response = await fetch(`${BASE}/reports/findings.pdf${query(params)}`, {
      credentials: "include"
    });
    if (!response.ok) {
      throw await toApiError(response, "生成报告失败");
    }
    return response.blob();
  },

  async reportFindingsCSV(params: { priority?: string; status?: string; q?: string }): Promise<Blob> {
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

  assets(params: { q?: string; page?: number; pageSize?: number }): Promise<Paged<AssetItem>> {
    return request(`/assets${query(params)}`);
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

  auditLogs(params: { page?: number; pageSize?: number; action?: string; actor?: string }): Promise<Paged<AuditItem>> {
    return request(`/audit-logs${query(params)}`);
  },

  trajectory(params: { kind?: string; limit?: number } = {}): Promise<{ items: TrajectoryItem[]; total: number }> {
    return request(`/trajectory${query(params)}`);
  },

  settings(): Promise<SettingsData> {
    return request("/settings");
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
    return response.json();
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
    onEvent: (event: HarnessEvent) => void,
    signal?: AbortSignal
  ): Promise<void> {
    return streamSSE(`/agent/sessions/${encodeURIComponent(id)}/messages`, { content }, onEvent, signal);
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
  }
};
