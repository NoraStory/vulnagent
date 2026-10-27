export type Role = "admin" | "operator" | "viewer";
export type Priority = "P0" | "P1" | "P2" | "P3";
export type ExploitState = "kev" | "poc" | "none";
export type AgentStatus = "online" | "offline" | "stale" | "none";
export type Source = "agent" | "ssh" | "container" | "self";
export type CheckStatus = "pass" | "warn" | "fail" | "skip";

export interface User {
  username: string;
  name: string;
  role: Role;
}

export interface LoginResponse {
  user: User;
}

export interface AssetBrief {
  id: number;
  hostname: string;
  env: string;
  exposure: string;
  tier: string;
}

export interface ComponentBrief {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  fixedVersion: string;
}

export interface Finding {
  id: number;
  cveId: string;
  title: string;
  priority: Priority;
  risk: number;
  cvss: number;
  epss: number;
  exploit: ExploitState;
  status: string;
  assignee: string;
  inferred: boolean;
  firstSeen: string;
  asset: AssetBrief;
  component: ComponentBrief;
}

export interface ScoreFactor {
  factor: "cvss" | "epss" | "exploit" | "asset";
  label: string;
  value: number | string;
  weight: number;
  weighted: number;
  note: string;
}

export interface PocItem {
  link: string;
  insertedAt: string;
}

export interface Advice {
  fixedVersion: string;
  upgradePath: string;
  command: string;
  note: string;
}

export interface FindingEvent {
  time: string;
  event: string;
  actor: string;
  detail: string;
}

export interface Ticket {
  id: string;
  findingId: number;
  cveId: string;
  assetId: number;
  priority: Priority;
  status: string;
  assignee: string;
  createdBy: string;
  note: string;
  createdAt: string;
  updatedAt: string;
}

export interface FindingDetail extends Finding {
  description: string;
  cwe: { id: number; cn: string };
  publishedAt: string;
  scoreBreakdown: ScoreFactor[];
  poc: PocItem[];
  advice: Advice;
  events: FindingEvent[];
  ticket?: Ticket;
}

export interface Paged<T> {
  demo: boolean;
  total: number;
  page: number;
  pageSize: number;
  items: T[];
}

export interface Overview {
  demo: boolean;
  generatedAt: string;
  counts: {
    p0: number;
    p1: number;
    p2: number;
    p3: number;
    total: number;
    open: number;
    fixing: number;
    fixed: number;
    verified: number;
    riskAccepted: number;
  };
  trend: Array<{ date: string; p0: number; p1: number; p2: number; p3: number; total: number }>;
  topComponents: Array<{
    name: string;
    version: string;
    ecosystem: string;
    cveCount: number;
    maxRisk: number;
    priority: Priority;
    assetCount: number;
  }>;
  sync: SyncSource[];
  agents: { total: number; online: number; offline: number; stale: number };
  selfcheck: {
    runId: string;
    status: "pass" | "warn" | "fail" | "never";
    checkedAt: string;
    passed: number;
    warnings: number;
    failed: number;
  };
  recentEvents: Array<{
    id: number;
    time: string;
    actor: string;
    action: string;
    target: string;
    detail: string;
  }>;
}

export interface SyncSource {
  source: "cve" | "poc" | "epss" | string;
  lastRunAt: string;
  status: "ok" | "warn" | "fail" | "running" | string;
  count: number;
  lagHours: number;
  error: string;
}

export interface AssetItem {
  id: number;
  hostname: string;
  ip: string;
  os: string;
  osVersion: string;
  env: string;
  exposure: string;
  tier: string;
  owner: string;
  source: Source;
  agentStatus: AgentStatus;
  lastSeen: string;
  components: number;
  findings: number;
  p0: number;
  risk: number;
}

export interface AssetComponent {
  purl: string;
  name: string;
  version: string;
  ecosystem: string;
  vendor: string;
  product: string;
  inferred: boolean;
  findings: number;
}

export interface HostMetrics {
  cpuPercent: number;
  load1: number;
  load5: number;
  load15: number;
  memUsed: number;
  memTotal: number;
  swapUsed: number;
  swapTotal: number;
  diskReadBps: number;
  diskWriteBps: number;
  netRxBps: number;
  netTxBps: number;
  uptimeSec: number;
  processCount: number;
}

export interface HostDisk {
  device: string;
  model: string;
  serial: string;
  sizeBytes: number;
}

export interface HostNIC {
  name: string;
  mac: string;
  speedMbps: number;
}

export interface HostHardware {
  cpuModel: string;
  cpuCores: number;
  cpuThreads: number;
  memTotal: number;
  kernel: string;
  virtualization: string;
  serial: string;
  disks: HostDisk[];
  nics: HostNIC[];
}

export interface HostService {
  name: string;
  state: string;
  enabled: boolean;
  detail: string;
}

export interface HostPort {
  proto: string;
  addr: string;
  port: number;
  process: string;
  pid: number;
}

export interface HostProcess {
  name: string;
  pid: number;
  memBytes: number;
}

export interface HostTelemetry {
  collectedAt: string;
  metrics: HostMetrics;
  hardware: HostHardware;
  services: HostService[];
  ports: HostPort[];
  processes: HostProcess[];
}

export interface MetricPoint {
  ts: string;
  cpuPercent: number;
  load1: number;
  memUsed: number;
  memTotal: number;
  netRxBps: number;
  netTxBps: number;
  diskReadBps: number;
  diskWriteBps: number;
}

export interface AssetTelemetry {
  telemetry: HostTelemetry | null;
  series: MetricPoint[];
}

export interface HostJob {
  id: string;
  assetId: number;
  action: string;
  params: string;
  risk: string;
  status: string;
  requestedBy: string;
  approvalId?: string;
  attempts: number;
  maxAttempts: number;
  nextRunAt?: string;
  output?: string;
  error?: string;
  exitCode: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface AssetJobs {
  items: HostJob[];
  total: number;
}

export interface TrajectoryItem {
  id: string;
  kind: string;
  time: string;
  actor: string;
  action: string;
  target: string;
  status: string;
  detail: string;
}

export interface OpsPolicy {
  readOnly: boolean;
  maxJobsPerHour: number;
  retentionDays: number;
}

export interface AssetDetail {
  demo: boolean;
  asset: AssetItem;
  components: AssetComponent[];
  findings: Finding[];
}

export interface CheckItem {
  id: string;
  group: string;
  name: string;
  status: CheckStatus;
  detail: string;
  hint: string;
  durationMs?: number;
}

export interface SelfCheckRun {
  demo: boolean;
  runId: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  status: "pass" | "warn" | "fail";
  triggeredBy: string;
  passed: number;
  warnings: number;
  failed: number;
  checks: CheckItem[];
}

export interface SelfCheckHistoryItem {
  runId: string;
  finishedAt: string;
  status: "pass" | "warn" | "fail";
  passed: number;
  warnings: number;
  failed: number;
  skipped: number;
  durationMs: number;
  triggeredBy: string;
}

export interface ProductMapping {
  eco: string;
  name: string;
  product: string;
  confidence: number;
  source: string;
  updatedAt: string;
}

export interface AuditItem {
  id: number;
  time: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  ip: string;
  detail: string;
}

export interface RiskPolicy {
  weights: { cvss: number; epss: number; exploit: number; asset: number };
  thresholds: { p0: number; p1: number; p2: number };
}

export interface SettingsData {
  demo: boolean;
  riskPolicy: RiskPolicy;
  users: Array<{
    username: string;
    name: string;
    role: Role;
    lastLogin: string;
    disabled: boolean;
  }>;
  build: { version: string; commit: string; builtAt: string; sbomDigest: string };
}

// ---------- Agent Harness ----------

export type HarnessRisk = "low" | "medium" | "high";

export interface HarnessToolSpec {
  name: string;
  description: string;
  risk: HarnessRisk;
  readOnly: boolean;
  minRole: Role;
  params: unknown;
}

export type HarnessApprovalMode = "each" | "smart" | "full";

export interface HarnessSkill {
  id: string;
  displayName: string;
  description: string;
  version: string;
  platforms: string[];
}

export interface HarnessSession {
  id: string;
  owner: string;
  role: Role;
  title: string;
  approvalMode: HarnessApprovalMode;
  createdAt: string;
  updatedAt: string;
}

export interface HarnessToolCall {
  id: string;
  name: string;
  arguments: string;
}

export interface HarnessMessage {
  id: number;
  sessionId: string;
  role: "user" | "assistant" | "tool" | "system";
  content: string;
  toolCalls: string;
  toolCallId: string;
  createdAt: string;
}

export interface HarnessApproval {
  id: string;
  sessionId: string;
  tool: string;
  argsHash: string;
  args: string;
  callId: string;
  risk: HarnessRisk;
  requestedBy: string;
  status: "pending" | "approved" | "rejected";
  reason: string;
  requestedAt: string;
  expiresAt: string;
  decidedAt: string;
  decidedBy: string;
  consumedAt: string;
}

export interface HarnessMessagesResponse {
  session: HarnessSession;
  messages: HarnessMessage[];
  pendingApprovals: HarnessApproval[];
  activeSkillId?: string;
}

export interface HarnessEvent {
  type: "message" | "tool_call" | "tool_result" | "approval_required" | "done" | "error" | string;
  data?: any;
}

// ---------- SSH 终端面板 ----------

export type SshAuthType = "password" | "key";

export interface SshHost {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: SshAuthType;
  hostKey: string;
  note: string;
  tags: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  lastConnectedAt: string;
  hasSecret: boolean;
}

export interface SshHostInput {
  name?: string;
  host?: string;
  port?: number;
  username?: string;
  authType?: SshAuthType;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  note?: string;
  tags?: string;
  clearHostKey?: boolean;
}

export interface SshHostTestResult {
  ok: boolean;
  fingerprint: string;
  serverVersion: string;
  elapsedMs: number;
  trusted: boolean;
}

export interface SshSessionItem {
  id: string;
  hostId: number;
  hostName: string;
  addr: string;
  actor: string;
  role: Role;
  status: "connecting" | "connected" | "closed" | "failed" | string;
  error: string;
  clientIp: string;
  startedAt: string;
  endedAt: string;
  bytesIn: number;
  bytesOut: number;
}

export interface SshAssistantReply {
  answer: string;
  commands: string[];
  model: string;
}

