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
  osArch: string;
  kernel: string;
  env: string;
  exposure: string;
  tier: string;
  owner: string;
  source: Source;
  agentStatus: AgentStatus;
  lastSeen: string;
  assetType: string;
  status: string;
  businessSystem: string;
  department: string;
  ownerEmail: string;
  location: string;
  cloudProvider: string;
  cloudAccount: string;
  region: string;
  instanceId: string;
  mac: string;
  serial: string;
  virtualized: string;
  mergedInto: number;
  tags: string[];
  components: number;
  findings: number;
  p0: number;
  risk: number;
}

export interface AssetIdentifier {
  id: number;
  assetId: number;
  kind: string;
  value: string;
  source: string;
  createdAt: string;
}

export interface AssetChange {
  id: number;
  assetId: number;
  field: string;
  oldValue: string;
  newValue: string;
  actor: string;
  source: string;
  createdAt: string;
}

export interface AssetImportRow {
  row: number;
  action: "created" | "updated" | "skipped" | "error";
  assetId?: number;
  hostname: string;
  message?: string;
  changed?: string[];
}

export interface AssetImportReport {
  dryRun: boolean;
  strategy: string;
  total: number;
  created: number;
  updated: number;
  skipped: number;
  errors: number;
  items: AssetImportRow[];
}

export interface AssetMergeStats {
  components: number;
  findings: number;
  tickets: number;
  identifiers: number;
  tags: number;
  relations: number;
}

export interface DiscoveryJob {
  id: number;
  name: string;
  cidrs: string;
  ports: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  total: number;
  scanned: number;
  found: number;
  options: string;
  cancelRequested: boolean;
  createdBy: string;
  createdAt: string;
  startedAt: string;
  finishedAt: string;
  error: string;
}

export interface DiscoveryCandidate {
  id: number;
  jobId: number;
  ip: string;
  hostname: string;
  mac: string;
  openPorts: string;
  services: string;
  evidence: string;
  matchedAssetId: number;
  decision: "new" | "existing" | "approved" | "ignored" | "merged";
  confidence: number;
  decidedBy: string;
  decidedAt: string;
  assetId: number;
  createdAt: string;
}

export interface DiscoveryPolicy {
  allowedCidrs: string[];
  defaultPorts: number[];
  maxHosts: number;
  maxConcurrency: number;
  timeoutMs: number;
  maxPorts: number;
  maxJobsPerHour: number;
  reverseDns: boolean;
}

export interface AssetRelationRef {
  id: number;
  hostname: string;
  ip: string;
  businessSystem: string;
  env: string;
  assetType: string;
  risk: number;
}

export interface AssetRelation {
  id: number;
  fromAssetId: number;
  toAssetId: number;
  relation: string;
  direction: "in" | "out";
  asset: AssetRelationRef;
  createdAt: string;
}

export interface BusinessSystem {
  name: string;
  tier: string;
  owner: string;
  description: string;
  updatedAt: string;
  assetCount: number;
}

export interface TopologyAsset {
  id: number;
  hostname: string;
  ip: string;
  businessSystem: string;
  env: string;
  tier: string;
  exposure: string;
  assetType: string;
  status: string;
  risk: number;
  findings: number;
  components: number;
}

export interface TopologyEdge {
  id: number;
  fromAssetId: number;
  toAssetId: number;
  relation: string;
}

export interface Topology {
  assets: TopologyAsset[];
  relations: TopologyEdge[];
  businessSystems: BusinessSystem[];
  truncated: boolean;
  total: number;
}

export interface GovernanceSummary {
  ownerMissing: number;
  stale: number;
  duplicate: number;
  exposureChanged: number;
}

export interface GovernancePeer {
  id: number;
  hostname: string;
  ip: string;
}

export interface GovernanceItem {
  type: "owner_missing" | "stale" | "duplicate" | "exposure_changed";
  assetId: number;
  hostname: string;
  ip: string;
  businessSystem: string;
  owner: string;
  status: string;
  source: string;
  lastSeen: string;
  detail: string;
  oldValue?: string;
  newValue?: string;
  updatedAt?: string;
  related?: GovernancePeer[];
}

export type IntegrationKind = "cloud_aliyun" | "cloud_aws" | "cloud_azure" | "cmdb_api";

export interface IntegrationSource {
  id: number;
  kind: IntegrationKind;
  name: string;
  config: Record<string, unknown>;
  hasCredential: boolean;
  enabled: boolean;
  intervalMinutes: number;
  lastRunAt: string;
  lastStatus: string;
  lastError: string;
  lastCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface IntegrationSample {
  instanceId?: string;
  name?: string;
  hostname?: string;
  privateIp?: string;
  publicIp?: string;
  osFamily?: string;
  region?: string;
  status?: string;
}

export interface IntegrationTestResult {
  ok: boolean;
  count?: number;
  sample?: IntegrationSample[];
  elapsedMs?: number;
  error?: string;
}

export interface IntegrationSyncStats {
  sourceId: number;
  kind: string;
  name: string;
  fetched: number;
  created: number;
  updated: number;
  unchanged: number;
  failed: number;
  errors?: string[];
  finishedAt: string;
}

export interface IntegrationSyncResult {
  ok: boolean;
  stats?: IntegrationSyncStats;
  error?: string;
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
  identifiers: AssetIdentifier[];
  changes: AssetChange[];
  relations: AssetRelation[];
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

export interface SshDiskUsage {
  mount: string;
  totalKb: number;
  usedKb: number;
  availKb: number;
  percent: number;
}

export interface SshProcessUsage {
  pid: number;
  command: string;
  cpuPercent: number;
  memPercent: number;
}

export interface SshHostMetrics {
  hostId: number;
  hostName: string;
  hostAddr: string;
  sampledAt: string;
  elapsedMs: number;
  cpuPercent: number;
  cpuCores: number;
  memTotalKb: number;
  memUsedKb: number;
  memAvailableKb: number;
  memPercent: number;
  swapTotalKb: number;
  swapUsedKb: number;
  swapPercent: number;
  load1: number;
  load5: number;
  load15: number;
  uptimeSeconds: number;
  processes: number;
  netRxBps: number;
  netTxBps: number;
  disks: SshDiskUsage[];
  top: SshProcessUsage[];
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
  hasRecording: boolean;
  recordingBytes: number;
  recordingMs: number;
  recordingTruncated: boolean;
}

export interface SshRecordingChunk {
  offsetMs: number;
  data: string;
}

export interface SshRecording {
  sessionId: string;
  hostName: string;
  actor: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  bytes: number;
  truncated: boolean;
  chunks: SshRecordingChunk[];
}

export interface SshSnippet {
  id: number;
  name: string;
  command: string;
  description: string;
  tags: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  usageCount: number;
}

export interface SshSnippetInput {
  name: string;
  command: string;
  description: string;
  tags: string;
}

export type SshSharePermission = "read" | "write";

export interface SshShareLink {
  id: number;
  permission: SshSharePermission;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
}

export interface SshShareCreated {
  token: string;
  path: string;
  permission: SshSharePermission;
  expiresAt: string;
  sessionId: string;
  hostName: string;
}

export interface SshShareInfo {
  sessionId: string;
  hostName: string;
  addr: string;
  owner: string;
  permission: SshSharePermission;
  canWrite: boolean;
  expiresAt: string;
  viewers: number;
  serverVersion: string;
}

export interface SshAssistantReply {
  answer: string;
  commands: string[];
  model: string;
  references: SshCommandReference[];
  referenceError?: string;
}

export interface SshCommandReference {
  topic: string;
  title: string;
  url: string;
  snippet: string;
}

export interface SshHostScanResult {
  ok: boolean;
  assetId: number;
  hostId: number;
  hostName: string;
  host: string;
  username: string;
  scanUser: string;
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
}

export type SshAgentMode = "confirm" | "safe" | "auto";

export interface SshAgentRun {
  id: string;
  hostId: number;
  hostName: string;
  actor: string;
  role: Role;
  goal: string;
  mode: SshAgentMode;
  status: string;
  steps: number;
  summary: string;
  error: string;
  startedAt: string;
  endedAt: string;
}

export interface SshAgentStepRecord {
  index: number;
  thought: string;
  command: string;
  output: string;
  risk: string;
  approved: string;
  exitCode: number;
  createdAt: string;
}

export interface SshAgentRunDetail {
  run: SshAgentRun;
  steps: SshAgentStepRecord[];
}

export interface SshAgentEvent {
  type:
    | "status"
    | "step"
    | "output"
    | "await_approval"
    | "approval_result"
    | "done"
    | "error"
    | string;
  data?: any;
}

// ---------- SFTP 文件管理 ----------

export interface SftpEntry {
  name: string;
  path: string;
  dir: boolean;
  size: number;
  mode: string;
  modified: string;
  symlink: boolean;
}

export interface SftpList {
  path: string;
  parent: string;
  items: SftpEntry[];
  truncated: boolean;
  host: string;
}

export interface SftpPreview {
  path: string;
  binary: boolean;
  truncated: boolean;
  content: string;
  size: number;
  modified: string;
}

