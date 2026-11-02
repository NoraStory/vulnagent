# 控制面 API 契约（前端 · 后端对接基线）

- Base URL：`/api/v1`（开发期 Vite 代理到 `http://127.0.0.1:8787`）
- 编码：JSON（UTF-8）；时间统一 RFC3339 字符串
- 认证：Cookie `va_session`（HttpOnly）。除 `POST /auth/login`、`GET /healthz` 外均需登录
- 错误：HTTP 4xx/5xx，body `{ "error": { "code": "forbidden", "message": "..." } }`
- 不存在的 `/api/*` 路径固定返回 JSON `404 not_found`，不参与前端 SPA 回退（避免把 index.html 当 JSON 解析）
- 角色：`admin` > `operator` > `viewer`；写操作需 `operator`+，账号/策略/同步需 `admin`

> 演示数据标记：所有响应根对象带 `"demo": true`，前端展示"演示数据"标识。

---

## 1. 认证

### POST /auth/login

```json
{ "username": "admin", "password": "Admin@12345" }
```

200：

```json
{ "user": { "username": "admin", "name": "张启明", "role": "admin" } }
```

- 同一「账号 + IP」10 分钟内失败 5 次返回 `429 too_many_attempts`，并带 `Retry-After`（秒）。
- 失败、锁定与成功登录都会写审计（`auth.login_failed` / `auth.login_blocked` / `auth.login`）。
- 会话空闲 30 分钟过期（`VA_SESSION_IDLE` 可调），Cookie `HttpOnly; SameSite=Lax`，HTTPS 或 `VA_COOKIE_SECURE=1` 时加 `Secure`。

### POST /auth/logout → `{ "ok": true }`

### GET /me

```json
{ "user": { "username": "admin", "name": "张启明", "role": "admin" } }
```

### POST /me/password

```json
{ "oldPassword": "Admin@12345", "newPassword": "Admin@2026new" }
```

- 口令至少 10 位且同时包含字母与数字，返回 `400 weak_password` / `400 invalid_password`。
- 成功后该账号其他会话立即失效，当前会话保留；写 `auth.password_change` 审计。

### GET /users（admin）

```json
{
  "items": [
    { "username": "admin", "name": "张启明", "role": "admin", "lastLogin": "2026-10-23T17:35:00+08:00", "disabled": false }
  ]
}
```

### POST /users（admin）

```json
{ "username": "sec-ops", "name": "王安全", "role": "operator", "password": "SecOps@12345" }
```

- 账号 3–32 位（字母/数字/`. _ -`）；冲突返回 `409 username_exists`。

### PATCH /users/{username}（admin）

```json
{ "name": "王安全", "role": "viewer", "disabled": false }
```

- 字段均可选；不能停用或降级当前登录账号（`400 cannot_modify_self`），至少保留一个启用管理员（`400 last_admin`）。
- 停用后该账号会话立即失效。

### POST /users/{username}/reset-password（admin）

```json
{ "password": "Reset@12345" }
```

- 重置后该账号所有会话下线，操作写审计（不记录明文）。

### POST /agent/token/rotate（admin）

```json
{ "ok": true, "token": "64位十六进制", "file": "…\\data\\agent.token", "rotatedAt": "2026-10-23T17:40:00+08:00" }
```

- 旧令牌立即失效；新令牌仅本次返回，同时写入 `agent.token`（0600）。
- 使用 `VA_AGENT_TOKEN` 托管时返回 `409 env_managed`。

---

## 2. 概览

### GET /overview

```json
{
  "demo": true,
  "generatedAt": "2026-10-22T10:00:00+08:00",
  "counts": { "p0": 4, "p1": 9, "p2": 17, "p3": 26, "total": 56, "open": 41, "fixing": 7, "fixed": 5, "verified": 3, "riskAccepted": 0 },
  "trend": [
    { "date": "2026-10-09", "p0": 2, "p1": 7, "p2": 15, "p3": 22, "total": 46 }
  ],
  "topComponents": [
    { "name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "cveCount": 3, "maxRisk": 96, "priority": "P0", "assetCount": 2 }
  ],
  "sync": [
    { "source": "cve", "lastRunAt": "2026-10-22T08:10:00+08:00", "status": "ok", "count": 241873, "lagHours": 1, "error": "" },
    { "source": "poc", "lastRunAt": "2026-10-22T08:40:00+08:00", "status": "ok", "count": 6120, "lagHours": 1, "error": "" },
    { "source": "epss", "lastRunAt": "2026-10-22T03:00:00+08:00", "status": "warn", "count": 241873, "lagHours": 7, "error": "离线包导入，滞后 1 天" }
  ],
  "agents": { "total": 11, "online": 9, "offline": 1, "stale": 1 },
  "selfcheck": { "runId": "sc-20261022-081500", "status": "warn", "checkedAt": "2026-10-22T08:15:00+08:00", "passed": 9, "warnings": 2, "failed": 0 },
  "recentEvents": [
    { "id": 1, "time": "2026-10-22T09:12:00+08:00", "actor": "李维", "action": "finding.status", "target": "CVE-2021-44228 @ web-01", "detail": "open → fixing" }
  ]
}
```

`selfcheck.status` 取值：`pass | warn | fail | never`。

---

## 3. 漏洞（findings）

### GET /findings?priority=P0&status=&q=&page=1&pageSize=20

```json
{
  "demo": true,
  "total": 56,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "id": 101,
      "cveId": "CVE-2021-44228",
      "title": "Apache Log4j2 JNDI 远程代码执行（Log4Shell）",
      "priority": "P0",
      "risk": 96,
      "cvss": 10.0,
      "epss": 0.944,
      "exploit": "kev",
      "status": "fixing",
      "assignee": "李维",
      "inferred": false,
      "firstSeen": "2026-10-18T02:10:00+08:00",
      "asset": { "id": 3, "hostname": "web-01", "env": "prod", "exposure": "public", "tier": "core" },
      "component": { "name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "fixedVersion": "2.17.1" }
    }
  ]
}
```

`exploit` 取值：`kev | poc | none`。`status` 取值：
`open | triaged | fixing | fixed | verified | closed | risk_accepted | false_positive`。

### GET /findings/{id}

在列表字段基础上追加：

```json
{
  "demo": true,
  "description": "Apache Log4j2 存在 JNDI 注入……",
  "cwe": { "id": 502, "cn": "反序列化不可信数据" },
  "publishedAt": "2021-12-10T00:00:00+08:00",
  "scoreBreakdown": [
    { "factor": "cvss", "label": "CVSS 基础分", "value": 10.0, "weight": 0.4, "weighted": 40.0, "note": "满分" },
    { "factor": "epss", "label": "EPSS 利用概率", "value": 0.944, "weight": 0.2, "weighted": 18.9, "note": "近 30 天在野" },
    { "factor": "exploit", "label": "在野利用", "value": "kev", "weight": 0.25, "weighted": 25.0, "note": "CISA KEV" },
    { "factor": "asset", "label": "资产权重", "value": 0.8, "weight": 0.15, "weighted": 12.0, "note": "公网 · 核心业务 · 业务系统一般" }
  ],
  "poc": [{ "link": "https://github.com/...", "insertedAt": "2026-10-20T00:00:00+08:00" }],
  "advice": {
    "fixedVersion": "2.17.1",
    "upgradePath": "2.14.1 → 2.17.1",
    "command": "mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1",
    "note": "升级后需回归 JNDI 相关日志配置"
  },
  "events": [
    { "time": "2026-10-22T09:12:00+08:00", "event": "status: open → fixing", "actor": "李维", "detail": "已排期 10-24 变更窗口" }
  ],
  "ticket": {
    "id": "VA-2026-0137",
    "findingId": 42,
    "cveId": "CVE-2021-44228",
    "assetId": 3,
    "priority": "P0",
    "status": "fixing",
    "assignee": "李维",
    "createdBy": "李维",
    "note": "控制面本地工单，需在变更窗口内完成修复并复扫验证",
    "createdAt": "2026-10-22T09:12:00+08:00",
    "updatedAt": "2026-10-22T09:12:00+08:00"
  }
}
```

`ticket` 仅在该漏洞已创建本地工单时出现；未建单时字段省略。

### PATCH /findings/{id}

```json
{ "status": "fixed", "assignee": "李维" }
```

200：`{ "ok": true, "finding": { ...列表字段 } }`

- 若该漏洞已存在本地工单，状态/责任人会同步到工单，`updatedAt` 一并刷新。

### POST /findings/{id}/ticket

创建（或返回既有）本地工单，幂等：

```json
{
  "ok": true,
  "ticketId": "VA-2026-0137",
  "status": "fixing",
  "created": true,
  "ticket": { "id": "VA-2026-0137", "findingId": 42, "...": "同上" }
}
```

- 首次创建时，`open/triaged` 会流转为 `fixing`；已存在工单返回 `created: false`，不重复建单。
- 建单动作写 `finding.ticket` 审计、追加工单事件，并派发 `ticket.created` webhook。

### GET /api/v1/tickets（operator）

```json
{
  "items": [
    {
      "id": "VA-2026-0137",
      "findingId": 42,
      "cveId": "CVE-2021-44228",
      "assetId": 3,
      "priority": "P0",
      "status": "fixing",
      "assignee": "李维",
      "createdBy": "李维",
      "note": "控制面本地工单，需在变更窗口内完成修复并复扫验证",
      "createdAt": "2026-10-22T09:12:00+08:00",
      "updatedAt": "2026-10-22T09:12:00+08:00"
    }
  ],
  "total": 1
}
```

- 查询参数：`status`（精确匹配）、`limit`（默认 50，上限 200），按 `updated_at` 倒序。

### POST /findings/{id}/rescan

重新匹配该资产并自动收敛漏洞状态（升级至修复版本 / 不再命中 → `verified`，组件移除 → `closed`，版本回退 → 重新打开）。

```json
{
  "ok": true,
  "skipped": false,
  "scanId": "scan-20261022-1015",
  "assetId": 3,
  "created": 0,
  "updated": 5,
  "verified": 2,
  "closed": 0,
  "reopened": 0,
  "status": "verified"
}
```

- `skipped: true` 表示该资产在防抖窗口（`VA_RESCAN_DEBOUNCE`，默认 10 分钟）内已扫描过，本次直接返回，不重复匹配。
- 同时存在后台定时复扫（`VA_RESCAN_INTERVAL`，默认 30 分钟，`0/off` 关闭）。

### GET /reports/findings.pdf（operator+）

按当前筛选条件导出 A4 中文 PDF 报告：页头（生成时间/生成人）、P0–P3 概览与涉及资产数、筛选说明、按风险分降序的明细（最多 300 条）。

查询参数与 `GET /findings` 一致：`priority`、`status`、`q`。

响应：`Content-Type: application/pdf`，`Content-Disposition: attachment; filename="vulnagent-findings-<yyyymmdd-hhmm>.pdf"`。
每次导出写一条 `report.export` 审计；只读角色返回 `403 forbidden`。

### GET /reports/findings.csv（operator+）

同一套筛选与排序，返回 `text/csv; charset=utf-8`（带 UTF-8 BOM），单次上限 5000 条，写 `report.export_csv` 审计。

列：`优先级,CVE,标题,组件,当前版本,修复版本,资产,CVSS,EPSS,风险分,状态`。

### GET /notify-settings（admin）

```json
{
  "url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx",
  "secretSet": true,
  "events": ["finding.new", "ticket.created", "sync.failed", "selfcheck.failed"],
  "catalog": ["finding.new", "ticket.created", "sync.failed", "selfcheck.failed"],
  "lastEvent": "ticket.created",
  "lastStatus": "ok",
  "lastError": "",
  "lastSentAt": "2026-10-23T17:45:25+08:00"
}
```

- 密钥不回显，仅返回 `secretSet`。

### PUT /notify-settings（admin）

```json
{ "url": "https://…", "secret": "可选，留空保持不变", "clearSecret": false, "events": ["finding.new", "sync.failed"] }
```

- `url` 为空表示关闭通知；必须为 http(s)；未知事件返回 `400 bad_request`。

### POST /notify-settings/test（admin）

同步推送一条 `notify.test` 事件，返回 `{ "ok": true, "elapsedMs": 57 }`；失败返回 `502 webhook_failed`。

Webhook 请求体：

```json
{ "event": "ticket.created", "sentAt": "2026-10-23T17:45:25+08:00", "data": { } }
```

请求头：`X-VulnAgent-Event`、`X-VulnAgent-Signature: sha256=<HMAC-SHA256(secret, body)>`（未配置密钥时省略）。

---

## 4. 资产

### GET /assets?q=&env=&status=&assetType=&businessSystem=&tier=&exposure=&owner=&cloudProvider=&includeArchived=&page=1&pageSize=20

```json
{
  "demo": true,
  "total": 12,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "id": 3,
      "hostname": "web-01",
      "ip": "10.20.1.11",
      "os": "debian",
      "osVersion": "12",
      "osArch": "amd64",
      "kernel": "6.1.0-18-amd64",
      "env": "prod",
      "exposure": "public",
      "tier": "core",
      "owner": "交易平台组",
      "source": "agent",
      "agentStatus": "online",
      "lastSeen": "2026-10-22T09:58:00+08:00",
      "assetType": "server",
      "status": "active",
      "businessSystem": "交易系统",
      "department": "基础架构",
      "ownerEmail": "ops@example.com",
      "location": "A机房 3F",
      "cloudProvider": "aliyun",
      "cloudAccount": "prod-main",
      "region": "cn-hangzhou",
      "instanceId": "i-bp1xxxx",
      "mac": "00:50:56:AA:BB:CC",
      "serial": "SN-001",
      "virtualized": "virtual",
      "mergedInto": 0,
      "tags": ["prod", "核心"],
      "components": 214,
      "findings": 11,
      "p0": 2,
      "risk": 96
    }
  ]
}
```

`agentStatus`：`online | offline | stale | none`；`source`：`agent | ssh | container | self`。
`status`：`active | maintenance | retired | merged`；`assetType`：`server | vm | container | network | database | other`。
默认不返回已合并资产（`mergedInto > 0`），`includeArchived=1` 时包含。

### GET /assets/{id}

```json
{
  "demo": true,
  "asset": { ...同上 item },
  "components": [
    { "purl": "pkg:deb/debian/openssl@3.0.11", "name": "openssl", "version": "3.0.11", "ecosystem": "deb", "vendor": "openssl", "product": "openssl", "inferred": false, "findings": 1 }
  ],
  "findings": [ ...同 /findings item ],
  "identifiers": [
    { "id": 1, "assetId": 3, "kind": "hostname", "value": "web-01", "source": "agent", "createdAt": "2026-10-29T10:00:00+08:00" }
  ],
  "changes": [
    { "id": 8, "assetId": 3, "field": "businessSystem", "oldValue": "", "newValue": "交易系统", "actor": "管理员", "source": "manual", "createdAt": "2026-10-29T10:05:00+08:00" }
  ]
}
```

`identifiers.kind`：`hostname | ip | mac | serial | cloud_instance`。`changes` 最多返回最近 100 条。

### PATCH /assets/{id}（operator+）

请求体为稀疏字段，未出现的字段不修改；值会 trim，单字段上限 512 字符。实际发生变化的字段会写入 `asset_changes` 并记录审计 `asset.update`。

```json
{ "businessSystem": "交易系统", "owner": "张三", "ownerEmail": "zhangsan@example.com", "status": "maintenance", "tags": ["prod", "核心"] }
```

```json
{ "ok": true, "asset": { ...同上 item }, "changes": [ { ...同上 change } ] }
```

主机名冲突返回 `409 conflict`；`hostname` 为空返回 `400 bad_request`。

### PUT /assets/{id}/tags（operator+）

```json
{ "tags": ["prod", "核心", "等保三级"] }
```

整体替换标签，返回 `{ "ok": true, "tags": [...] }`；标签会去重、排序，单标签上限 64 字符。

### GET /assets/{id}/changes?limit=100

返回 `{ "items": [ ...同上 change ] }`，`limit` 默认 100、上限 500。

### GET /assets/export（operator+）

按当前列表筛选条件导出 CSV（UTF-8 BOM，最多 5000 行）。表头为中文：主机名、IP、操作系统、系统版本、架构、内核、环境、暴露面、业务等级、资产类型、状态、责任人、责任人邮箱、部门、业务系统、机房位置、云厂商、云账号、区域、实例ID、MAC、序列号、虚拟化、标签、来源。

### POST /assets/import（operator+）

`multipart/form-data`：`file`（CSV，≤5MB / ≤5000 行）、`strategy`（`update` 默认 / `skip` / `create`）、`dryRun`（`true` 时只预览不写入）。
`update` 命中则更新字段；`skip` 只跳过已存在资产，新资产仍会创建；`create` 命中已有资产时记为该行冲突。

表头支持中文或英文别名（如 主机名 / hostname、业务系统 / businessSystem）。身份匹配优先级：云实例 ID → 序列号 → MAC → 主机名 → IP；同一行命中多个资产时返回该行错误，需先人工合并。

```json
{
  "dryRun": false,
  "strategy": "update",
  "total": 2,
  "created": 1,
  "updated": 1,
  "skipped": 0,
  "errors": 0,
  "items": [
    { "row": 2, "action": "created", "assetId": 8, "hostname": "web-01", "message": "已新建资产" },
    { "row": 3, "action": "updated", "assetId": 9, "hostname": "db-01", "message": "已更新 2 个字段", "changed": ["businessSystem", "owner"] }
  ]
}
```

### POST /assets/merge（admin）

```json
{ "sourceId": 9, "targetId": 3 }
```

把源资产的组件、漏洞、工单、标识、标签与关系迁移到目标资产，源资产标记为 `status=merged`、`mergedInto=targetId`，并写入 `merged_into` 关系与两端变更历史；不物理删除源资产。

```json
{ "ok": true, "stats": { "components": 12, "findings": 4, "tickets": 1, "identifiers": 3, "tags": 2, "relations": 0 } }
```

### GET /assets/{id}/telemetry

返回最新一次主机遥测快照与最近 N 个性能采样点（`limit` 默认 48，上限 1000，按时间升序）。

```json
{
  "telemetry": {
    "collectedAt": "2026-10-26T20:02:39+08:00",
    "metrics": {
      "cpuPercent": 20,
      "load1": 0.42, "load5": 0.38, "load15": 0.31,
      "memUsed": 12522741760, "memTotal": 15885082624,
      "swapUsed": 0, "swapTotal": 0,
      "diskReadBps": 0, "diskWriteBps": 0,
      "netRxBps": 2700000, "netTxBps": 12300,
      "uptimeSec": 819321, "processCount": 329
    },
    "hardware": {
      "cpuModel": "AMD Ryzen 7 8845H w/ Radeon 780M Graphics",
      "cpuCores": 8, "cpuThreads": 16, "memTotal": 15885082624,
      "kernel": "10.0.26200", "virtualization": "physical", "serial": "…",
      "disks": [{ "device": "PHYSICALDRIVE0", "model": "Micron_2450…", "serial": "…", "sizeBytes": 1024209543168 }],
      "nics": [{ "name": "Ethernet0", "mac": "00:50:56:AA:BB:CC", "speedMbps": 1000 }]
    },
    "services": [{ "name": "W3SVC", "state": "running", "enabled": true, "detail": "Automatic" }],
    "ports": [{ "proto": "tcp", "addr": "::", "port": 8787, "process": "vulnagent", "pid": 44808 }],
    "processes": [
      { "name": "chrome", "pid": 4321, "memBytes": 2147483648 },
      { "name": "svchost", "pid": 4, "memBytes": 104857600 }
    ]
  },
  "series": [
    { "ts": "2026-10-26T20:02:39+08:00", "cpuPercent": 20, "load1": 0.42,
      "memUsed": 12522741760, "memTotal": 15885082624,
      "netRxBps": 2700000, "netTxBps": 12300, "diskReadBps": 0, "diskWriteBps": 0 }
  ]
}
```

- `telemetry` 为 `null` 表示该资产尚未上报遥测。
- 性能采样写入 `host_metrics`，硬件/服务/端口/进程以最新快照整体替换（`asset_telemetry`）。
- `processes` 为按工作集内存（Windows WorkingSet64 / Linux VmRSS）排序的 Top10，用于定位内存占用最高的进程。
- Windows 的 `load1/5/15` 无对应语义，统一返回 0；网卡 `speedMbps` 已从 bit/s 换算并对异常值归零。

### POST /assets/ssh-scan（operator+）

无 Agent 兜底采集：控制面 SSH 直连目标机执行只读脚本，结果走与 Agent 相同的入库/匹配/收敛流程。
凭据仅用于本次连接，不写入数据库与日志。

```json
{
  "host": "10.20.9.71",
  "port": 22,
  "username": "root",
  "password": "******",
  "privateKey": "",
  "passphrase": "",
  "hostKeyFingerprint": "SHA256:xxxx"
}
```

200：

```json
{
  "ok": true,
  "assetId": 21,
  "components": 6,
  "created": 3,
  "updated": 0,
  "verified": 0,
  "closed": 0,
  "reopened": 0,
  "os": "debian",
  "osVersion": "12.4",
  "hostKeyFingerprint": "SHA256:jkMLzeL/SPsZAkCmgA8z84PWtvPtpWXd2q+rjeZUg8U",
  "elapsedMs": 312
}
```

- `password` 与 `privateKey` 二选一；`hostKeyFingerprint` 留空表示首次连接接受并回报指纹（TOFU），配置后校验不匹配即拒绝。
- 错误：`400 bad_request`（参数缺失）、`502 ssh_scan_failed`（连接/认证/指纹失败）、`422 no_components`（不支持的系统或权限不足）。

### POST /scans（operator+）

批量复扫：对指定资产或全部资产走同一套匹配 + 状态收敛逻辑。

```json
{ "assetIds": [3, 7, 12], "all": false }
```

- `all: true` 时忽略 `assetIds`；两者都为空返回 `400 bad_request`；单次上限 500 台，超出返回 `400 too_many_assets`。
- 处于防抖窗口（`VA_RESCAN_DEBOUNCE`，默认 10 分钟）的资产计入 `skipped`，不重复扫描。

200：

```json
{
  "ok": true,
  "scanned": 12,
  "skipped": 4,
  "created": 0,
  "updated": 56,
  "verified": 0,
  "closed": 0,
  "reopened": 0,
  "items": [
    { "assetId": 3, "skipped": false, "created": 0, "updated": 5, "verified": 0, "closed": 0, "reopened": 0 }
  ]
}
```

- 每次调用写一条 `scan.batch` 审计记录。

### 资产发现（discovery）

网段发现仅允许授权 CIDR，默认白名单为 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`；
任务展开后会校验白名单、主机数上限与端口数量，越权请求返回 `400 cidr_not_allowed` 并写 `discovery.job.reject` 审计。

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/discovery/jobs?status=&page=1&pageSize=20` | viewer+ | 任务列表（按 ID 倒序） |
| POST | `/discovery/jobs` | operator+ | 创建并异步执行发现任务 |
| GET | `/discovery/jobs/{id}` | viewer+ | 任务详情与候选处置统计 |
| POST | `/discovery/jobs/{id}/cancel` | operator+ | 取消 pending/running 任务 |
| GET | `/discovery/candidates?jobId=&decision=&q=&page=1&pageSize=20` | viewer+ | 候选资产列表 |
| POST | `/discovery/candidates/{id}/approve` | operator+ | 确认候选：新建资产或补充已有资产标识 |
| POST | `/discovery/candidates/{id}/ignore` | operator+ | 忽略候选 |
| POST | `/discovery/candidates/{id}/merge` | admin | 合并到指定资产（写入 IP/主机名/MAC 标识） |
| POST | `/discovery/candidates/batch` | operator+ | 批量确认/忽略（单次 ≤200） |
| GET/PUT | `/settings/discovery` | viewer+ / admin | 授权网段、默认端口与限速策略 |

`POST /discovery/jobs`：

```json
{ "name": "办公网巡检", "cidrs": ["10.20.9.0/24"], "ports": [22, 80, 443], "concurrency": 32, "timeoutMs": 600, "reverseDns": true }
```

- `cidrs` 支持 IPv4 网段或单个 IP；不支持 IPv6；`0.0.0.0/0`、白名单外网段、超过 `maxHosts` 的网段一律拒绝。
- `ports` 留空使用策略默认端口；同一时间只允许一个任务执行（`409 job_running`），每小时任务数受 `maxJobsPerHour` 限制（`429 too_many_jobs`）。
- 返回 `202`：`{ "ok": true, "job": { "id": 12, "status": "pending", "total": 256, ... } }`。

`GET /discovery/jobs/{id}`：

```json
{
  "job": { "id": 12, "status": "running", "total": 256, "scanned": 64, "found": 3, "cidrs": "10.20.9.0/24", "ports": "22,80,443", "cancelRequested": false },
  "counts": { "new": 2, "existing": 1 }
}
```

`GET /discovery/candidates` item：

```json
{
  "id": 9, "jobId": 12, "ip": "10.20.9.21", "hostname": "web-01", "mac": "",
  "openPorts": "22,443", "services": "[{\"port\":22,\"banner\":\"SSH-2.0-OpenSSH_9.6\"}]",
  "evidence": "tcp/22 SSH-2.0-OpenSSH_9.6; tcp/443 open",
  "matchedAssetId": 0, "decision": "new", "confidence": 0.6, "assetId": 0
}
```

- `decision`：`new`（新发现）、`existing`（通过主机名/IP 匹配到已有资产）、`approved`、`ignored`、`merged`。
- `POST .../merge` 请求体 `{ "assetId": 3 }`；`POST .../batch` 请求体 `{ "ids": [9,10], "action": "approve|ignore" }`。

策略对象：

```json
{
  "allowedCidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
  "defaultPorts": [22, 80, 443, 3389, 3306, 5432, 6379, 9200],
  "maxHosts": 1024, "maxConcurrency": 64, "timeoutMs": 600,
  "maxPorts": 32, "maxJobsPerHour": 10, "reverseDns": true
}
```

### 业务系统、拓扑、关系与治理

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/business-systems` | viewer+ | 业务系统及资产数（未登记项按一般业务补齐） |
| PUT | `/business-systems/{name}` | admin | 设置重要性 `core/important/normal`，立即重算风险分 |
| DELETE | `/business-systems/{name}` | admin | 删除登记（资产字段保留，重新按一般业务计算） |
| GET | `/topology?businessSystem=&env=` | viewer+ | 拓扑节点、关系边与业务系统列表（≤300 节点） |
| GET | `/assets/{id}/relations` | viewer+ | 资产关系（出入方向 + 对端摘要） |
| POST | `/assets/{id}/relations` | operator+ | 创建关系 `{toAssetId, relation}` |
| DELETE | `/assets/relations/{id}` | operator+ | 删除关系 |
| GET | `/governance/summary?days=7&changeDays=30` | viewer+ | 四类待办数量 |
| GET | `/governance/todos?type=&page=&pageSize=` | viewer+ | 待办列表，type 为 `owner_missing/stale/duplicate/exposure_changed` |
| POST | `/assets/batch` | operator+ | 批量更新责任人/部门/业务系统/状态等（≤200 台） |

`PUT /business-systems/{name}`：

```json
{ "tier": "core", "owner": "张三", "description": "交易主链路" }
```

```json
{ "ok": true, "businessSystem": { "name": "交易系统", "tier": "core" }, "recomputed": 128 }
```

`GET /topology`：

```json
{
  "assets": [
    { "id": 3, "hostname": "web-01", "ip": "10.20.9.21", "businessSystem": "交易系统", "env": "prod",
      "tier": "core", "exposure": "public", "assetType": "server", "status": "active",
      "risk": 96, "findings": 11, "components": 214 }
  ],
  "relations": [ { "id": 1, "fromAssetId": 3, "toAssetId": 4, "relation": "depends_on" } ],
  "businessSystems": [ { "name": "交易系统", "tier": "core", "assetCount": 2 } ],
  "truncated": false, "total": 2
}
```

关系类型：`depends_on | runs_on | member_of | manages | connects_to`。`GET /assets/{id}/relations` 返回
`direction`（`out/in`）与对端资产摘要（hostname/ip/businessSystem/env/risk）。

`POST /assets/batch`：

```json
{ "ids": [3, 4], "patch": { "owner": "张三", "department": "基础架构", "status": "retired" } }
```

```json
{ "ok": true, "updated": 2, "unchanged": 0, "failed": [] }
```

`type` 说明：`owner_missing`（责任人缺失）、`stale`（Agent 资产超过 `days` 天未上报）、
`duplicate`（IP/MAC/序列号相同的资产组，含 `related` 成员）、`exposure_changed`（`changeDays` 天内暴露面变更）。

### 集成中心（云厂商 / 外部 CMDB，admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/integrations` | 集成源列表（不含凭据，返回 `hasCredential`） |
| POST | `/integrations` | 新增集成源 |
| PUT | `/integrations/{id}` | 更新配置 / 凭据 / 启停 / 间隔 |
| DELETE | `/integrations/{id}` | 删除集成源 |
| POST | `/integrations/{id}/test` | 只读拉取样例，不写资产 |
| POST | `/integrations/{id}/sync` | 手动同步一次，写入资产台账 |

集成类型：`cloud_aliyun`（ECS DescribeInstances）、`cloud_aws`（EC2 DescribeInstances）、
`cloud_azure`（ARM 虚拟机列表）、`cmdb_api`（GET JSON）。

`POST /integrations`：

```json
{
  "kind": "cloud_aliyun",
  "name": "生产账号",
  "config": { "region": "cn-hangzhou", "endpoint": "" },
  "credentials": { "accessKeyId": "LTAI...", "accessKeySecret": "..." },
  "enabled": true,
  "intervalMinutes": 360
}
```

- 凭据以 AES-256-GCM 加密存储，接口永不回传明文或密文，仅返回 `hasCredential`。
- `cmdb_api` 的 `config` 为 `{ "url": "...", "authType": "none|bearer|basic" }`，
  凭据为 `{ "token" }` 或 `{ "username", "password" }`。
- 更新时 `credentials` 留空表示保持不变；`clearSecret: true` 清除已有凭据；类型创建后不可修改。

`POST /integrations/{id}/test` 返回（不写库）：

```json
{ "ok": true, "count": 2, "elapsedMs": 12, "sample": [
  { "instanceId": "i-bp1abc", "hostname": "web-01", "privateIp": "10.0.0.10", "osFamily": "linux", "region": "cn-hangzhou" }
] }
```

`POST /integrations/{id}/sync` 返回：

```json
{ "ok": true, "stats": {
  "sourceId": 1, "kind": "cloud_aliyun", "name": "生产账号",
  "fetched": 128, "created": 3, "updated": 12, "unchanged": 113, "failed": 0,
  "finishedAt": "2026-11-01T12:00:00+08:00"
} }
```

- 身份归并顺序：`cloud_instance → serial → mac → hostname → ip`；同一实例命中多个资产时该条计入 `failed`。
- 新资产以 `source=cloud` 建档，写入 `cloud_provider/cloud_account/region/instance_id` 等字段与标识；
  已存在资产仅更新非空字段，不覆盖人工维护的字段为空值。
- 每次同步写 `integration.sync` 审计，失败触发 `integration.sync_failed` Webhook。

### 资产 Webhook 事件

`notify-settings` 支持追加订阅：`asset.created`、`asset.updated`、`asset.merged`、`integration.sync_failed`。
请求头仍为 `X-VulnAgent-Event`，配置密钥时附带 `X-VulnAgent-Signature: sha256=<HMAC>`。

---

## 5. 产品映射（admin）

把发行版/语言包名映射到漏洞库产品名，命中映射的结论会标记 `inferred: true`。

### GET /product-map?q=

```json
{
  "demo": true,
  "total": 7,
  "items": [
    { "eco": "deb", "name": "python3-requests", "product": "requests", "confidence": 1.0, "source": "builtin", "updatedAt": "2026-10-22T22:16:37+08:00" }
  ]
}
```

### PUT /product-map

```json
{ "eco": "deb", "name": "apache2-utils", "product": "apache2", "confidence": 0.9 }
```

200：`{ "ok": true, "mapping": { ... }, "rematched": 16 }`（保存后立即重新匹配全部资产）

### DELETE /product-map?eco=deb&name=apache2-utils

200：`{ "ok": true, "rematched": 16 }`

---

## 6. 自检

### POST /selfcheck/run

返回一次完整自检结果（耗时真实计算，检查项针对真实数据）：

```json
{
  "demo": true,
  "runId": "sc-20261022-101500",
  "startedAt": "2026-10-22T10:15:00+08:00",
  "finishedAt": "2026-10-22T10:15:01+08:00",
  "durationMs": 842,
  "status": "warn",
  "triggeredBy": "张启明",
  "passed": 10,
  "warnings": 2,
  "failed": 0,
  "checks": [
    {
      "id": "db.integrity",
      "group": "数据库",
      "name": "数据库完整性",
      "status": "pass",
      "detail": "quick_check 通过，12 张表",
      "hint": ""
    },
    {
      "id": "auth.default_password",
      "group": "权限与审计",
      "name": "默认口令检测",
      "status": "warn",
      "detail": "3 个账号仍使用初始口令",
      "hint": "首次登录后立即修改口令，或在配置中关闭演示账号"
    }
  ]
}
```

`status`：`pass | warn | fail | skip`。检查分组固定为：
`数据库`、`情报同步`、`采集链路`、`平台自身`、`权限与审计`。

其中 `intel.cve_lag`（CVE 情报新鲜度）按同步周期计算阈值：默认 12h 周期下，滞后 >18h 记 `warn`、>24h 记 `fail`；最近一次同步 `status=fail` 时直接 `fail` 并展示错误原因。`VA_SYNC_INTERVAL=off` 时阈值放宽为 >24h / >48h。

### GET /selfcheck/latest

返回最近一次 run 对象；从未运行时：`{ "demo": true, "run": null }`；有记录时：`{ "demo": true, "run": { ...run } }`。

### GET /selfcheck/history

```json
{ "demo": true, "items": [ { "runId": "sc-...", "finishedAt": "...", "status": "warn", "passed": 10, "warnings": 2, "failed": 0, "durationMs": 842, "triggeredBy": "张启明" } ] }
```

---

## 7. 审计与设置

### GET /audit-logs?page=1&pageSize=20&action=&actor=&q=&from=&to=

- `action`、`actor`：模糊匹配动作与操作人，可传动作前缀（如 `agent.`）。
- `q`：关键字，模糊匹配操作人、动作、对象、说明与来源 IP。
- `from` / `to`：RFC3339 时间边界（含端点），与库内 `created_at` 直接比较，需带时区偏移。

```json
{
  "demo": true,
  "total": 128,
  "page": 1,
  "pageSize": 20,
  "items": [
    { "id": 128, "time": "2026-10-22T09:12:00+08:00", "actor": "李维", "role": "operator", "action": "finding.status", "target": "CVE-2021-44228 @ web-01", "ip": "10.20.9.31", "detail": "open → fixing" }
  ]
}
```

### GET /settings

```json
{
  "demo": true,
  "riskPolicy": { "weights": { "cvss": 0.4, "epss": 0.2, "exploit": 0.25, "asset": 0.15 }, "thresholds": { "p0": 85, "p1": 70, "p2": 50 } },
  "users": [ { "username": "admin", "name": "张启明", "role": "admin", "lastLogin": "2026-10-22T09:00:00+08:00", "disabled": false } ],
  "build": { "version": "0.1.0-dev", "commit": "local", "builtAt": "2026-10-22T00:00:00+08:00", "sbomDigest": "sha256:demo" }
}
```

### GET /settings/runtime（viewer+）

读取网页可调节的运行配置。返回每项的分组、类型、最低角色、来源（db/env/default）、是否需重启；密钥只返回 `hasValue`，不回显值。

```json
{
  "items": [
    { "key": "VA_LLM_MODEL", "group": "AI 模型", "label": "模型名称", "kind": "text", "minRole": "operator", "restart": true,
      "value": "deepseek-v4-1-flash-261017", "hasValue": true, "source": "db", "updatedBy": "va-admin", "updatedAt": "2026-11-02T20:00:00+08:00" },
    { "key": "VA_LLM_API_KEY", "group": "AI 模型", "label": "模型密钥", "kind": "secret", "minRole": "admin", "restart": true,
      "value": "", "hasValue": true, "source": "db", "updatedBy": "va-admin", "updatedAt": "2026-11-02T20:00:00+08:00" }
  ]
}
```

### PUT /settings/runtime（operator+，按项校验角色）

```json
{ "values": { "VA_LLM_MODEL": "deepseek-v4-1-flash-261017", "VA_LLM_BASE_URL": "https://ark.cn-beijing.volces.com/api/v3" } }
```

- 优先级：网页保存值（`app_settings`）> 环境变量/`.env` > 默认值；值为空表示删除覆盖并回落到环境变量。
- 密钥使用 AES-256-GCM 加密存储；请求传 `********` 表示保持原值。
- `operator` 仅可修改 `VA_LLM_MODEL`、`VA_AGENT_CONTEXT_BUDGET`；其余 AI 端点/密钥、同步周期、情报源与安全项仅 `admin`。
- 响应：`{"ok":true,"changed":["…"],"restartRequired":true,"message":"已保存，部分配置需重启服务后生效"}`。
- AI 端点/模型、GPU 端点、同步/复扫周期需重启生效；会话空闲、Cookie Secure 与情报源地址即时生效。
- 校验：URL 必须 http(s)，上下文预算 4000–128000，周期为时长或 `0/off`，布尔为 `1/0`、`on/off`、`true/false`。
- 写审计 `settings.runtime.update`（只记录键名，不记录值）。

### PATCH /settings/risk-policy（admin）

```json
{ "weights": { "cvss": 0.4, "epss": 0.2, "exploit": 0.25, "asset": 0.15 }, "thresholds": { "p0": 85, "p1": 70, "p2": 50 } }
```

200：`{ "ok": true, "riskPolicy": { ... }, "recomputed": 56 }`
校验：权重和必须为 1.0（±0.001），否则 400。

### GET / PUT /settings/ops-policy（admin）

```json
{ "policy": { "readOnly": false, "maxJobsPerHour": 30, "retentionDays": 30 } }
```

- `readOnly=true` 时服务端拒绝写文件、服务变更、快照/恢复与包升级，仅允许只读文件与白名单只读命令。
- `maxJobsPerHour` 按资产统计最近 1 小时作业数，超限入队返回 400；0 表示不限制。
- `retentionDays` 控制作业历史保留，服务启动时清理超期 `host_jobs` 与尝试记录。

### GET /sync/status → `{ "demo": true, "sources": [ ...同 overview.sync ] }`

### POST /sync/osv（admin）

对全部或指定资产做 OSV 精确版本匹配（Go / npm / PyPI / Maven / NuGet / Debian / Alpine 等）：

```json
{ "all": true }
```

200：

```json
{ "ok": true, "assets": 1, "components": 11, "queried": 11, "vulns": 1, "created": 1, "updated": 0, "errors": 0 }
```

- 命中结果写入 `cves` / `cve_affected` / `findings`，并复用状态收敛。
- 审计动作：`sync.osv`。

### POST /sync/{source}（admin，source = cve|poc）

按更新时间增量拉取（情报平台公开接口免费；如平台要求鉴权，再配置 `VULNAGENT_CVE_API_KEY`），返回本次写入结果：

```json
{ "ok": true, "mode": "api", "fetched": 120, "inserted": 118, "updated": 2, "startedAt": "2026-10-22T21:30:00+08:00" }
```

错误：

| HTTP | code | 说明 |
|---|---|---|
| 400 | `no_api_key` | 未配置 `VULNAGENT_CVE_API_KEY`，改用 `vulnagent sync --bundle` 导入离线包 |
| 502 | `sync_failed` | 情报平台不可达或返回错误，`error.message` 给出原因 |

控制面启动后会常驻定时同步：默认每 12 小时（`VA_SYNC_INTERVAL`，设为 `0/off` 关闭）增量同步 `cve` 与 `poc`；启动时若距上次同步已超过一个周期，会先补一次。同步成功/失败都会写审计，失败额外派发 `sync.failed` webhook。

### POST /sync/epss（admin，`Content-Type: text/csv`）

上传 FIRST 格式的 EPSS CSV（`cve,epss,percentile`，≤64MB）。仅更新库内已存在的 CVE，导入后把分值同步到漏洞快照并重算风险分。

```json
{ "ok": true, "mode": "epss-csv", "rows": 8, "matched": 7, "unmatched": 1, "invalid": 0, "recomputed": 58, "cursor": "2026-10-22T22:01:00+08:00" }
```

错误：`400 epss_import_failed`（CSV 无有效数据或解析失败）。

### GET /healthz

```json
{ "ok": true, "version": "0.1.0-dev", "demo": true }
```

- `demo` 表示当前是否为演示数据模式（`VA_SEED_DEMO=off` 时为 false），登录页据此决定是否展示演示账号。

### GET /trajectory?kind=&limit=100

统一操作轨迹，聚合 `audit_logs`、`host_jobs` 与 `agent_tool_calls`，按时间倒序。`kind` 可选 `audit | job | tool`。

```json
{
  "items": [
    { "id": "JOB-…", "kind": "job", "time": "2026-10-26T20:20:00+08:00", "actor": "李维",
      "action": "run_command", "target": "asset:1", "status": "succeeded", "detail": "storyseeker" },
    { "id": "audit-128", "kind": "audit", "time": "2026-10-26T20:19:00+08:00", "actor": "李维",
      "action": "host.job.queue", "target": "JOB-…", "status": "recorded", "detail": "run_command @ asset:1" }
  ],
  "total": 2
}
```

### GET /metrics

Prometheus 文本格式（`text/plain; version=0.0.4`）。允许登录会话或 Agent Bearer 令牌访问，便于 Prometheus 抓取。

```
vulnagent_findings_total{priority="P0"} 17
vulnagent_findings_status{status="open"} 23
vulnagent_assets 16
vulnagent_components 184
vulnagent_cves 32
vulnagent_agents_online 11
vulnagent_selfcheck_failed 0
```

### GET /reports/findings.json（operator+）

同一套筛选与排序，返回：

```json
{
  "demo": true,
  "total": 60,
  "assets": 15,
  "byPriority": { "P0": 17, "P1": 13, "P2": 23, "P3": 7 },
  "limit": 5000,
  "items": [ { "priority": "P0", "cveId": "CVE-2021-44228", "title": "…", "component": "log4j-core", "version": "2.14.1", "fixedVersion": "2.17.1", "hostname": "web-01", "status": "open", "cvss": 10, "epss": 0.94, "risk": 99 } ]
}
```

导出写 `report.export_json` 审计。

---

## 8. Agent 上报（Bearer 令牌）

- 认证：`Authorization: Bearer <token>`，与人类用户会话相互独立；无令牌或令牌错误返回 401。
- 令牌由控制面首次启动生成，写入 `<数据目录>/agent.token`（仅本机可读），数据库只保存 SHA-256 摘要；也可用环境变量 `VA_AGENT_TOKEN` 覆盖。

### POST /agent/report

```json
{
  "hostname": "web-01",
  "ip": "10.20.1.11",
  "os": "debian",
  "os_version": "12",
  "collected_at": "2026-10-22T20:00:00+08:00",
  "mode": "full",
  "components": [
    {
      "purl": "pkg:deb/debian/openssl@3.0.11?arch=amd64",
      "name": "openssl",
      "version": "3.0.11",
      "eco": "deb",
      "vendor": "debian",
      "product": "openssl",
      "source": "dpkg"
    }
  ],
  "self_sbom": [
    { "purl": "pkg:golang/golang.org/x/crypto@v0.58.0", "name": "golang.org/x/crypto", "version": "v0.58.0", "eco": "golang", "vendor": "golang", "product": "golang.org/x/crypto", "source": "self" }
  ]
}
```

200：

```json
{ "ok": true, "assetId": 13, "components": 225, "created": 5, "updated": 0, "matchedAt": "2026-10-22T20:00:01+08:00" }
```

行为：按 hostname upsert 资产 → 整体替换组件清单 → 清理已移除组件的未处置漏洞 → 按版本区间重新匹配（已有漏洞保留状态/责任人/工单）。上报体可携带 `telemetry`（见 §6 遥测字段），服务端写入 `host_metrics` 与 `asset_telemetry`。

### GET /agent/jobs?hostname=web-01

返回该主机当前到期、待执行的作业（最多 5 条，按创建时间升序）。

```json
{
  "jobs": [
    {
      "id": "JOB-7f3a1c9e2b4d5a6c",
      "assetId": 13,
      "action": "run_command",
      "params": "{\"argv\":[\"systemctl\",\"status\",\"nginx\"]}",
      "risk": "high",
      "status": "pending",
      "requestedBy": "李维",
      "attempts": 0,
      "maxAttempts": 3,
      "createdAt": "2026-10-26T20:00:00+08:00",
      "signature": "hmac-sha256-hex"
    }
  ]
}
```

- `signature = HMAC-SHA256(token, job.id + "|" + job.action + "|" + job.params)`；Agent 必须校验后再执行，签名不符直接丢弃。
- 同一资产存在 `running` 作业时不再派发新作业，避免并发变更。

### POST /agent/jobs/{id}/claim

请求 `{ "hostname": "web-01" }`。原子抢占成功返回 `{ "job": { ... } }`；作业已被取走、主机不匹配或未到重试时间返回 `409 not_available`。

### POST /agent/jobs/{id}/result

```json
{
  "hostname": "web-01",
  "status": "failed",
  "output": "",
  "error": "连接超时",
  "exitCode": -1,
  "durationMs": 12000,
  "retryable": true
}
```

- `status` 仅接受 `succeeded | failed`。
- 失败且 `retryable=true` 且未超过最大次数时，服务端按指数退避 + 抖动写入 `next_run_at`，作业回到 `pending`；响应 `retryScheduled: true`。
- 作业不属于该 hostname 时返回 `403 forbidden`。

### GET /assets/{id}/jobs?limit=50

控制台查看资产作业历史，返回 `{ "items": [ ...同作业字段 ], "total": 3 }`；作业输出与错误会脱敏后展示。

---

## 9. 演示账号

仅在 `VA_SEED_DEMO=on`（或 `1/true/yes`）时首次启动创建；默认关闭。生产模式同时设置 `VA_ADMIN_PASSWORD`，只初始化一个 admin 账号。

| 账号 | 口令 | 角色 | 显示名 |
|---|---|---|---|
| admin | Admin@12345 | admin | 张启明 |
| operator | Ops@12345 | operator | 李维 |
| viewer | View@12345 | viewer | 陈可 |

---

## 10. 业务字典 `GET /meta`

登录后任意角色可读，前端据此渲染枚举，避免字典在前端重复维护。

```json
{
  "version": "0.1.0-dev",
  "demo": false,
  "statuses": [{ "value": "open", "label": "待处理" }],
  "priorities": [{ "value": "P0", "label": "立即处置" }],
  "roles": [{ "value": "admin", "label": "管理员" }],
  "exposures": [{ "value": "public", "label": "公网" }],
  "tiers": [{ "value": "core", "label": "核心" }],
  "ecosystems": ["apk", "deb", "golang", "maven", "npm", "pypi", "rpm"],
  "defaultPolicy": { "weights": { "cvss": 0.4, "epss": 0.2, "exploit": 0.25, "asset": 0.15 },
                     "thresholds": { "p0": 85, "p1": 70, "p2": 50 } },
  "riskFormula": "100 × (0.40·CVSS/10 + 0.20·EPSS + 0.25·在野利用 + 0.15·资产权重)",
  "passwordPolicy": { "minLength": 10, "requireLetterDigit": true, "requireDiffFromOld": true,
                      "sessionIdleMinutes": 30, "loginLockoutMinutes": 5 },
  "harnessEnabled": true
}
```

`statuses` 顺序即前端展示顺序，共 8 种状态；`harnessEnabled` 为 false 时助手页显示配置提示。

---

## 11. Agent 助手（Harness）

模型凭据通过 `VA_LLM_BASE_URL`、`VA_LLM_API_KEY`、`VA_LLM_MODEL` 注入（通用 OpenAI 兼容协议），三项齐备才启用。未启用时相关接口返回 `503 harness_disabled`。

### GET /agent/tools

```json
{ "enabled": true, "model": "deepseek-v4-1-flash-261017",
  "tools": [{ "name": "list_findings", "description": "…", "risk": "low",
              "readOnly": true, "minRole": "viewer", "params": { "type": "object" } }] }
```

工具共 32 个，静态注册，按角色裁剪；**不暴露** SSH 扫描、令牌轮换、账号增删改、策略修改、shell、任意 SQL/URL。

| 风险 | 工具 |
|---|---|
| low（只读，直接执行） | overview_summary、list_assets、get_asset、host_metrics、host_hardware、list_skill_files、read_skill_file、list_findings、get_finding、search_cves、get_cve、list_product_map、get_sync_status、get_selfcheck_latest、list_host_jobs、get_host_job |
| low（operator） | host_diagnose、recall_memory |
| low（admin） | list_audit_logs |
| medium（需审批） | rescan_asset、read_host_file、create_snapshot、remember |
| medium（admin，需审批） | run_selfcheck |
| high（需审批 + 口令再认证） | update_finding_status、create_ticket、run_host_command、write_host_file、service_action、restore_snapshot、apply_remediation |
| high（admin，需审批 + 口令再认证） | upsert_product_map |

### GET /agent/skills

返回从 `skills/` 加载的运维技能（启动时自动解压 `skill/*.zip`）：

```json
{ "skills": [
  { "id": "tencentos-expert", "displayName": "TencentOS Server 全栈运维诊断",
    "description": "…", "version": "2.1.0", "platforms": ["linux"] },
  { "id": "winskill", "displayName": "Windows 服务器运维工具箱",
    "description": "…", "version": "3.4.0", "platforms": ["windows"] }
] }
```

前端在输入框键入 `/` 时展示该列表；选中后下一条消息携带 `skillId`。服务端在会话中注入一条 `[skill]` 系统消息（同一技能只注入一次），模型通过 `list_skill_files` / `read_skill_file`（支持 `startLine` / `maxLines`，单次 ≤400 行/64KB）按需加载 `SKILL.md`、`guides/` 与 `references/`，再调用 `host_diagnose`、`host_metrics` 等工具执行诊断。退出技能后自动写入退出标记；`GET /agent/sessions/{id}/messages` 额外返回 `activeSkillId` 供前端恢复技能 chip。

### POST /agent/sessions

请求 `{ "title": "排查 P0", "approvalMode": "each" }`，返回 `{ "session": { "id": "…", "owner": "admin", "approvalMode": "each", … } }`。会话按账号隔离，他人会话一律 403。

`approvalMode` 为会话级权限，缺省 `each`：

| 值 | 名称 | 行为 |
|---|---|---|
| `each` | 每次审批 | 所有 medium/high 工具都必须人工点击批准；high 还需口令再认证 |
| `smart` | 智能审批 | 由模型判断能否自动执行；拿不准、判断失败或解析失败一律转人工审批 |
| `full` | 完全操作 | medium/high 工具直接执行，不再弹审批；工具调用记录 `approver=auto:full`，审批模式切换写审计 |

切换模式：`PATCH /agent/sessions/{id}`，请求 `{ "approvalMode": "smart" }`，返回 `{ "session": {…} }`；仅会话属主可改，变更写 `agent.session.mode` 审计。

### GET /agent/sessions

返回当前账号最近 50 个会话，按更新时间倒序。

### GET /agent/sessions/{id}/messages

返回 `{ "session": {…}, "messages": [ { "role": "user|assistant|tool", "content": "…", "toolCalls": "[]", "toolCallId": "" } ], "pendingApprovals": [ …Approval ] }`。

`pendingApprovals` 为该会话仍在有效期内（10 分钟）的待审批记录，用于刷新页面后恢复审批卡；已过期或已处理的记录不会返回。

### POST /agent/sessions/{id}/messages

请求 `{ "content": "…", "skillId": "tencentos-expert" }`（`skillId` 可省略；未知技能返回 `400 bad_request`），响应为 `text/event-stream`，每行 `data: <json>`：

| type | data | 说明 |
|---|---|---|
| message | `{role, content, toolCalls?}` | 用户或助手消息 |
| tool_call | `{id, tool, args}` | 模型发起工具调用 |
| tool_result | `{tool, ok, result}` | 工具结果（已脱敏） |
| approval_required | `{…Approval}` | 写操作等待审批，本轮暂停 |
| done | `{steps, waitingApproval?}` | 本轮结束 |
| error | `{message}` | 执行失败 |

### POST /agent/sessions/{id}/resume

审批处理完成后继续本轮对话，响应同为 SSE。存在未处理审批时返回 `409 approval_pending`。

### POST /agent/approvals/{id}

请求 `{ "decision": "approve|reject", "password": "…" }`。

- 审批一次性：`approved` 后立即消费，重复处理返回 `409 approval_expired`。
- 审批绑定「会话 + 用户 + 工具 + 参数 SHA-256」，参数变化即失效；有效期 10 分钟。
- high 风险必须携带当前账号口令（或 5 分钟内的再认证记录），否则返回 `401 reauth_required`。
- 批准后立即执行工具并写入工具结果消息，前端再调用 `resume` 让模型汇总。

九道执行闸门：静态工具表 → 参数 JSON ≤ 64KB → 角色最小权限 → 每会话 20 次/分钟 → 风险分级 → 参数指纹绑定 → 一次性消费 + TTL → 高风险口令再认证 → 每轮最多 6 步。所有调用写入 `agent_tool_calls`，审批写入 `agent_approvals` 并记审计。

---

## 12. SSH 智能终端

主机凭据使用 AES-256-GCM 加密保存在数据目录，密钥文件 `<数据目录>/ssh.key` 首次使用时自动生成（0600），可用 `VA_SSH_KEY`（32 字节 base64）覆盖。所有接口只返回 `hasSecret`，永不回显口令、私钥与私钥口令。

### GET /ssh/hosts（viewer+）

```json
{
  "items": [
    {
      "id": 1,
      "name": "web-01",
      "host": "10.0.0.12",
      "port": 22,
      "username": "root",
      "authType": "password",
      "hostKey": "SHA256:…",
      "note": "生产 Web",
      "tags": "prod, web",
      "createdBy": "va-admin",
      "createdAt": "2026-10-27T10:30:00+08:00",
      "updatedAt": "2026-10-27T10:30:00+08:00",
      "lastConnectedAt": "2026-10-27T10:36:00+08:00",
      "hasSecret": true,
      "gpuAccel": false
    }
  ]
}
```

### POST /ssh/hosts（operator+）

```json
{ "name": "web-01", "host": "10.0.0.12", "port": 22, "username": "root",
  "authType": "password", "password": "…", "privateKey": "", "passphrase": "",
  "note": "生产 Web", "tags": "prod, web", "gpuAccel": false }
```

- `authType=password` 需要 `password`；`authType=key` 需要 `privateKey`，可选 `passphrase`。
- 同一 `host + port + username` 重复时返回 `409 host_exists`。

### PATCH /ssh/hosts/{id}（operator+）

字段均可选；`password` / `privateKey` 留空表示保持原值；切换认证方式必须同时提供新凭据；地址或端口变化会清空已信任指纹；`clearHostKey=true` 可主动清除指纹；`gpuAccel` 为该主机的服务加速开关。

### DELETE /ssh/hosts/{id}（operator+）

`{ "ok": true }`。删除主机不会删除历史审计与会话记录。

### POST /ssh/hosts/{id}/test（operator+）

```json
{ "ok": true, "fingerprint": "SHA256:…", "serverVersion": "SSH-2.0-OpenSSH_9.6",
  "elapsedMs": 42, "trusted": true }
```

首次连接记录 TOFU 指纹；指纹不匹配或连接失败返回 `502 ssh_failed`。

### GET /ssh/sessions?limit=50（viewer+）

```json
{ "items": [
  { "id": "9f2c…", "hostId": 1, "hostName": "web-01", "addr": "10.0.0.12:22",
    "actor": "王浩", "role": "operator", "status": "connected", "error": "",
    "clientIp": "127.0.0.1", "startedAt": "…", "endedAt": "",
    "bytesIn": 128, "bytesOut": 4096 }
] }
```

`status` 取值：`connected | closed | failed`。

### GET /ssh/terminal?hostId=1&cols=120&rows=32（WebSocket，operator+）

同源 Cookie 会话鉴权后升级为 WebSocket。

| 方向 | 消息 |
|---|---|
| 客户端 → 服务端 | `{"type":"input","data":"ls\r"}`、`{"type":"resize","cols":140,"rows":40}`、`{"type":"ping"}` |
| 服务端 → 客户端 | `{"type":"status","status":"connected","sessionId":"…","fingerprint":"SHA256:…","serverVersion":"…"}` |
| 服务端 → 客户端 | `{"type":"output","data":"<base64>"}` |
| 服务端 → 客户端 | `{"type":"exit","code":0}`、`{"type":"error","message":"…"}`、`{"type":"pong"}` |

输出使用 base64 以保留二进制字节。连接、断开与用户输入的命令分别写入 `ssh_sessions`、`ssh_events` 与审计日志。

### POST /ssh/assistant（operator+）

```json
{ "hostId": 1, "question": "解释最近输出",
  "context": "$ df -h\nFilesystem …", "sessionId": "9f2c…" }
```

```json
{ "answer": "根分区使用率 88%，建议…", "commands": ["df -i", "journalctl --disk-usage"], "model": "deepseek-v4-1-flash-261017", "accelerated": false,
  "context": { "usedTokens": 4210, "budgetTokens": 16000, "percent": 26.3, "compressedItems": 2, "savedTokens": 860, "historyItems": 10 } }
```

- `question` 上限 2000 字符，`context` 上限 8000 字符（前端只发送最近终端输出）。
- 历史超过 8 条或 6000 字时，较早对话会压缩成一段摘要，`context.compressedItems` 表示被压缩条数。
- 主机开启 GPU 加速且服务端已配置 GPU 端点时，请求走 GPU 端点，响应 `accelerated=true`，`model` 为 GPU 端点模型。
- 模型未配置返回 `503 llm_unavailable`；调用失败返回 `502 llm_failed`。
- 返回命令只是建议，前端默认仅插入终端，执行前需要人工二次确认。

### POST /ssh/agent/run（SSE，operator+）

请求：

```json
{ "hostId": 1, "goal": "检查磁盘使用率并找出占用最大的目录", "mode": "safe" }
```

`mode` 取值：

| 值 | 行为 |
|---|---|
| `confirm` | 每条命令执行前都等待人工批准 |
| `safe` | 只读命令直接执行；high / critical 需要批准（默认） |
| `auto` | 除 critical 外直接执行；critical 始终需要批准 |

响应 `text/event-stream`，每行 `data: <json>`：

| type | data | 说明 |
|---|---|---|
| `status` | `{runId, mode, maxSteps, host}` | 运行开始 |
| `step` | `{index, thought, command, risk, approval}` | 规划出的命令；`risk` 为 `normal/high/critical`，`approval` 为 `pending/not_required` |
| `await_approval` | `{approvalId, index, command, risk, reason}` | 等待人工批准（5 分钟有效） |
| `approval_result` | `{index, approved}` | 审批结果 |
| `output` | `{index, output, exitCode}` | 命令输出（单步最多 16KB） |
| `done` | `{runId, steps, summary, truncated}` | 结束；达到步数上限时 summary 为模型生成的收尾结论 |
| `error` | `{message}` | 运行失败 |

- 每次运行最多 8 步；单条命令 90 秒超时；运行与每一步写入 `ssh_agent_runs` / `ssh_agent_steps`。
- 运行与当前浏览器 SSE 连接绑定，断开即终止；审计记录 `ssh.agent.run` / `ssh.agent.done`。

### POST /ssh/agent/approvals/{id}（operator+）

```json
{ "decision": "approve" }
```

- `decision` 为 `approve` 或 `reject`；审批不存在或已失效返回 `404 not_found`。

### GET /ssh/agent/runs?hostId=1&limit=20（viewer+）

```json
{ "items": [
  { "id": "55b9…", "hostId": 1, "hostName": "web-01", "actor": "王浩", "role": "operator",
    "goal": "检查磁盘…", "mode": "safe", "status": "completed", "steps": 8,
    "summary": "…", "error": "", "startedAt": "…", "endedAt": "…" }
] }
```

### GET /ssh/agent/runs/{id}（viewer+）

返回 `{ "run": {…}, "steps": [ { "index": 0, "thought": "…", "command": "df -h", "output": "…", "risk": "normal", "approved": "auto", "exitCode": 0, "createdAt": "…" } ] }`，用于审计与复盘。

### 12.1 SFTP 文件管理（operator+）

路径参数统一使用绝对路径，后端会 `path.Clean` 归一化；空路径返回 `400 bad_request`，根目录 `/` 不可删除。

#### GET /ssh/files/list?hostId=1&path=/var/log

```json
{
  "host": "web-01",
  "path": "/var/log",
  "parent": "/var",
  "truncated": false,
  "items": [
    { "name": "syslog", "path": "/var/log/syslog", "dir": false, "size": 4096,
      "mode": "-rw-r-----", "modified": "2026-10-27T11:42:45+08:00", "symlink": false }
  ]
}
```

- 目录优先、名称不区分大小写排序；单次最多返回 2000 项，超出时 `truncated=true`。
- 软链接会额外 `stat` 一次以判定真实类型；`parent` 在根目录时为空字符串。
- 目录不存在或不可读返回 `404 not_found`；SSH/SFTP 连接失败返回 `502 sftp_failed`。

#### GET /ssh/files/preview?hostId=1&path=/etc/hosts

```json
{ "path": "/etc/hosts", "binary": false, "truncated": false, "content": "127.0.0.1 localhost\n",
  "size": 24, "modified": "2026-10-27T11:42:45+08:00" }
```

- 仅用于小文本文件：超过 2MB 返回 `413 too_large`；内容最多返回前 256KB（`truncated=true`）。
- 包含 NUL 字节时 `binary=true`，前端提示改为下载。

#### GET /ssh/files/download?hostId=1&path=/var/log/syslog

- 返回 `application/octet-stream` 与 `Content-Disposition: attachment`，支持 `Range`（`http.ServeContent`）。
- 目标不存在 `404 not_found`；目标是目录 `400 bad_request`。

#### POST /ssh/files/upload?hostId=1

`multipart/form-data`：

| 字段 | 位置 | 说明 |
|---|---|---|
| `hostId` | query | 主机 ID |
| `path` | form | 目标目录（绝对路径） |
| `file` | form | 文件内容，单文件上限 256MB |

- 使用临时文件名写入后再 `rename`，避免半写文件；同名文件会被覆盖，同名目录返回 `409 is_dir`。
- 200：`{ "ok": true, "path": "/var/log/app.log", "size": 1024 }`。

#### POST /ssh/files/mkdir

```json
{ "hostId": 1, "path": "/opt/backup/2026-10" }
```

- `path` 是完整目标路径，使用 `MkdirAll` 语义；200：`{ "ok": true, "path": "…" }`。

#### POST /ssh/files/rename

```json
{ "hostId": 1, "from": "/opt/a.txt", "to": "/opt/b.txt" }
```

- 同时支持重命名与跨目录移动；目标已存在时的行为由远端 SFTP 服务决定。

#### DELETE /ssh/files?hostId=1&path=/opt/backup&recursive=true

- 文件直接删除；目录非空且未传 `recursive=true` 时返回 `409 dir_not_empty`，前端据此弹出递归确认。
- 递归删除先 `Walk` 收集路径（上限 5000 条）再逆序删除；删除根目录返回 `400 bad_request`。

#### POST /ssh/files/save

```json
{ "hostId": 1, "path": "/etc/nginx/nginx.conf", "content": "…" }
```

- 在线编辑保存，`content` 上限 256KB（超过返回 `400 bad_request`）。
- 同样采用「临时文件 + rename」原子替换，文件权限重置为远端默认（通常 0644 受 umask 影响），原有权限位不保留。
- 200：`{ "ok": true, "path": "…", "size": 1234 }`。

> 所有 SFTP 操作都会写审计：`ssh.file.list` 不记录，`ssh.file.read` / `ssh.file.download` / `ssh.file.upload` / `ssh.file.save` / `ssh.file.mkdir` / `ssh.file.rename` / `ssh.file.delete` 记录主机名与目标路径（上传附带字节数）。

### 12.2 会话录制与回放

终端会话的输出会按时间偏移异步写入 `ssh_recordings`（元数据）与 `ssh_recording_chunks`（分片，`data` 为 base64），单会话原始输出上限 2MB，超出后 `truncated=true`。

`GET /ssh/sessions` 的每条记录新增：

| 字段 | 说明 |
|---|---|
| `hasRecording` | 是否有可回放分片 |
| `recordingBytes` | 录制的原始输出字节数 |
| `recordingMs` | 会话时长（毫秒） |
| `recordingTruncated` | 是否因超过上限被截断 |

#### GET /ssh/sessions/{id}/recording（viewer+）

```json
{
  "sessionId": "0f5d52af…",
  "hostName": "web-01",
  "actor": "王浩",
  "startedAt": "2026-10-28T00:21:30+08:00",
  "endedAt": "2026-10-28T00:23:06+08:00",
  "durationMs": 96000,
  "bytes": 307,
  "truncated": false,
  "chunks": [
    { "offsetMs": 0, "data": "G1sySj4…" },
    { "offsetMs": 420, "data": "ZWNobyBoaQ==" }
  ]
}
```

- `chunks` 按 `seq` 升序返回，`offsetMs` 为相对会话开始的毫秒偏移，前端按偏移与播放倍速重放。
- 无录制返回 `404 not_found`；只有产生过输出的会话才会保留记录（空会话在结束时删除）。

### 12.3 快捷命令（脚本库）

#### GET /ssh/snippets?limit=100（viewer+）

```json
{ "items": [
  { "id": 1, "name": "磁盘巡检", "command": "df -hT", "description": "查看磁盘使用率",
    "tags": "disk", "createdBy": "va-admin", "createdAt": "…", "updatedAt": "…", "usageCount": 12 }
] }
```

按 `usageCount` 降序、`updatedAt` 降序返回，最多 200 条。

#### POST /ssh/snippets（operator+）

```json
{ "name": "磁盘巡检", "command": "df -hT", "description": "查看磁盘使用率", "tags": "disk" }
```

- 名称 1–64 字符；命令必填、≤2000 字节且必须为单行；说明 ≤200 字符；标签 ≤120 字符。
- 200：`{ "snippet": {…} }`；写审计 `ssh.snippet.create`。

#### PATCH /ssh/snippets/{id}（operator+）

请求体同上，整体覆盖；不存在返回 `404 not_found`；写审计 `ssh.snippet.update`。

#### DELETE /ssh/snippets/{id}（operator+）

200：`{ "ok": true }`；写审计 `ssh.snippet.delete`。

#### POST /ssh/snippets/{id}/use（operator+）

```json
{ "hostNames": ["web-01", "web-02"], "broadcast": true }
```

- 累加 `usage_count` 并写审计 `ssh.snippet.use`（目标包含主机名与是否广播），用于排序与追溯。
- 200：`{ "ok": true, "usageCount": 13 }`。

### 12.4 会话协同

分享链接只对**在线会话**有效，令牌使用 SHA-256 存储、明文只返回一次；所有接口要求登录，可写权限仅对 operator 及以上角色生效（viewer 打开可写链接自动降级为只读）。

#### POST /ssh/sessions/{id}/share（operator+）

```json
{ "permission": "read", "ttlMinutes": 60 }
```

- `permission`：`read` | `write`；`ttlMinutes` 默认 60，范围 5–1440。
- 200：

```json
{ "token": "P9RUhHHU…", "path": "/share/P9RUhHHU…", "permission": "read",
  "expiresAt": "2026-10-28T02:03:00+08:00", "sessionId": "ed58e39c…", "hostName": "web-01" }
```

- 会话不在线返回 `409 session_not_live`；写审计 `ssh.share.create`。

#### GET /ssh/sessions/{id}/shares（operator+）

```json
{ "items": [
  { "id": 3, "permission": "read", "createdBy": "va-admin",
    "createdAt": "2026-10-28T01:03:00+08:00", "expiresAt": "2026-10-28T02:03:00+08:00" }
] }
```

- 只返回未过期的链接，不含令牌明文。

#### DELETE /ssh/shares/{id}（operator+）

200：`{ "ok": true }`；立即失效并写审计 `ssh.share.revoke`。

#### GET /ssh/shared/{token}/info（viewer+）

```json
{ "sessionId": "ed58e39c…", "hostName": "web-01", "addr": "10.0.0.1:22", "owner": "va-admin",
  "permission": "read", "canWrite": false, "expiresAt": "…", "viewers": 1, "serverVersion": "SSH-2.0-OpenSSH_9.6" }
```

- 链接不存在 `404 not_found`，过期 `410 share_expired`，会话已结束 `410 session_ended`。
- `canWrite` 是结合链接权限与当前用户角色后的实际能力。

#### GET /ssh/shared/{token}（WebSocket，viewer+）

帧格式与终端一致：

| type | 方向 | 说明 |
|---|---|---|
| `status` | 服务端 | `{sessionId, hostName, permission, canWrite, serverVersion, viewers}` |
| `output` | 服务端 | 当前输出（base64）；加入时先发送最近 16KB 快照 |
| `viewers` | 服务端 | 协作者人数变化 |
| `exit` | 服务端 | 主会话结束 |
| `input` | 客户端 | 仅 `canWrite=true` 时写入远端 PTY，并记录 `ssh_events`（kind=`shared_input`） |
| `ping/pong` | 双向 | 保活 |

- 加入与退出写审计 `ssh.share.join`；只读连接丢弃所有输入。

### 12.5 命令参考检索（AI 与 Agent）

为避免模型臆造命令参数，AI 问答与 Agent 会先从公共命令示例库 `cheat.sh` 检索相关命令（常见命令白名单 + 中文关键词映射，最多 3 个主题），清洗 HTML/ANSI 后作为「命令参考资料」注入提示，并明确要求先在目标机用 `command -v` / `--help` 验证。

- 缓存：主题级内存缓存 10 分钟，单次检索 8 秒超时，最多 3 个并发主题。
- 失败降级：检索失败不阻塞回答，返回 `referenceError` 并在界面提示。
- 参考内容仅用于提示，不直接执行；命令执行仍走原有的插入/确认/审批流程。

`POST /ssh/assistant` 请求新增可选字段：

```json
{
  "hostId": 1,
  "question": "tar 如何解压到指定目录",
  "context": "…",
  "search": true,
  "history": [
    { "role": "user", "content": "这台主机的磁盘快满了" },
    { "role": "assistant", "content": "建议先查看 df -h 与 du 的差异" }
  ]
}
```

`history` 仅接受 `user` / `assistant`，服务端只保留最近 8 条、单条 1500 字、总计 6000 字，用于多轮对话与指代消解；`search` 缺省为 `true`。响应新增：

```json
{
  "answer": "…",
  "commands": ["tar -xf a.tar -C /tmp/out"],
  "model": "…",
  "references": [
    { "topic": "tar", "title": "tar", "url": "https://cheat.sh/tar", "snippet": "GNU version of the tar archiving utility · …" }
  ],
  "referenceError": ""
}
```

Agent 的 `status` 事件新增：

```json
{ "type": "status", "data": { "runId": "…", "host": "web-01", "search": true, "contextRuns": 2, "accelerated": false, "model": "deepseek-v4-1-flash-261017", "references": [ … ], "referenceError": "" } }
```

`POST /ssh/agent/run` 请求新增可选字段 `search`（缺省 `true`）：

```json
{ "hostId": 1, "goal": "排查最近异常登录", "mode": "safe", "search": true }
```

- 本地关键词无法判断命令主题时，会额外调用一次模型提取 1–3 个命令名（只输出 JSON 数组），再检索参考。
- Agent 在每一步决策前都会携带参考块，并新增「不熟悉参数必须先 `command -v` / `--help` 验证」的约束。
- `contextRuns` 表示注入了同一主机最近多少次已完成任务的结论（最多 3 次）。

**模型输出容错**：决策 JSON 解析兼容 Markdown 围栏、前后解释、尾逗号、中文引号；解析失败时会把原始输出回填给模型要求重写，并对临时模型错误自动重试（单步最多 2 次）。连续失败时发送 `warning` 事件并以 `done` 优雅结束（`truncated=true`），已执行步骤与输出全部保留，不再直接中断任务。

| type | data | 说明 |
|---|---|---|
| `warning` | `{message}` | 自动重试、格式修复或提前结束提示 |
| `context` | `{usedTokens, budgetTokens, percent, compressedItems, savedTokens, historyItems, step}` | 每次模型调用前的上下文占用与压缩统计 |
| `done` | `{runId, steps, summary, truncated}` | `truncated=true` 表示因模型格式异常提前结束 |

### 12.6 SSH 主机漏洞扫描

复用已保存的 SSH 主机凭据执行只读软件清单采集（deb/rpm/apk），结果直接写入资产与漏洞流水线，让终端主机可以参与现有漏洞运营。

#### POST /ssh/hosts/{id}/scan（operator+）

无请求体（`{}` 即可）。连接使用主机已保存的加密凭据与 TOFU 指纹，采集脚本只读，不修改目标机。

200：

```json
{
  "ok": true, "assetId": 653, "hostId": 7, "hostName": "web-01", "host": "10.0.0.1",
  "username": "root", "scanUser": "va-admin",
  "components": 3, "created": 2, "updated": 1, "verified": 0, "closed": 0, "reopened": 0,
  "os": "ubuntu", "osVersion": "22.04",
  "hostKeyFingerprint": "SHA256:…", "elapsedMs": 135
}
```

- 凭据不可用：`400 credential_error`；主机不存在：`404 not_found`。
- SSH 连接或采集失败：`502 ssh_scan_failed`；未采集到软件包：`422 no_components`。
- 首次扫描若主机未记录指纹，会回写 TOFU 指纹；写审计 `scan.ssh`（成功/失败均记录）。

### 12.7 SSH 主机性能采样

#### GET /ssh/hosts/{id}/metrics（viewer+）

只读采集一次主机性能，不写审计、不修改目标机。连接从只读 SSH 连接池获取（空闲 3 分钟回收），单次 15 秒总超时。

200：

```json
{
  "hostId": 7, "hostName": "web-01", "hostAddr": "10.0.0.1:22",
  "sampledAt": "2026-11-02T16:20:31+08:00", "elapsedMs": 820,
  "cpuPercent": 12.3, "cpuCores": 4,
  "memTotalKb": 16000000, "memUsedKb": 8000000, "memAvailableKb": 8000000, "memPercent": 50,
  "swapTotalKb": 2000000, "swapUsedKb": 500000, "swapPercent": 25,
  "load1": 0.52, "load5": 0.40, "load15": 0.35,
  "uptimeSeconds": 123456, "processes": 123,
  "netRxBps": 20480, "netTxBps": 8192,
  "disks": [{ "mount": "/", "totalKb": 100000000, "usedKb": 42000000, "availKb": 58000000, "percent": 42 }],
  "top": [{ "pid": 1234, "command": "nginx", "cpuPercent": 12.3, "memPercent": 4.5 }]
}
```

- 主机不存在：`404 not_found`；SSH 连接失败：`502 ssh_failed`；采集/解析失败：`502 metrics_failed`。
- CPU 与网络速率来自两次快照（间隔 0.6s）的差值；磁盘与进程为单次快照。

### 12.8 SSH 主机 GPU 探测与加速对比

#### GET /ssh/hosts/{id}/gpu（viewer+）

只读执行 `nvidia-smi --query-gpu=name,memory.total,driver_version,utilization.gpu`，不写审计、不修改目标机。

```json
{
  "hostId": 7, "hostName": "gpu-01", "available": true,
  "name": "NVIDIA GeForce RTX 4090", "memoryMb": 24564, "driver": "550.54.14", "utilization": 37,
  "devices": [{ "name": "NVIDIA GeForce RTX 4090", "memoryMb": 24564, "driver": "550.54.14", "utilization": 37 }],
  "endpointReady": true, "accelEnabled": false,
  "sampledAt": "2026-11-02T16:20:31+08:00"
}
```

- 未安装驱动 / 非 NVIDIA 主机：`available=false`，`error` 说明原因（HTTP 仍为 200）。
- `endpointReady` 表示服务端已配置 `VA_GPU_LLM_*`；`accelEnabled` 为该主机保存的加速开关。

#### POST /ssh/hosts/{id}/gpu/benchmark（operator+）

对比默认端点与 GPU 端点的推理耗时。前置条件：主机检测到 GPU、服务端已配置默认端点与 GPU 端点。

可选查询参数 `rounds`（1–3，默认 2）：每侧预热 1 次后连续调用并统计成功样本。

```json
{
  "hostId": 7, "hostName": "gpu-01",
  "detected": { "available": true, "name": "NVIDIA GeForce RTX 4090", "…": "…" },
  "default": { "model": "deepseek-v4-1-flash", "avgMs": 1820, "minMs": 1610, "maxMs": 2010, "samples": 2, "failed": 0 },
  "gpu": { "model": "qwen2.5-32b-instruct", "avgMs": 240, "minMs": 210, "maxMs": 270, "samples": 2, "failed": 0 },
  "speedupPercent": 86.8, "rounds": 2, "sampledAt": "2026-11-02T16:25:02+08:00"
}
```

- 未配置 GPU 端点：`503 gpu_not_configured`；未配置默认端点：`503 llm_unavailable`。
- 主机无可用 GPU：`400 gpu_unavailable`，响应附带 `detected` 明细。
- 成功对比写审计 `ssh.gpu.benchmark`；`speedupPercent` 为负数表示 GPU 端点更慢。

### 12.9 SSH 主机服务加速

#### GET /ssh/hosts/{id}/accel（viewer+）

只读采集 GPU 与系统加速能力，不修改目标机；结果按主机缓存 60 秒，供 `GET /accel/hosts` 调度节点列表使用。查询参数 `refresh=1` 强制重新采样。

```json
{
  "hostId": 7, "hostName": "gpu-01", "hostAddr": "10.0.0.7:22",
  "sampledAt": "2026-11-02T18:40:00+08:00", "elapsedMs": 860,
  "available": true, "nvidiaSmi": true,
  "gpus": [{
    "index": 0, "uuid": "GPU-xxxx", "name": "NVIDIA GeForce RTX 4090",
    "memoryMb": 24564, "memoryUsedMb": 1024, "memoryUtilization": 12,
    "driver": "550.54.14", "utilization": 37, "persistenceMode": "Enabled",
    "powerLimitW": 450, "powerDefaultW": 450, "powerMaxW": 500, "powerDrawW": 120.5,
    "clockMhz": 2100, "maxClockMhz": 2520, "memoryClockMhz": 10501,
    "tempC": 62, "fanPercent": 45, "pstate": "P2", "computeMode": "Default",
    "migMode": "Disabled", "throttle": "Not Active",
    "processes": [{ "pid": 1234, "name": "python", "memoryMb": 512 }]
  }],
  "cuda": "12.4", "driver": "550.54.14", "cpuModel": "Intel Xeon Gold 6338", "cpuCores": 32, "cpuGovernor": "performance",
  "memTotalKb": 64000000, "swapTotalKb": 0,
  "endpointReady": true, "accelEnabled": true, "baselineAt": "2026-11-02T18:30:00+08:00",
  "suggestions": [{
    "id": "cpu-governor", "title": "CPU 调频策略不是 performance",
    "detail": "当前策略为 powersave…", "command": "echo performance | sudo tee …",
    "impact": "降低调度抖动", "risk": "medium"
  }]
}
```

- 无 NVIDIA 驱动时 `nvidiaSmi=false`、`available=false`，`suggestions` 给出安装提示；HTTP 仍为 200。
- `endpointReady` 表示服务端已配置 `VA_GPU_LLM_*`，`accelEnabled` 为主机加速开关。
- 加速能力与系统指标在同一 SSH 连接上并发采集；GPU 字段兼容旧版 10 字段输出。

#### GET /ssh/hosts/{id}/accel/live（viewer+）

轻量实时 GPU 指标，供页面 5 秒轮询；后端缓存 3 秒，`refresh=1` 强制重采。只执行一条 `nvidia-smi --query-gpu`，不重复探测 CPU/驱动。

```json
{
  "hostId": 7, "hostName": "gpu-01", "hostAddr": "10.0.0.7:22",
  "sampledAt": "2026-11-02T18:40:05+08:00", "elapsedMs": 180, "available": true,
  "gpus": [{
    "index": 0, "uuid": "GPU-xxxx", "name": "NVIDIA GeForce RTX 4090",
    "memoryMb": 24564, "memoryUsedMb": 2048, "utilization": 45, "memoryUtilization": 30,
    "powerDrawW": 120.5, "powerLimitW": 450, "tempC": 62, "fanPercent": 45,
    "pstate": "P2", "throttle": "Not Active"
  }]
}
```

- 无 GPU 时返回 200，`available=false` 且 `error` 说明原因；SSH 失败返回 `502`。

#### POST /ssh/hosts/{id}/accel/baseline（operator+）

保存当前能力画像与性能指标作为基线（每主机一条，重复记录覆盖），写审计 `ssh.accel.baseline`。

```json
{ "profile": { "…": "…" }, "metrics": { "cpuPercent": 12.3, "…": "…" }, "createdAt": "2026-11-02T18:40:00+08:00" }
```

#### POST /ssh/hosts/{id}/accel/compare（operator+）

重新采样并与最近基线对比，写审计 `ssh.accel.compare`。

```json
{
  "hostId": 7, "hostName": "gpu-01",
  "baselineAt": "2026-11-02T18:40:00+08:00", "baselineBy": "va-admin",
  "currentAt": "2026-11-02T18:55:00+08:00", "elapsedMs": 910,
  "metrics": [
    { "key": "cpu", "label": "CPU 使用率", "before": 40, "after": 20, "delta": -20, "unit": "%", "better": "lower", "improved": true },
    { "key": "gpu-clock", "label": "GPU 当前频率", "before": 1500, "after": 2100, "delta": 600, "unit": "MHz", "better": "higher", "improved": true }
  ],
  "changes": ["GPU 0 持久化模式：Disabled → Enabled", "CPU 调频策略：powersave → performance"],
  "before": { "…": "…" }, "after": { "…": "…" }, "suggestions": []
}
```

- 未记录基线：`404 no_baseline`；SSH/解析失败：`502 accel_failed`。
- `better` 为 `lower`/`higher`/`none`，`improved` 仅对可判定方向的指标计算。

#### GET /accel/hosts（viewer+）

返回已开启服务加速的主机与最近一次探测缓存，作为服务端计算任务调度的候选节点。

```json
{ "items": [{ "hostId": 7, "hostName": "gpu-01", "hostAddr": "10.0.0.7:22",
  "accelEnabled": true, "endpointReady": true, "available": true,
  "gpuName": "NVIDIA GeForce RTX 4090", "cuda": "12.4", "lastProfiledAt": "2026-11-02T18:40:00+08:00" }] }
```

#### 连接复用与缓存

- 性能监控、服务加速、GPU 探测与 hashcat 共用进程内 SSH 连接池；空闲 3 分钟回收，复用前用空会话探活，失效自动重连。
- `GET /ssh/hosts/{id}/accel` 命中 60 秒缓存时不建立 SSH 连接；`refresh=1` 强制重采。加速能力与系统指标并发采集。
- `GET /ssh/hosts/{id}/accel/live` 命中 3 秒缓存时不建立 SSH 连接；页面在不可见时暂停轮询。

### 12.10 SSH 主机 hashcat 口令审计

#### POST /ssh/hosts/{id}/hashcat/benchmark（operator+）

在目标机运行 `hashcat -b -m 0`，分别以 `-D 2`（GPU）与 `-D 1`（CPU）采样速度，写审计 `ssh.hashcat.benchmark`。

```json
{
  "available": true, "version": "v6.2.6", "mode": "MD5",
  "gpuDevice": "NVIDIA GeForce RTX 4090", "cpuDevice": "Intel Xeon Gold 6338",
  "gpuSpeedHs": 12000000000, "cpuSpeedHs": 300000000, "speedup": 3900,
  "elapsedMs": 18400
}
```

- 未安装 hashcat：`400 hashcat_unavailable`。
- 两侧速度均为 0 时返回 200，`error` 说明后端设备不可用。

#### POST /ssh/hosts/{id}/hashcat/audit（operator+）

```json
{ "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99"], "hashMode": 0, "wordlistPath": "/usr/share/wordlists/rockyou.txt" }
```

```json
{
  "total": 1, "crackedCount": 1, "notFound": 0, "hashMode": 0,
  "wordlist": "/usr/share/wordlists/rockyou.txt", "elapsedMs": 3200,
  "cracked": [{ "hash": "5f4dcc3b5aa765d61d8327deb882cf99", "plain": "password" }]
}
```

- 最多 100 条哈希，单条 8–512 字符；`hashMode` 为 hashcat `-m`（0–99999）；字典必须是目标机绝对路径。
- 哈希经 SFTP 写入 `/tmp/vulnagent-hashcat-*.txt`，命令限制 `--runtime 300`，结束后立即删除哈希、结果与日志文件。
- 字典不存在：`400 wordlist_missing`；SSH/SFTP 失败：`502 ssh_failed` / `502 sftp_failed`。
- 写审计 `ssh.hashcat.audit`（仅记录数量，不记录哈希与明文）；接口仅限 operator，返回明文前需确认授权范围。

### 13. 项目与集群（多主机运维）

#### 项目

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/projects` | viewer+ | 项目列表，含集群数/节点数 |
| POST | `/projects` | admin | 创建项目 `{name, description, owner}` |
| PATCH | `/projects/{id}` | admin | 修改名称/说明/负责人 |
| DELETE | `/projects/{id}` | admin | 级联删除集群/节点，资产 `cluster_id` 置 0 |

#### 集群

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/clusters?projectId=1` | viewer+ | 集群列表，含节点健康、资产数、未关闭漏洞 P0/P1 |
| POST | `/clusters` | admin | `{projectId, name, environment, provider, region, description}` |
| GET | `/clusters/{id}` | viewer+ | 详情：cluster + nodes + assets + findings 统计 |
| PATCH | `/clusters/{id}` | admin | 修改环境/厂商/地域/说明 |
| DELETE | `/clusters/{id}` | admin | 删除集群与节点，资产 `cluster_id` 置 0 |

`environment` 取值：`prod` / `staging` / `dev` / `test` / `other`。

#### 节点

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| POST | `/clusters/{id}/nodes` | operator+ | 新增节点 |
| PATCH | `/cluster-nodes/{id}` | operator+ | 修改节点 |
| DELETE | `/cluster-nodes/{id}` | operator+ | 删除节点 |
| POST | `/clusters/{id}/check` | operator+ | 检查集群全部节点 |
| POST | `/cluster-nodes/{id}/check` | operator+ | 检查单节点 |
| POST | `/clusters/{id}/scan` | operator+ | 扫描全部关联 SSH 的节点 |
| POST | `/cluster-nodes/{id}/scan` | operator+ | 扫描单节点 |

节点字段：

```json
{
  "name": "backend-1", "role": "backend|database|cache|proxy|storage|scan_target",
  "host": "10.0.0.12", "port": 8787, "url": "http://10.0.0.12:8787/api/v1/healthz",
  "sshHostId": 3, "checkType": "auto|http|tcp|ssh|ssh_file",
  "path": "/var/lib/app/app.db", "note": "主库",
  "dbEngine": "mysql|postgresql|", "dbName": "app", "dbUser": "vuln_readonly",
  "dbPassword": "仅写入，不回显", "dbSslMode": "disable|require"
}
```

- `checkType=auto` 时：backend→http，database→tcp（填了 `sshHostId` 与 `path` 则为 ssh_file），scan_target→ssh，其余→tcp。
- SSH/ssh_file 检查复用已保存的 SSH 主机凭据；数据库深检凭据单独使用 AES-256-GCM 加密存储，接口只返回 `hasDbSecret`，不返回明文。
- 配置 `dbEngine` 后，database 节点的 TCP 检查升级为只读深检：版本、当前/最大连接数、数据容量与运行时长；失败会返回连接或查询原因。
- 扫描结果进入现有资产/漏洞流水线，并自动把资产 `cluster_id` 设为该集群。
- 检查/扫描结果包含 `status`（ok/failed/unknown）、`latencyMs`、`detail`；扫描汇总包含每个节点的成功/失败原因。

#### 异步检查/扫描任务

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| POST | `/clusters/{id}/jobs` | operator+ | `{kind:"check"\|"scan"}`，创建后台任务，返回 `job` |
| GET | `/clusters/{id}/jobs?limit=20` | viewer+ | 任务列表 |
| GET | `/cluster-jobs/{id}` | viewer+ | 任务进度与逐节点结果 |
| POST | `/cluster-jobs/{id}/cancel` | operator+ | 取消排队/执行中的任务 |

任务状态：`queued` / `running` / `succeeded` / `partial` / `failed` / `canceled`；`items` 记录每个节点的 `status`、`message`、`latencyMs` 与扫描统计。节点最多 3 个并发执行，服务重启时未完成任务标记为 `canceled`。

#### 集群筛选

`GET /findings`、`GET /reports/findings.pdf|csv`、`GET /assets`、`GET /assets/export` 均支持 `clusterId` 参数，按 `assets.cluster_id` 过滤。

#### 资产关联

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| POST | `/clusters/{id}/assets` | operator+ | `{assetIds:[1,2]}` 批量关联已有资产（≤200） |
| DELETE | `/clusters/{id}/assets/{assetId}` | operator+ | 解除单个资产关联 |

- 删除项目/集群/解除关联只清空 `cluster_id`，不删除资产、组件或漏洞。
- 所有写操作、检查与扫描写审计（`project.*`、`cluster.*`、`cluster.node.*`、`cluster.assets.*`）。

---

## 14. Agent 管理（单机身份）

除旧版全局 Bearer 令牌外，每台主机可注册独立身份，使用请求头 `X-Agent-Id` + `X-Agent-Secret` 访问 Agent 接口。

### 页面接口（会话 Cookie）

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/agents` | viewer+ | Agent 列表，含在线状态、归属项目/集群、命令计数 |
| POST | `/agents/enroll-tokens` | operator+ | `{nameHint, projectId?, clusterId?, ttlMinutes?}` 生成一次性令牌，明文仅返回一次 |
| GET | `/agents/enroll-tokens` | operator+ | 注册令牌列表（不含明文） |
| DELETE | `/agents/enroll-tokens/{id}` | operator+ | 删除未使用令牌 |
| POST | `/agents/{id}/revoke` | operator+ | 吊销 Agent，未执行命令标记失败 |
| POST | `/agents/{id}/commands` | operator+ | `{action:"ping"\|"collect"}` 下发命令 |
| GET | `/agents/{id}/commands?limit=50` | viewer+ | 命令历史与结果 |

在线判定：最近心跳在 3 分钟以内为 `online`，否则 `offline`；`revokedAt` 非空为 `revoked`。

### Agent 接口（无需会话）

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/agents/enroll` | 注册令牌 | `{token, name?, hostname, os?, osVersion?, version?}` → `{agentId, secret}` |
| POST | `/agents/heartbeat` | Agent 身份 | 更新主机信息与 `lastSeenAt`，返回待执行命令数 |
| GET | `/agents/commands` | Agent 身份 | 拉取最多 5 条待执行命令，并标记为 `claimed` |
| POST | `/agents/commands/{id}/result` | Agent 身份 | `{status:"succeeded"\|"failed", output, error}` |
| POST | `/agent/report` | 全局令牌或 Agent 身份 | SBOM 上报；绑定集群时资产自动写入 `cluster_id` |
| GET/POST | `/agent/jobs...` | 全局令牌或 Agent 身份 | 主机作业拉取/抢占/回传，签名密钥随身份类型派生 |

注册令牌一次性使用，默认 60 分钟有效；Agent 首次注册后把 `agentId` 与 `secret` 保存至 `<数据目录>/agent.identity.json`（0600），后续自动复用。旧版全局令牌流程保持兼容。

