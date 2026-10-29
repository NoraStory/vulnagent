# 控制面 API 契约（前端 · 后端对接基线）

- Base URL：`/api/v1`（开发期 Vite 代理到 `http://127.0.0.1:8787`）
- 编码：JSON（UTF-8）；时间统一 RFC3339 字符串
- 认证：Cookie `va_session`（HttpOnly）。除 `POST /auth/login`、`GET /healthz` 外均需登录
- 错误：HTTP 4xx/5xx，body `{ "error": { "code": "forbidden", "message": "..." } }`
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
    { "factor": "asset", "label": "资产权重", "value": 0.8, "weight": 0.15, "weighted": 12.0, "note": "公网 · 核心业务" }
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

### GET /assets?q=&page=1&pageSize=20

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
      "env": "prod",
      "exposure": "public",
      "tier": "core",
      "owner": "交易平台组",
      "source": "agent",
      "agentStatus": "online",
      "lastSeen": "2026-10-22T09:58:00+08:00",
      "components": 214,
      "findings": 11,
      "p0": 2,
      "risk": 96
    }
  ]
}
```

`agentStatus`：`online | offline | stale | none`；`source`：`agent | ssh | container | self`。

### GET /assets/{id}

```json
{
  "demo": true,
  "asset": { ...同上 item },
  "components": [
    { "purl": "pkg:deb/debian/openssl@3.0.11", "name": "openssl", "version": "3.0.11", "ecosystem": "deb", "vendor": "openssl", "product": "openssl", "inferred": false, "findings": 1 }
  ],
  "findings": [ ...同 /findings item ]
}
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
      "hasSecret": true
    }
  ]
}
```

### POST /ssh/hosts（operator+）

```json
{ "name": "web-01", "host": "10.0.0.12", "port": 22, "username": "root",
  "authType": "password", "password": "…", "privateKey": "", "passphrase": "",
  "note": "生产 Web", "tags": "prod, web" }
```

- `authType=password` 需要 `password`；`authType=key` 需要 `privateKey`，可选 `passphrase`。
- 同一 `host + port + username` 重复时返回 `409 host_exists`。

### PATCH /ssh/hosts/{id}（operator+）

字段均可选；`password` / `privateKey` 留空表示保持原值；切换认证方式必须同时提供新凭据；地址或端口变化会清空已信任指纹；`clearHostKey=true` 可主动清除指纹。

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
{ "answer": "根分区使用率 88%，建议…", "commands": ["df -i", "journalctl --disk-usage"], "model": "deepseek-v4-1-flash-261017" }
```

- `question` 上限 2000 字符，`context` 上限 8000 字符（前端只发送最近终端输出）。
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
{ "hostId": 1, "question": "tar 如何解压到指定目录", "context": "…", "search": true }
```

`search` 缺省为 `true`；响应新增：

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
{ "type": "status", "data": { "runId": "…", "host": "web-01", "search": true, "references": [ … ], "referenceError": "" } }
```

`POST /ssh/agent/run` 请求新增可选字段 `search`（缺省 `true`）：

```json
{ "hostId": 1, "goal": "排查最近异常登录", "mode": "safe", "search": true }
```

- 本地关键词无法判断命令主题时，会额外调用一次模型提取 1–3 个命令名（只输出 JSON 数组），再检索参考。
- Agent 在每一步决策前都会携带参考块，并新增「不熟悉参数必须先 `command -v` / `--help` 验证」的约束。

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
