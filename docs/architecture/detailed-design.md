# 安全漏洞运维 Agent · 详细设计

> 对应架构图：`vuln-agent-architecture.html` / `diagram.excalidraw`（v0.2）
> 技术栈基线：Go 单二进制 + SQLite（可切 PostgreSQL）+ 内嵌 Web 控制台
> 采集方式：Agent 为主，SSH 无 Agent 兜底
> 情报源：漏洞平台 API（`cve.imfht.com`）+ EPSS

---

## 1. 目标与边界

### 1.1 目标

| 目标 | 可验证标准 |
|---|---|
| 掌握主机软件清单 | 单机全量采集 ≤ 3 s，覆盖系统包、语言依赖、容器镜像、自身组件 |
| 漏洞判定 | 对清单中每个组件给出"命中/未命中"结论，并附 CVSS、EPSS、POC 状态 |
| 等级排序 | 输出 P0–P3 四档，P0 全量可解释（分数 + 分项因子） |
| 易部署 | 单机 1 条命令起服务、1 条命令装 Agent；全离线可用 |
| 高性能 | 1 万台资产 × 平均 300 组件，全量重匹配 ≤ 60 s；常驻内存 ≤ 300 MB |
| 自身安全 | Agent/控制面自身依赖入库并参与扫描；全部写操作可审计 |

### 1.2 非目标（v1 不做）

- 主动漏洞利用验证（不跑 exploit）
- 主机入侵检测、EDR 能力
- 自动执行升级/变更（只出建议与工单，执行由人/自动化平台完成）
- 非软件类资产（网络设备固件、云配置基线）

---

## 2. 总体设计

### 2.1 四层职责

| 层 | 职责 | 关键约束 |
|---|---|---|
| ① 采集层 | 读取本机软件清单与版本，产出 SBOM；自身依赖同样入库 | 只读、单二进制、无常驻高开销进程 |
| ② 接入与归一化 | 认证鉴权、限流、SBOM 归一为统一清单、增量 diff、资产台账 | 服务端不信任 Agent 上报内容，全部校验 |
| ③ 匹配与排序 | CVE/EPSS 情报同步与本地索引、CPE + 版本区间匹配、风险打分 | 断网可用；匹配可解释 |
| ④ 修复与输出 | 控制台、修复建议、工单编排、复扫验证、报告 | 闭环可追溯，权限受控 |

### 2.2 运行时形态

```
                  ┌──────────────────────────── 单个二进制 vulnagent ───────────────────────────┐
  主机 Agent  ──▶ │ server 子命令：HTTP API / 内嵌 Web / 同步器 / 匹配器 / 调度器 / SQLite        │
  SSH 兜底    ──▶ │ agent  子命令：采集 → 增量 diff → 签名上报（与 server 同一份代码）           │
                  │ scan   子命令：一次性离线扫描，输出 JSON/表格（无服务端场景）                 │
                  └──────────────────────────────────────────────────────────────────────────────┘
```

- `vulnagent server`：控制面（默认监听 `:8443`，可 TLS 终结于反代）
- `vulnagent agent`：主机侧采集（systemd 定时触发或常驻 ticker）
- `vulnagent scan --offline-bundle ...`：单机应急模式，不依赖控制面

### 2.3 一次完整扫描链路（时序）

1. `server` 定时（默认 6 h）或人工触发 → 下发扫描任务（Agent 拉取 policy）
2. Agent 采集 → 与上次快照 diff → 仅变更组件上报（gzip + Ed25519 签名）
3. 接入网关校验 mTLS 证书 → 校验签名/digest → 幂等写入快照
4. 归一化：PURL 标准化、去重、CPE 映射（命中映射表或留空待补）
5. 匹配：以 `vendor + product` 命中候选 CVE 集合 → 版本区间求值 → 生成 finding
6. 排序：CVSS / EPSS / POC / 资产权重 → 风险分 → P0–P3
7. 输出：控制台看板、告警、工单；修复后触发复扫，finding 状态机闭环

---

## 3. 技术选型

| 领域 | 选型 | 理由 |
|---|---|---|
| 语言 | Go 1.23+ | 单二进制、交叉编译、内存可控，Agent 与控制面同栈 |
| HTTP | `net/http` + `chi` | 轻量中间件（认证、限流、审计、恢复） |
| 存储 | SQLite（`modernc.org/sqlite`，纯 Go 无 cgo）；PostgreSQL 可选 | 单机零依赖；PG 走同一 `database/sql` 接口 |
| 迁移 | 内嵌 SQL migration（`embed`） | 二进制自带 schema，无需外部工具 |
| 前端 | Vite + React + TypeScript + Tailwind，构建产物 `embed` 进二进制 | 单文件交付，无独立前端服务 |
| 配置 | YAML + 环境变量覆盖（`VULNAGENT_*`） | 容器友好 |
| 日志/指标 | `log/slog`（JSON）+ Prometheus `/metrics` | 可观测性基线 |
| SBOM 格式 | CycloneDX 1.6 子集 + PURL | 与主流 SCA 工具互通 |
| 版本比较 | 自研 `vercmp`：dpkg / rpm / semver / apk 四套 | 各生态规则不同，不能统一用 semver |
| 签名 | Ed25519（上报签名、二进制清单签名） | 密钥短、验签快 |
| 调度 | 进程内 cron（`robfig/cron`）+ 数据库任务表 | 单机无需外部队列 |

**明确不引入**：Kafka/Redis/Elasticsearch（v1 规模不需要，破坏"易部署"）；Python/Java 运行时（Agent 侧）。

---

## 4. 模块详细设计

### 4.1 采集器（agent）

#### 4.1.1 采集源

| 平台 | 数据源 | 采集内容 |
|---|---|---|
| Linux (deb) | `/var/lib/dpkg/status` | 包名、版本、架构、来源仓库 |
| Linux (rpm) | `rpm -qa --qf`（或直接读 rpmdb） | 包名、epoch:version-release、架构 |
| Linux (apk) | `/lib/apk/db/installed` | 包名、版本 |
| 语言依赖 | `go.mod`/`go.sum`、`requirements.txt`/`dist-info`、`package-lock.json`/`node_modules`、`pom.xml` | 生态 + 名称 + 版本 + 依赖路径 |
| 运行服务 | `systemctl list-units --type=service`、监听端口 → 进程 → 可执行文件包归属 | 服务名、二进制、关联包（用于暴露面加权） |
| 容器 | Docker/containerd 镜像列表 → 镜像内 SBOM（读取镜像层包数据库，不启动容器） | 镜像名:tag、digest、内含组件 |
| 自身 | 编译期注入的模块列表（`debug.ReadBuildInfo`） | Agent 自身依赖版本 |

#### 4.1.2 关键行为

- **只读**：仅读取文件/调用查询类命令，不写系统目录、不改包数据库、不执行远程下发命令。
- **增量**：本地保存上次组件指纹（`purl@version` 的 hash 集合），仅上报新增/变更/删除；全量重传周期默认 7 天。
- **资源约束**：单次采集 CPU 时间片上限 2 s（`GOMAXPROCS=1` 场景下仍可完成），峰值内存 ≤ 50 MB；采集结束即退出（默认 one-shot + systemd timer）。
- **自更新**：`GET /agent/binary/latest` 返回版本 + sha256 + Ed25519 签名，本地验签后才替换；替换走原子 rename，失败自动回滚。
- **排除项**：可通过 policy 排除路径/包名前缀（如自研内部包），避免噪声。

#### 4.1.3 SSH 兜底采集

- 由**控制面**发起（Agent 侧无 SSH 能力），支持口令或私钥认证，凭据只用于本次连接，不落库、不写日志。
- 远程执行只读脚本：优先 `dpkg-query`，其次 `rpm -qa`，最后解析 `/lib/apk/db/installed`，输出 `生态→名称→版本→架构` 的 TSV。
- 主机指纹：留空时接受并回报 `SHA256:...`（TOFU），填入后指纹不匹配立即拒绝，防止中间人。
- 结果进入与 Agent 完全相同的 `ingestComponents` 管道（资产 upsert → 组件替换 → 区间匹配 → 状态收敛），资产来源标记为 `ssh`。
- 入口：控制台「资产 · SSH 采集」、`POST /api/v1/assets/ssh-scan`、`vulnagent sshscan --host ...`。

### 4.2 接入网关

| 能力 | 实现 |
|---|---|
| 传输安全 | 当前实现：Bearer 令牌（控制面生成，写入数据目录 `agent.token`，库内只存 SHA-256）。规划：mTLS + 证书绑定，Agent 首次 enroll 签发客户端证书 |
| 报文完整性 | Header `X-VA-Signature`（Ed25519 over body），`X-VA-Digest`（sha256） |
| 幂等 | `Idempotency-Key = agent_id + snapshot_digest`，重复上报直接返回 200 不重复写 |
| 限流 | 按 agent 令牌桶（默认 60 req/min），全局并发上限 |
| RBAC | 人类用户走 session/JWT；Agent 走证书主体 + `agent:report` scope |
| 入参校验 | 体积上限 8 MB（gzip 解压后 64 MB）、组件条数上限 20 万、字段白名单 |

### 4.3 SBOM 归一化与资产台账

- **PURL 规范化**：`pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.4?arch=amd64`、`pkg:golang/github.com/gin-gonic/gin@v1.9.1`。
- **去重键**：`asset_id + purl`；同 purl 多路径（如两个 venv 装了同版本）合并为一条，记录 `locations` 数组。
- **与上次快照 diff**：新增 / 版本变更 / 消失；消失组件不立即删除 finding，标记 `component_removed` 并在下次匹配时关闭。
- **资产权重来源**：手工标注（业务等级、是否公网）、服务监听端口自动推断暴露面、CMDB 同步（可选，v1 预留接口）。

### 4.4 情报同步（CVE / EPSS）

#### 4.4.1 对外接口（漏洞平台 API）

| 用途 | 接口 | 说明 |
|---|---|---|
| 增量拉取 | `GET /api/cve/?page=&per_page=&search=` | 按 `updated_at` 倒序翻页，直到遇到已入库游标；`search` 用于按产品名定向补齐 |
| 详情补齐 | `GET /api/cve/{cve_id}` | 获取 `cvss_vector`、`record_source`、`official_record`、POC 列表 |
| POC 情报 | `GET /api/poc/?page=&per_page=` | 在野利用信号，落 `cve_poc` 表 |
| 鉴权 | 公开接口无需鉴权；如平台要求则 Header `X-API-Key` | 密钥不落库，仅从环境变量读取 |

**已有字段直接可用**：`cve_id`、`title`、`description`、`cvss_vector`、`cwe_id`/`cwe_cn`、`published_at`、`updated_at`、`pocs[]`、`record_status`。
**需要自算**：CVSS 3.1 基础分（由 `cvss_vector` 计算）、严重级（由分数分档）。

#### 4.4.2 同步策略

- **客户端**：公开接口直接调用；如配置了 `X-API-Key` 则附带；429/5xx 指数退避重试 3 次；单次超时 20s。
- **游标**：平台增量游标存于 `app_meta.cve_cursor`（首次回退 `MAX(updated_at)`），翻页遇到不新于游标的数据即停止；中断可续。
- **分值**：平台只给 `cvss_vector`，由本地 `cvss.go` 按 CVSS 3.1 规范计算基础分与严重级（含 roundup）。
- **频率**：增量建议每 30 min；POC 每 60 min；EPSS 每日一次（离线包可导入）。
- **离线模式**：`vulnagent sync --bundle cve-bundle.json`，包内为 `{source:"cve", items:[...]}`，与在线同步走同一套 upsert；示例见 `docs/architecture/examples/cve-bundle.json`。
- **首次全量**：建议走离线包（百万级 CVE 全量走 API 不现实），之后只做增量。

#### 4.4.4 OSV 精确版本匹配

- 背景：漏洞平台只提供 CVE 元数据，不返回受影响版本区间；语言生态需要第二数据源。
- 数据源：`https://api.osv.dev/v1/query`（免费、无需 Key），按「包名 + 版本 + 生态」查询，只返回确实影响该版本的漏洞。
- 覆盖生态：Go、npm、PyPI、Maven、NuGet、Debian、Alpine、RubyGems、crates.io、Packagist；Windows 注册表软件（`generic/windows`）暂不覆盖。
- 落库：写入 `cves`（CVE 别名优先，标题/详情/CVSS 向量）、`cve_affected`（产品名 + 修复版本）与 `findings`（四因子评分），随后走同一套状态收敛。
- 触发：Agent 上报后异步执行；手动复扫、定时复扫、`POST /api/v1/sync/osv` 与控制台「OSV 匹配」都会触发。
- 游标隔离：平台 CVE 增量游标存于 `app_meta.cve_cursor`，不会被 OSV 写入的 `updated_at` 干扰。

#### 4.4.3 EPSS

- 数据源：FIRST 每日 CSV（`cve,epss,percentile`）；只更新库内已存在的 CVE，未知 CVE 跳过并计数。
- 导入后把最新分值同步到 `findings.epss` 快照，再按当前风险策略重算全部漏洞的风险分与优先级。
- 入口：控制台「审计与设置 · 情报同步」上传、`POST /api/v1/sync/epss`（text/csv，≤64MB）、`vulnagent sync --epss-file`。
- 示例文件：`docs/architecture/examples/epss-sample.csv`。

### 4.5 匹配引擎

#### 4.5.1 流程

```
component(purl, vendor, product, version, ecosystem)
   │ 1) PURL → CPE 映射（映射表 → 启发式 → 未命中则仅按产品名检索）
   ▼
候选 CVE 集合（内存索引：vendor+product → []cve_id）
   │ 2) 版本区间求值（按生态选择比较器）
   ▼
命中结论（含匹配依据：哪个 cpe、命中哪条区间）
```

#### 4.5.2 PURL → CPE 映射

- 主路径：`product_map(eco, name) → product`，把发行版/语言包名映射到漏洞库产品名（如 `python3-requests → requests`）。
- 匹配顺序：映射产品 → 组件 `product` → 组件 `name`；同一组件内按 CVE 去重。
- 命中的若是映射产品，结论标记 `inferred=1`，控制台显示「映射推断」。
- 内置别名（`node-*`、`python3-*`、`libssl3`、`openssl-libs`）首次启动写入，带 `confidence`；控制台可增删改，删除后重启不复活。
- 映射变更（新增/修改/删除）会立即重新匹配全部资产，无需等待下一轮扫描。
- 未映射组件仍按原始产品名/包名匹配；后续可扩充字典或接入 NVD CPE 字典。

#### 4.5.3 版本比较

| 生态 | 规则 |
|---|---|
| deb | epoch + upstream + revision 逐段比较，`~` 小于空串 |
| rpm | `rpmvercmp`（字母段/数字段交替比较） |
| apk | `-rN` 后缀 + 字母后缀规则 |
| semver | `x/mod/semver`，处理 `v` 前缀与预发布 |
| 其他 | 退化为点分段数字比较，并标记 `compare_mode=fallback` |

区间匹配时把 CVE 的 `versionStartIncluding/Excluding`、`versionEndIncluding/Excluding` 统一为半开区间求值。

#### 4.5.4 误报压制规则

1. 发行版已回补（distro backport）：CVE 版本区间不覆盖发行版版本号时自动判定不命中。
2. 组件存在但未被加载/未监听端口 → 不降级为"不存在"，但 `asset_weight` 降低。
3. 供应商 `record_status != published`（REJECTED/Withdrawn）→ 不生成 finding。
4. `inferred=true` 且 CVSS < 7.0 → 只入库不打告警（可在设置中放开）。

### 4.6 风险排序

#### 4.6.1 公式

```
risk = 100 × ( 0.40·S_cvss + 0.20·S_epss + 0.25·S_exploit + 0.15·S_asset )

S_cvss    = cvss_base / 10                      # 0–1，缺省 0.5 并标记 unknown
S_epss    = epss_score                          # 0–1，缺省 0（标记 no-epss）
S_exploit = 1.0  有 POC/已观测利用
            0.6  仅 PoC 仓库链接
            0.0  无
S_asset   = exposure × business_tier            # 0–1
            exposure:     公网 1.0 / 内网 0.6 / 隔离 0.2
            business_tier: 核心 1.0 / 重要 0.8 / 一般 0.5
```

#### 4.6.2 分档与硬规则

| 档位 | 条件 | SLA |
|---|---|---|
| P0 | risk ≥ 85，或（CVSS ≥ 9.0 且 有 POC），或（在 KEV 名单且公网暴露） | 24 h |
| P1 | 70 ≤ risk < 85，或 CVSS ≥ 8.0 且 EPSS ≥ 0.5 | 7 天 |
| P2 | 50 ≤ risk < 70 | 30 天 |
| P3 | risk < 50 | 90 天 |

- 打分为**纯函数 + 可解释**：`findings` 里保存 `score_breakdown` JSON（四个因子值与权重），UI 直接展开显示。
- 权重可通过 `risk_policy` 配置调整，变更写审计；重算走后台任务，不阻塞读。

### 4.7 修复模块

#### 4.7.1 修复建议（advice）

输入：`finding` + 组件生态 + 当前版本。
输出：`fixed_version`、`upgrade_path`、`command`、`risk_note`。

| 场景 | 建议生成 |
|---|---|
| CVE 有 `fixed_version` | 升级到 ≥ fixed_version 的最小可用版本 |
| 发行版有安全更新 | 优先建议发行版补丁包（`apt install --only-upgrade <pkg>`），不跨大版本 |
| 无修复版本 | 给缓解措施（关闭端口/关闭模块/加 WAF 规则）+ 标记 `no_fix` |
| 多 CVE 同一组件 | 合并为一条"组件升级建议"，取所有 fixed_version 的最大值 |

生成命令时按生态模板：deb `apt-get install --only-upgrade pkg=ver`、rpm `dnf update pkg-ver`、golang `go get module@vX.Y.Z`、npm `npm i pkg@ver`。

#### 4.7.2 修复编排

- 状态机：`open → triaged → fixing → fixed → verified → closed`（另有 `risk_accepted`、`false_positive`）。
- 工单：内置轻量工单表；创建后通过通知模块推送 `ticket.created` 事件到已配置的 Webhook（可对接 Jira/飞书机器人，字段回写需对方接口适配）。
- 责任人：按资产 `owner` 默认分配，支持按团队批量指派；变更窗口可配置。
- 审批：P0 强制走审批记录（谁批准、何时、变更单号）。

#### 4.7.3 复扫验证

- 触发：控制台「触发复扫」，或 Agent 再次上报该资产时自动执行（同一套逻辑）。
- 判定（只处理 `open/triaged/fixing/fixed/verified`）：
  - 当前版本 ≥ `fixed_version` → `verified`；
  - 已不在 `cve_affected` 区间内 → `verified`；
  - 组件已从资产移除 → `closed`；
  - 已验证但版本回退、重新落入受影响区间 → 重新打开为 `open`；
  - 仍然命中 → 保持原状态。
- 每次收敛都会写入 finding 事件（含旧版本 → 新版本）与一条审计摘要。
- 触发方式（同一套 `rescanAsset`）：详情抽屉「触发复扫」、资产页「全量复扫」（`POST /api/v1/scans`）、Agent 上报、后台定时器。
- 防抖：单资产在 `VA_RESCAN_DEBOUNCE`（默认 10m）内重复触发直接跳过并返回 `skipped: true`，避免前端连点与定时器叠加造成重复扫描。
- 定时：`VA_RESCAN_INTERVAL`（默认 30m，设为 `0/off` 关闭）由常驻 ticker 对全部资产做一轮收敛，单批上限 500 台。

#### 4.7.4 报告导出

- 入口：漏洞清单右上角「PDF 报告」，按当前优先级 / 状态 / 关键词筛选生成，`operator+` 可导出，写 `report.export` 审计。
- 内容：页头（生成时间、生成人）、P0–P3 概览卡片与涉及资产数、筛选说明、按风险分降序的明细（优先级、CVE、标题、组件当前版本 → 修复版本、资产、CVSS、EPSS、风险分、状态）。
- 实现：`go-pdf/fpdf` 生成，思源黑体（Noto Sans SC，SIL OFL 1.1）随二进制 `embed`，子集化后单份报告约 50 KB，部署不依赖系统字体。
- 单次最多渲染 300 条明细，超出时页首注明「仅展示风险分最高的 300 条」并提示总数。
- 空结果同样生成报告并提示「当前筛选条件下没有漏洞记录」。
- CSV 导出：同一套筛选与排序，UTF-8 BOM 便于 Excel 打开，单次上限 5000 条，写 `report.export_csv` 审计。

#### 4.7.5 告警通知

- 事件：`finding.new`（新增 P0/P1）、`ticket.created`、`sync.failed`、`selfcheck.failed`，可在「审计与设置 → 通知」按事件勾选订阅。
- 传输：JSON POST，请求头 `X-VulnAgent-Event`；配置密钥后附加 `X-VulnAgent-Signature: sha256=HMAC-SHA256(secret, body)`，接收方可验签。
- 可靠性：单事件最多 3 次尝试（1s、4s 退避），失败只记录不阻塞主流程；最近一次事件/状态/错误/时间落库并在设置页展示。
- 配置：`admin` 维护 Webhook 地址、密钥与订阅事件，支持「发送测试」；清空地址即关闭通知。

### 4.8 权限与审计

| 角色 | 权限 |
|---|---|
| `admin` | 用户/角色管理、策略与权重配置、密钥轮换、全量数据 |
| `operator` | 查看资产与漏洞、生成工单、触发扫描/复扫、导出报告 |
| `viewer` | 只读看板与报告，不可导出原始 SBOM |

- 认证：本地账号（bcrypt cost 10）。会话 Cookie `HttpOnly; SameSite=Lax`，`Secure` 在 HTTPS 下自动开启，也可用 `VA_COOKIE_SECURE=1` 强制；会话空闲 `VA_SESSION_IDLE`（默认 30 min）滑动过期，当前保存在进程内，控制面重启后需重新登录。
- 登录防护：同一「账号 + IP」10 分钟内连续失败 5 次锁定 5 分钟，返回 `429 too_many_attempts` 与 `Retry-After`；失败、锁定、成功登录均写审计。
- 账号管理：`admin` 可新建账号、调整角色、停用/启用、重置口令；不能停用或降级当前登录账号，且至少保留一个启用状态的管理员。修改本人口令、管理员重置口令、停用账号都会立即使其会话失效。
- Agent 令牌：仅保存 SHA-256 摘要，明文只落在数据目录 `agent.token`（0600）；`admin` 可在控制台一键轮换，旧令牌立即失效；使用 `VA_AGENT_TOKEN` 托管时禁止控制台轮换。
- 安全响应头：`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`；所有写操作校验 `Origin` 与当前站点同源（忽略端口，兼容前端开发代理）。
- 尚未实现：OIDC 单点登录、按 scope 签发的细粒度 API Token（见 §12.5）。
- 审计：登录/登出、登录失败与锁定、扫描触发、状态变更、策略修改、账号与令牌操作、数据导出，全部落 `audit_logs`（含 IP、UA），只追加不可改。
- 数据隔离：按资产分组授权（v1 单租户，预留 `tenant_id` 字段）。

### 4.9 自身安全保障

1. **构建期**：二进制内置自身依赖 SBOM 摘要并在自检中展示；`govulncheck` 尚未接入 CI（见 §12.5）。
2. **运行期**：控制面把自身 SBOM 当作一台"虚拟资产"入库，自身漏洞与控制面告警同级展示。
3. **二进制完整性**：`vulnagent keygen` 生成 Ed25519 密钥对，`vulnagent sign` 产出带签名清单（version/os/arch/sha256/url）；`vulnagent self-update` 校验签名与 SHA-256 后原子替换，保留 `.old` 便于回滚。公钥通过 `VA_UPDATE_PUBKEY` 或 `--pubkey` 提供，篡改清单或二进制都会拒绝更新。
4. **最小权限**：Agent 以只读方式访问包数据库；不使用 `--privileged`，K8s 用 `readOnlyRootFilesystem: true` + hostPath 只读挂载。
5. **密钥管理**：CVE API Key 仅来自环境变量，Agent 令牌只存 SHA-256 摘要；SSH 凭据仅保存在本次连接内存中，不落库、不写日志。
6. **供应链**：镜像基于 `alpine`，单一来源构建，产物带自身 SBOM 摘要。

---

## 5. 数据模型

### 5.1 当前实现（SQLite，已落地）

> 以 `server/internal/infrastructure/sqlite/migrations/*.sql` 为准。核心表与关键索引：

```sql
-- 账号（角色 admin/operator/viewer）
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE, name TEXT NOT NULL, pwd_hash TEXT NOT NULL,
  role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, last_login TEXT NOT NULL DEFAULT ''
);

-- 资产（source: agent/ssh/container/self）
CREATE TABLE assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT NOT NULL UNIQUE, ip TEXT NOT NULL DEFAULT '',
  os_family TEXT NOT NULL DEFAULT '', os_version TEXT NOT NULL DEFAULT '',
  env TEXT NOT NULL DEFAULT '', exposure TEXT NOT NULL DEFAULT 'internal',
  tier TEXT NOT NULL DEFAULT 'normal', owner TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'agent', agent_status TEXT NOT NULL DEFAULT 'none',
  last_seen_at TEXT NOT NULL DEFAULT ''
);

-- 组件清单（按资产整体替换）
CREATE TABLE components (
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL,
  purl TEXT NOT NULL, eco TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
  version TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
  inferred INTEGER NOT NULL DEFAULT 0, UNIQUE(asset_id, purl)
);

-- CVE 主表（EPSS / 在野利用 / 修复版本内联）
CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  cvss_vector TEXT NOT NULL DEFAULT '', cvss_score REAL NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'medium', cwe_id INTEGER NOT NULL DEFAULT 0,
  cwe_cn TEXT NOT NULL DEFAULT '', published_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '', record_state TEXT NOT NULL DEFAULT 'published',
  official INTEGER NOT NULL DEFAULT 1, epss REAL NOT NULL DEFAULT 0,
  exploit_state TEXT NOT NULL DEFAULT 'none', fixed_version TEXT NOT NULL DEFAULT ''
);

-- 受影响版本区间（左闭右开，按产品名匹配）
CREATE TABLE cve_affected (
  cve_id TEXT NOT NULL, product TEXT NOT NULL,
  version_start_incl TEXT NOT NULL DEFAULT '', version_end_excl TEXT NOT NULL DEFAULT '',
  fixed_version TEXT NOT NULL DEFAULT '', PRIMARY KEY (cve_id, product)
);

CREATE TABLE cve_poc (
  id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
  link TEXT NOT NULL, inserted_at TEXT NOT NULL DEFAULT '', UNIQUE(cve_id, link)
);

CREATE TABLE product_map (
  eco TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, product TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 1.0, source TEXT NOT NULL DEFAULT 'manual',
  updated_at TEXT NOT NULL DEFAULT '', PRIMARY KEY (eco, name)
);

-- 漏洞结论（risk 为整数 0-100）
CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL, purl TEXT NOT NULL,
  component_name TEXT NOT NULL, component_version TEXT NOT NULL, eco TEXT NOT NULL DEFAULT '',
  cve_id TEXT NOT NULL, cvss REAL NOT NULL DEFAULT 0, epss REAL NOT NULL DEFAULT 0,
  exploit TEXT NOT NULL DEFAULT 'none', asset_weight REAL NOT NULL DEFAULT 0,
  risk INTEGER NOT NULL DEFAULT 0, priority TEXT NOT NULL DEFAULT 'P3',
  score_breakdown TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'open',
  inferred INTEGER NOT NULL DEFAULT 0, fixed_version TEXT NOT NULL DEFAULT '',
  assignee TEXT NOT NULL DEFAULT '', ticket_id TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT '',
  UNIQUE(asset_id, purl, cve_id)
);

CREATE TABLE finding_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
  event TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT ''
);

-- 本地工单（幂等：一个漏洞至多一张）
CREATE TABLE tickets (
  id TEXT PRIMARY KEY, finding_id INTEGER NOT NULL, cve_id TEXT NOT NULL,
  asset_id INTEGER NOT NULL, priority TEXT NOT NULL DEFAULT 'P3',
  status TEXT NOT NULL DEFAULT 'open', assignee TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

-- 审计、同步游标、策略、自检、Agent 令牌与元数据
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '', ua TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE sync_cursors (
  source TEXT PRIMARY KEY, last_run_at TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ok', count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE risk_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1), weights TEXT NOT NULL,
  thresholds TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE selfcheck_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL UNIQUE,
  started_at TEXT NOT NULL, finished_at TEXT NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, triggered_by TEXT NOT NULL DEFAULT '',
  passed INTEGER NOT NULL DEFAULT 0, warnings INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0, checks TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE agent_tokens (token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '');
CREATE TABLE notify_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1), webhook_url TEXT NOT NULL DEFAULT '',
  secret TEXT NOT NULL DEFAULT '', events TEXT NOT NULL DEFAULT '[]',
  last_event TEXT NOT NULL DEFAULT '', last_status TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '', last_sent_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT ''
);

-- Agent Harness：会话、消息、工具调用、审批
CREATE TABLE agent_sessions (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, role TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE agent_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '', tool_calls TEXT NOT NULL DEFAULT '[]',
  tool_call_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE agent_tool_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, tool TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '{}', args_hash TEXT NOT NULL, risk TEXT NOT NULL DEFAULT 'low',
  status TEXT NOT NULL DEFAULT 'running', result TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '',
  approver TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE agent_approvals (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool TEXT NOT NULL,
  args_hash TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}', call_id TEXT NOT NULL DEFAULT '',
  risk TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT NOT NULL DEFAULT '', requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  decided_at TEXT NOT NULL DEFAULT '', decided_by TEXT NOT NULL DEFAULT '',
  consumed_at TEXT NOT NULL DEFAULT ''
);
```

关键索引：`findings(risk DESC)`、`findings(priority)`、`findings(status)`、`findings(asset_id)`、
`findings(cve_id)`、`components(asset_id)`、`cve_affected(product)`、`cves(updated_at)`、
`cves(epss DESC)`、`audit_logs(created_at DESC)`、`tickets(finding_id)`、`tickets(status, updated_at DESC)`、
`agent_sessions(owner, updated_at DESC)`、`agent_messages(session_id, id)`、`agent_approvals(session_id, status)`。

### 5.2 目标模型（规划中，尚未实现）

> 以下为后续演进方向（Agent 注册/心跳、SBOM 快照版本化、EPSS 历史、API Token、多租户）。
> 当前版本没有这些表，不要据此编写查询。

```sql
-- 资产
CREATE TABLE assets (
  id            INTEGER PRIMARY KEY,
  hostname      TEXT NOT NULL,
  ip            TEXT,
  os_family     TEXT,            -- debian/rhel/alpine/windows/container
  os_version    TEXT,
  env           TEXT,            -- prod/staging/dev
  business_tier TEXT DEFAULT 'normal',   -- core/important/normal
  exposure      TEXT DEFAULT 'internal', -- public/internal/isolated
  owner         TEXT,
  source        TEXT NOT NULL,   -- agent/ssh/container/self
  agent_id      TEXT,
  last_seen_at  TEXT,
  tenant_id     TEXT DEFAULT 'default',
  UNIQUE(hostname, tenant_id)
);

-- Agent 注册与心跳
CREATE TABLE agents (
  id             TEXT PRIMARY KEY,   -- uuid
  asset_id       INTEGER REFERENCES assets(id),
  cert_fp        TEXT NOT NULL,      -- 客户端证书指纹
  agent_version  TEXT,
  status         TEXT,               -- active/offline/revoked
  last_heartbeat TEXT,
  enrolled_at    TEXT
);

-- SBOM 快照
CREATE TABLE sbom_snapshots (
  id            INTEGER PRIMARY KEY,
  asset_id      INTEGER NOT NULL REFERENCES assets(id),
  source        TEXT NOT NULL,
  collected_at  TEXT NOT NULL,
  digest        TEXT NOT NULL,
  component_cnt INTEGER,
  raw_ref       TEXT,               -- 原始上报对象存储键（可选）
  UNIQUE(asset_id, digest)
);

-- 组件（快照内）
CREATE TABLE components (
  id           INTEGER PRIMARY KEY,
  snapshot_id  INTEGER NOT NULL REFERENCES sbom_snapshots(id),
  purl         TEXT NOT NULL,
  eco          TEXT,                -- deb/rpm/apk/golang/npm/pypi/maven/oci
  name         TEXT NOT NULL,
  vendor       TEXT,
  version      TEXT NOT NULL,
  arch         TEXT,
  cpe          TEXT,
  inferred     INTEGER DEFAULT 0,
  locations    TEXT                 -- JSON 数组
);
CREATE INDEX idx_components_purl ON components(purl);
CREATE INDEX idx_components_eco_name ON components(eco, name);

-- 当前态（物化，便于查询）
CREATE TABLE inventory_current (
  asset_id    INTEGER NOT NULL,
  purl        TEXT NOT NULL,
  version     TEXT NOT NULL,
  vendor      TEXT,
  product     TEXT,
  first_seen  TEXT,
  last_seen   TEXT,
  PRIMARY KEY(asset_id, purl)
);

-- CVE 主表
CREATE TABLE cves (
  cve_id       TEXT PRIMARY KEY,
  title        TEXT,
  description  TEXT,
  cvss_vector  TEXT,
  cvss_score   REAL,
  severity     TEXT,                -- critical/high/medium/low/none
  cwe_id       INTEGER,
  cwe_cn       TEXT,
  published_at TEXT,
  updated_at   TEXT,
  record_state TEXT,
  official     INTEGER,
  raw_json     TEXT,
  fetched_at   TEXT
);
CREATE INDEX idx_cves_cvss ON cves(cvss_score DESC);
CREATE INDEX idx_cves_updated ON cves(updated_at);

-- 受影响产品与版本区间
CREATE TABLE cve_affected (
  id                 INTEGER PRIMARY KEY,
  cve_id             TEXT NOT NULL REFERENCES cves(cve_id),
  cpe_vendor         TEXT,
  cpe_product        TEXT NOT NULL,
  version_start_incl TEXT,
  version_start_excl TEXT,
  version_end_incl   TEXT,
  version_end_excl   TEXT,
  fixed_version      TEXT,
  source             TEXT
);
CREATE INDEX idx_aff_product ON cve_affected(cpe_product);
CREATE INDEX idx_aff_vp ON cve_affected(cpe_vendor, cpe_product);

-- POC / 在野利用
CREATE TABLE cve_poc (
  id         INTEGER PRIMARY KEY,
  cve_id     TEXT NOT NULL,
  link       TEXT,
  inserted_at TEXT,
  UNIQUE(cve_id, link)
);

-- EPSS
CREATE TABLE cve_epss (
  cve_id     TEXT NOT NULL,
  score      REAL,
  percentile REAL,
  date       TEXT NOT NULL,
  PRIMARY KEY(cve_id, date)
);

-- PURL → CPE 映射
CREATE TABLE product_map (
  purl_namespace TEXT,
  purl_name      TEXT NOT NULL,
  cpe_vendor     TEXT,
  cpe_product    TEXT NOT NULL,
  confidence     REAL DEFAULT 1.0,
  updated_by     TEXT,
  updated_at     TEXT,
  PRIMARY KEY(purl_namespace, purl_name)
);

-- 漏洞结论
CREATE TABLE findings (
  id            INTEGER PRIMARY KEY,
  asset_id      INTEGER NOT NULL,
  purl          TEXT NOT NULL,
  component_version TEXT NOT NULL,
  cve_id        TEXT NOT NULL,
  cvss_score    REAL,
  epss          REAL,
  exploit_state TEXT,               -- poc/kev/none
  asset_weight  REAL,
  risk_score    REAL,
  priority      TEXT NOT NULL,      -- P0..P3
  score_breakdown TEXT,             -- JSON
  status        TEXT NOT NULL,      -- open/triaged/fixing/fixed/verified/closed/risk_accepted/false_positive
  inferred      INTEGER DEFAULT 0,
  fixed_version TEXT,
  assignee      TEXT,
  ticket_id     TEXT,
  first_seen    TEXT,
  last_seen     TEXT,
  verified_at   TEXT,
  UNIQUE(asset_id, purl, cve_id)
);
CREATE INDEX idx_findings_prio ON findings(priority, risk_score DESC);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_asset ON findings(asset_id);

-- 事件流水
CREATE TABLE finding_events (
  id         INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL,
  event      TEXT NOT NULL,
  actor      TEXT,
  payload    TEXT,
  created_at TEXT
);

-- 本地工单（控制面自建，幂等：一个漏洞至多一张工单）
CREATE TABLE tickets (
  id         TEXT PRIMARY KEY,        -- VA-YYYY-NNNN
  finding_id INTEGER NOT NULL,
  cve_id     TEXT NOT NULL,
  asset_id   INTEGER NOT NULL,
  priority   TEXT NOT NULL DEFAULT 'P3',
  status     TEXT NOT NULL DEFAULT 'open',
  assignee   TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  note       TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_tickets_finding ON tickets(finding_id);
CREATE INDEX idx_tickets_status ON tickets(status, updated_at DESC);

-- 主机遥测：性能时序 + 最新硬件/服务/端口快照
CREATE TABLE host_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL, ts TEXT NOT NULL,
  cpu_percent REAL NOT NULL DEFAULT 0, load1 REAL NOT NULL DEFAULT 0,
  load5 REAL NOT NULL DEFAULT 0, load15 REAL NOT NULL DEFAULT 0,
  mem_used INTEGER NOT NULL DEFAULT 0, mem_total INTEGER NOT NULL DEFAULT 0,
  swap_used INTEGER NOT NULL DEFAULT 0, swap_total INTEGER NOT NULL DEFAULT 0,
  disk_read_bps REAL NOT NULL DEFAULT 0, disk_write_bps REAL NOT NULL DEFAULT 0,
  net_rx_bps REAL NOT NULL DEFAULT 0, net_tx_bps REAL NOT NULL DEFAULT 0,
  uptime_sec INTEGER NOT NULL DEFAULT 0, process_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_host_metrics_asset_ts ON host_metrics(asset_id, ts DESC);

CREATE TABLE asset_telemetry (
  asset_id INTEGER PRIMARY KEY, collected_at TEXT NOT NULL,
  metrics_json TEXT NOT NULL DEFAULT '{}', hardware_json TEXT NOT NULL DEFAULT '{}',
  services_json TEXT NOT NULL DEFAULT '[]', ports_json TEXT NOT NULL DEFAULT '[]'
);

-- 主机作业：下行执行、重试与结果
CREATE TABLE host_jobs (
  id TEXT PRIMARY KEY, asset_id INTEGER NOT NULL, action TEXT NOT NULL,
  params TEXT NOT NULL DEFAULT '{}', risk TEXT NOT NULL DEFAULT 'high',
  status TEXT NOT NULL DEFAULT 'pending', requested_by TEXT NOT NULL DEFAULT '',
  approval_id TEXT NOT NULL DEFAULT '', idempotency_key TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
  next_run_at TEXT NOT NULL DEFAULT '', output TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '', exit_code INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT '', finished_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_host_jobs_asset ON host_jobs(asset_id, created_at DESC);
CREATE INDEX idx_host_jobs_status ON host_jobs(status, next_run_at);
CREATE UNIQUE INDEX idx_host_jobs_idem ON host_jobs(idempotency_key) WHERE idempotency_key <> '';

CREATE TABLE host_job_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, attempt INTEGER NOT NULL,
  status TEXT NOT NULL, output TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT ''
);

-- Agent 长期记忆
CREATE TABLE agent_memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL DEFAULT 'global',
  scope_key TEXT NOT NULL DEFAULT '', content TEXT NOT NULL,
  source_session TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX idx_agent_memories_scope ON agent_memories(scope, scope_key, updated_at DESC);

-- 权限
CREATE TABLE users (
  id         INTEGER PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,
  pwd_hash   TEXT,
  role       TEXT NOT NULL,        -- admin/operator/viewer
  disabled   INTEGER DEFAULT 0,
  created_at TEXT
);
CREATE TABLE api_tokens (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER,
  name       TEXT,
  token_hash TEXT NOT NULL,
  scopes     TEXT,
  expires_at TEXT,
  created_at TEXT
);

-- 审计
CREATE TABLE audit_logs (
  id          INTEGER PRIMARY KEY,
  actor       TEXT,
  action      TEXT NOT NULL,
  target_type TEXT,
  target_id   TEXT,
  ip          TEXT,
  ua          TEXT,
  request_id  TEXT,
  detail      TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_audit_time ON audit_logs(created_at DESC);

-- 同步游标
CREATE TABLE sync_cursors (
  source     TEXT PRIMARY KEY,     -- cve/poc/epss
  cursor_val TEXT,
  last_run_at TEXT,
  status     TEXT,
  error      TEXT
);
```

---

## 6. 接口设计

### 6.1 Agent 侧（Bearer 令牌，mTLS 规划中）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/agent/report` | 上报 SBOM（Bearer 令牌），幂等 upsert 并立即匹配 |
| POST | `/api/v1/agent/enroll` | 规划中：一次性 bootstrap token 换发 mTLS 证书 |
| GET | `/api/v1/agent/policy` | 规划中：采集间隔、排除项、自更新通道 |
| GET | `/api/v1/agent/binary/latest` | 规划中：自更新清单与签名 |

`report` 请求示例：

```json
{
  "agent_id": "0b1f...",
  "collected_at": "2026-10-22T09:00:00Z",
  "mode": "incremental",
  "host": {"hostname":"web-01","os":"debian","os_version":"12","ip":"10.0.0.11"},
  "components": [
    {"purl":"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64","locations":["/usr/bin/openssl"]}
  ],
  "removed": ["pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u5"],
  "self_sbom": [{"purl":"pkg:golang/github.com/gin-gonic/gin@v1.9.1"}]
}
```

### 6.2 人类用户 API（session / token）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/v1/auth/login` | - | 登录，返回会话（失败 5 次锁定 5 分钟） |
| GET | `/api/v1/me` | 登录 | 当前用户与角色 |
| POST | `/api/v1/me/password` | 登录 | 修改本人口令（旧口令校验，其他会话下线） |
| GET/POST | `/api/v1/users` | admin | 账号列表 / 新建账号 |
| PATCH | `/api/v1/users/{username}` | admin | 改姓名、角色、停用启用 |
| POST | `/api/v1/users/{username}/reset-password` | admin | 重置口令并踢下线 |
| POST | `/api/v1/agent/token/rotate` | admin | 轮换 Agent 接入令牌 |
| GET | `/api/v1/assets` | viewer+ | 分页、按环境/暴露面筛选 |
| GET | `/api/v1/assets/{id}/sbom` | viewer+ | 最近快照组件清单 |
| POST | `/api/v1/assets/ssh-scan` | operator+ | SSH 兜底采集（只读脚本，凭据不落库） |
| GET | `/api/v1/findings` | viewer+ | 按 priority/status/asset/时间筛选 |
| GET | `/api/v1/findings/{id}` | viewer+ | 含 score_breakdown、POC、修复建议 |
| PATCH | `/api/v1/findings/{id}` | operator+ | 改状态/责任人/备注 |
| POST | `/api/v1/findings/{id}/ticket` | operator+ | 创建工单/推送外部系统 |
| POST | `/api/v1/findings/{id}/rescan` | operator+ | 触发单资产复扫 |
| POST | `/api/v1/scans` | operator+ | 触发指定资产/分组扫描 |
| GET | `/api/v1/reports/findings.pdf` | operator+ | 按筛选条件导出 PDF 报告（审计留痕） |
| GET | `/api/v1/reports/findings.csv` | operator+ | 按筛选条件导出 CSV（UTF-8 BOM，上限 5000 条） |
| GET/PUT | `/api/v1/notify-settings` | admin | Webhook 通知配置 |
| POST | `/api/v1/notify-settings/test` | admin | 发送测试事件 |
| GET | `/api/v1/stats/overview` | viewer+ | P0–P3 分布、Top 组件、趋势 |
| POST | `/api/v1/sync/{cve\|epss\|poc}` | admin | 手动触发同步 |
| POST | `/api/v1/sync/epss/refresh` | admin | 从 FIRST 在线拉取 EPSS 并重算 |
| GET/PATCH | `/api/v1/settings/risk-policy` | admin | 权重与分档 |
| GET/POST/PATCH | `/api/v1/users`、`/api/v1/users/{username}` | admin | 账号与角色 |
| GET | `/api/v1/audit-logs` | admin | 审计检索 |

### 6.3 对外回调

- `POST {webhook}`：`finding.new`（新增 P0/P1）、`ticket.created`、`sync.failed`、`selfcheck.failed`；HMAC-SHA256 签名（`X-VulnAgent-Signature`），失败退避重试 3 次，事件头 `X-VulnAgent-Event`。
- 工单系统回写（Jira/飞书审批状态）：尚未实现。

---

## 7. 性能设计

| 指标 | 目标 | 手段 |
|---|---|---|
| 单机采集耗时 | ≤ 3 s（典型 1–2 s） | 直接读包数据库文件，不逐包调命令 |
| Agent 常驻内存 | ≤ 50 MB | one-shot + systemd timer，不常驻 |
| 上报体积 | 增量 ≤ 200 KB | 仅 diff + gzip |
| 全量重匹配 | 1 万资产 / 300 万组件 ≤ 60 s | 内存索引（`vendor+product → cve`）+ 分区并行 worker |
| 控制面内存 | ≤ 300 MB（1 万资产） | 索引只保留 `cve_id → {score,epss,products}` 轻量结构 |
| 看板首屏 | ≤ 1 s | 物化统计表 + 分页索引 |
| 同步吞吐 | ≥ 20 万 CVE/小时（离线导入） | 批量事务（500 条/批）+ 关闭同步写盘 |

索引与写入要点：

- SQLite 启用 `WAL`、`synchronous=NORMAL`、`mmap_size=256MB`。
- 批量写入用单事务 + 预编译语句；避免逐条 commit。
- 匹配阶段只读内存索引，结果批量落库；重算用临时表 + 原子替换，避免读抖动。
- 迁移：`server/internal/infrastructure/sqlite/migrations/*.sql` 通过 `go:embed` 打包，启动时按文件名顺序执行未应用脚本，执行记录写入 `schema_migrations`；脚本全部使用 `IF NOT EXISTS`，对既有库幂等。
- 只读连接：Harness 读工具使用 `mode=ro` 的独立连接（`sqlite.OpenReadOnly`），从连接层杜绝写入。
- 端口与仓储：`server/internal/application/ports` 定义读写契约（资产、情报、漏洞、账号、审计、策略、通知、同步、统计），`server/internal/infrastructure/sqlite/*_repo.go` 提供实现；接口层只做 DTO 编解码与参数校验，不再直接拼 SQL。
- 仍保留直接 SQL 的只有基础设施与运维代码：`selfcheck.go`（探测）、`seed.go`（演示数据）、`ensureProductMap`（内置映射初始化）与 `backup` 子命令。
- 配置：全部环境变量集中在 `server/internal/platform/config`，默认数据目录 `./data`，可用 `VA_DATA_DIR` 覆盖。

---

## 7.5 Agent Harness（叠加层）

Harness 不接管扫描，只在用户提问时调用既有应用服务。所有副作用通过静态注册的工具显式发生。

### 7.5.1 结构

```
internal/domain/harness      工具规格、风险分级、会话/消息/调用/审批、参数指纹
internal/application/harness 注册表、对话循环、九道闸门、审批、脱敏
internal/application/ports   LLM 与 HarnessRepository 端口
internal/infrastructure/llm/openai  OpenAI 兼容 Chat Completions（含 tools）
internal/infrastructure/sqlite/harness_repo.go  四张表的仓储
harness_tools.go             29 个工具的绑定（读工具走 mode=ro 连接）
harness_handlers.go          SSE 会话接口与审批接口
```

模型凭据只从环境变量读取：`VA_LLM_BASE_URL`、`VA_LLM_API_KEY`、`VA_LLM_MODEL`，三项齐备才启用；缺失时服务照常启动，助手页提示配置方法。

### 7.5.2 九道执行闸门

1. **身份不可由模型决定**：主体只来自服务端会话，模型输出不能携带用户名/角色。
2. **静态工具表**：工具编译期注册，未知工具直接拒绝。
3. **参数校验**：必须是合法 JSON 对象且 ≤ 64KB。
4. **最小权限**：按角色裁剪工具，服务端再次校验，越权直接返回拒绝结果。
5. **只读连接**：读工具使用 `sqlite.OpenReadOnly`（`mode=ro`），从连接层杜绝写入。
6. **风险分级与会话权限**：medium/high 默认必须人工审批；会话可切换 `each`（每次审批）、`smart`（模型判断，失败即转人工）、`full`（直接执行，`approver=auto:full` 留痕）三种模式，切换写 `agent.session.mode` 审计。
7. **参数指纹**：审批绑定 `SHA-256(排序后的参数 JSON)`，参数任何变化即失效。
8. **一次性消费 + TTL**：审批 10 分钟过期，`approved` 后立即消费，重复处理返回 409。
9. **再认证与限流**：high 风险需 5 分钟内口令再认证；每会话 20 次/分钟、每轮最多 4 步。

所有调用写入 `agent_tool_calls`，审批写入 `agent_approvals`，并在 `audit_logs` 留下动作记录；工具输出经脱敏（password/secret/token/api_key/authorization）。

### 7.5.3 工具清单（29 个）

| 风险 | 工具 | 最小角色 |
|---|---|---|
| low | overview_summary、list_assets、get_asset、host_metrics、host_hardware、list_findings、get_finding、search_cves、get_cve、list_product_map、get_sync_status、get_selfcheck_latest、list_host_jobs、get_host_job、recall_memory | viewer/operator |
| low | list_audit_logs | admin |
| medium | rescan_asset、read_host_file、create_snapshot、remember | operator |
| medium | run_selfcheck | admin |
| high | update_finding_status、create_ticket、run_host_command、write_host_file、service_action、restore_snapshot、apply_remediation | operator |
| high | upsert_product_map | admin |

明确不暴露：SSH 扫描、Agent 令牌轮换、账号增删改、风险策略修改、任意 shell 拼接 / 任意 SQL / 任意 URL。
主机命令只接受 argv 数组与白名单命令；写文件限白名单目录并自动备份；快照 + 回滚与包升级均需审批，高风险需口令再认证。

### 7.5.4 交互流程

1. `POST /agent/sessions` 建会话（可带 `approvalMode`）；`POST /agent/sessions/{id}/messages` 以 SSE 流式返回 `message / tool_call / tool_result / approval_required / done`。
2. 输入框上方可切换 `each / smart / full` 权限；切换调用 `PATCH /agent/sessions/{id}`。
3. 遇到需要人工的写操作：本轮暂停，输入框上方固定展示「批准并执行 / 拒绝」按钮（high 需口令），模型不得用文字索要确认。
4. `POST /agent/approvals/{id}` 批准或拒绝；批准后立即执行并写入工具结果消息。
5. `POST /agent/sessions/{id}/resume` 继续本轮，让模型汇总执行结果。

### 7.5.5 数据表

`agent_sessions`（含 `approval_mode`）、`agent_messages`（含 `tool_call_id`）、`agent_tool_calls`（参数指纹、风险、状态、审批人/自动放行人）、`agent_approvals`（指纹、TTL、一次性消费）。迁移见 `sqlite/migrations/0002_harness.sql` 与 `0008_session_mode.sql`。

### 7.5.6 验收

- 单元测试覆盖：参数指纹稳定性、只读循环、写操作审批、一次性消费、越权拒绝、高风险再认证、会话隔离、三种审批模式（含 AI 判断放行/转人工与解析兜底）。
- 真实联调：火山方舟（OpenAI 兼容）完成「查询 → 工具调用 → 结论」与「改状态 → 审批 → 口令 → 执行 → 汇总」两条链路。

---

## 8. 部署方案

### 8.1 单机（推荐起步）

```bash
# 控制面
curl -fsSL https://dl.example.com/vulnagent/install.sh | sh
vulnagent server init --data /var/lib/vulnagent --admin admin
systemctl enable --now vulnagent

# 主机 Agent
vulnagent agent enroll --server https://vuln:8443 --token <bootstrap> 
systemctl enable --now vulnagent-agent.timer
```

### 8.2 Docker Compose

```yaml
services:
  vulnagent:
    image: ghcr.io/your-org/vulnagent:1.0.0
    ports: ["8443:8443"]
    volumes:
      - ./data:/var/lib/vulnagent
    environment:
      VULNAGENT_CVE_API_KEY: ${CVE_API_KEY}
      VULNAGENT_MASTER_KEY_FILE: /run/secrets/master.key
  postgres:            # 可选，> 5000 资产时建议
    image: postgres:16-alpine
```

### 8.3 Kubernetes

- 控制面：`Deployment`（1 副本 + SQLite PVC；或 PG 时多副本）
- Agent：`DaemonSet`，`hostPID: true`、`readOnlyRootFilesystem: true`，只读挂载 `/var/lib/dpkg`、`/lib/apk/db`、`/var/lib/rpm`、`/var/lib/docker`
- 密钥：`Secret` 注入；CA 与主密钥建议外部 KMS

### 8.4 离线环境

1. 外网机器：`vulnagent sync export --out cve-bundle.tar.zst`（含 CVE + POC + EPSS + 映射表）
2. 内网导入：`vulnagent sync offline --bundle cve-bundle.tar.zst`
3. Agent 安装包与升级包随离线介质分发，安装脚本支持 `--offline`

---

## 9. 可观测性

| 类型 | 内容 |
|---|---|
| 日志 | `slog` JSON：`level, ts, module, asset_id, request_id, err` |
| 指标 | `va_scan_duration_seconds`、`va_ingest_bytes_total`、`va_match_duration_seconds`、`va_sync_lag_seconds`、`va_findings_total{priority}`、`va_agent_offline_total` |
| 健康检查 | `GET /healthz`（进程）、`GET /readyz`（DB + 索引就绪） |
| 告警 | 同步失败 > 3 次、Agent 离线 > 24 h、P0 新增未确认 > 4 h |

---

## 10. 包结构与里程碑

### 10.1 代码结构

```
cmd/vulnagent/main.go              # 子命令：server / agent / scan / sync
internal/
  agent/          collect_{linux,windows,container,self}.go  diff.go  report.go  update.go
  sshscan/        client.go  script.go  runner.go
  server/         router.go  middleware_{auth,ratelimit,audit}.go
  api/            agent_api.go  ui_api.go  dto.go
  auth/           rbac.go  session.go  mtls_ca.go  token.go
  ingest/         normalize.go  purl.go  idempotency.go
  inventory/      store.go  diff.go
  intel/          cve_client.go  poc_client.go  epss.go  sync.go  offline.go
  match/          matcher.go  cpe.go  index.go  vercmp_{deb,rpm,apk,semver}.go
  risk/           score.go  policy.go
  remediate/      advice.go  ticket.go  rescan.go
  store/          db.go  migrations/*.sql  sqlite.go  pg.go
  model/          types.go
  webui/          embed.go  dist/（构建产物）
deploy/           systemd/  compose/  helm/  install.sh
```

### 10.2 里程碑

| 阶段 | 交付 | 验收 |
|---|---|---|
| M1 采集与库存 | Agent 采集（Linux/Windows/容器/自身）、SBOM 归一化、SQLite 落库、`scan` 离线命令 | 目标机采集结果与 `dpkg -l` 人工核对一致率 ≥ 99% |
| M2 情报与匹配 | CVE/POC/EPSS 同步与离线包、CPE 映射、版本比较、finding 生成 | 对 20 个已知漏洞样本（含 nginx/openssl/log4j）召回 100%，误报 ≤ 5% |
| M3 排序与呈现 | 风险打分与分档、控制台看板、报告导出、RBAC 与审计 | P0 列表人工复核可解释；越权访问返回 403 且留痕 |
| M4 修复闭环 | 修复建议、工单/Webhook、复扫验证、SSH 兜底、K8s 部署 | 一条 P0 从发现→工单→复扫→closed 全流程跑通 |
| M5 加固与发布 | 自更新签名、自身 SBOM 入库、性能调优、离线安装包 | 1 万资产压测达标；断网环境完整跑通 |

---

## 11. 风险与待确认

| 风险/待定 | 影响 | 处理建议 |
|---|---|---|
| 漏洞平台 API 配额与稳定性未知 | 全量同步可能受限 | 首次走离线包；增量低频拉取；`search` 定向补齐限流 |
| API 不返回受影响版本区间（`cve_affected`） | 无法精确判定版本是否受影响 | 语言生态已接入 OSV 精确匹配；Windows 注册表软件仍依赖 CPE/版本区间（后续接 NVD CPE） |
| PURL → CPE 映射准确率 | 直接决定误报率 | 先覆盖 Top 2000 常用组件，其余标 `inferred` 降级处理 |
| Windows 补丁 KB 与 CVE 映射 | Windows 场景容易漏报 | v1 只做软件版本维度，KB 级别后续接微软 MSRC API |
| 是否需要 PDF 报告 | 影响前端实现量 | 已实现 PDF / CSV / JSON 导出 |
| 是否需要 CMDB 同步 | 影响资产权重准确度 | 接口已预留（`assets.owner/business_tier`），v1 支持 CSV 导入 |
| 多租户/多环境隔离 | 影响数据模型 | 已预留 `tenant_id`，v1 单租户 |

---

## 12. 当前实现（可运行骨架）

已按第 2 章的形态落地「控制面 API + Web 客户端 + 平台自检」的纵向切片，前端直接对接真实后端（无 mock）。接口以 [api-contract.md](./api-contract.md) 为准。

### 12.1 目录

```
server/                 Go 控制面 + 采集器（同一份二进制）
  main.go               子命令分发、路由、请求日志、静态托管（web/dist）
  cli.go                collect / agent 子命令
  db.go / seed.go       表结构 + 演示数据（12 资产 / 29 CVE / 版本区间）
  version.go            dpkg / rpm / apk / semver 版本比较
  match.go              受影响区间匹配、findings upsert、失效清理
  agent.go              Agent 令牌、上报处理、上报后立即匹配
  risk.go               四因子打分、分档硬规则、scoreBreakdown
  auth.go               bcrypt 账号、会话 Cookie、RBAC、审计
  handlers_*.go         findings / assets / overview / settings / audit / sync
  scanner.go            单资产/批量复扫、防抖、定时调度器
  report.go             PDF 报告（内嵌中文字体、概览卡片 + 明细表）
  export.go             漏洞清单 CSV 导出
  notify.go             Webhook 通知（HMAC 签名、退避重试、事件订阅）
  osv.go                OSV 在线精确版本匹配（语言生态）
  metrics.go            Prometheus 文本指标
  meta.go               运行模式标记（演示 / 生产）与环境开关
  security.go           会话空闲过期、登录限速、账号管理、令牌轮换、安全响应头
  assets/fonts/         Noto Sans SC（SIL OFL 1.1），编译期 embed
  selfcheck.go          16 项真实自检 + 历史
  internal/collect/     系统包采集：dpkg / rpm / apk / Windows 注册表 / 自身 SBOM
web/                    React 18 + Vite + TypeScript + Tailwind
  src/pages/            登录、概览、漏洞、资产、资产详情、自检、审计与设置
  src/components/       AppShell、FindingDrawer、TrendChart、PasswordDialog、UI 原语
Dockerfile              多阶段构建（前端 + Go，单镜像）
deploy/systemd/         控制面服务、Agent oneshot + timer、环境变量样例
deploy/k8s/             控制面 Deployment/Service/PVC、Agent CronJob
docs/architecture/      架构图、详细设计、API 契约
data/vulnagent.db       首次启动自动生成（默认空库，VA_SEED_DEMO=on 才灌演示数据）
data/agent.token        Agent 接入令牌（0600）
```

### 12.2 运行

```powershell
cd server
go build -o bin/vulnagent.exe .

# 控制面（同时托管已构建的前端）
.\bin\vulnagent.exe server            # http://127.0.0.1:8787
# 可选：$env:VA_ADDR=':9000'; $env:VA_DATA_DIR='E:\va-data'（默认 ./data）
# 可选：$env:VA_WEB_DIST='..\web\dist'（默认依次探测 ../web/dist、./web/dist、web/dist）
# 可选：$env:VA_RESCAN_INTERVAL='30m'; $env:VA_RESCAN_DEBOUNCE='10m'（间隔设 0/off 关闭定时复扫）
# 可选：$env:VA_SESSION_IDLE='30m'; $env:VA_COOKIE_SECURE='1'（HTTPS 部署时强制 Secure Cookie）
# 可选：$env:VULNAGENT_CVE_BASE_URL='https://cve.imfht.com'; $env:VA_EPSS_URL='https://epss.cyentia.com/epss_scores-current.csv.gz'
# Agent 助手（三项齐备才启用，建议用系统环境变量而非脚本）
# $env:VA_LLM_BASE_URL='https://ark.cn-beijing.volces.com/api/v3'; $env:VA_LLM_API_KEY='...'; $env:VA_LLM_MODEL='deepseek-v4-1-flash-261017'
# 生产模式：不灌演示数据，用 VA_ADMIN_PASSWORD 初始化唯一管理员（首次启动）
# $env:VA_SEED_DEMO='off'; $env:VA_ADMIN_PASSWORD='请替换为强口令'

# 采集（只读，不联网）
.\bin\vulnagent.exe collect --out ..\data\sbom.json

# 采集并上报（令牌自动读取 ..\data\agent.token）
.\bin\vulnagent.exe agent --server http://127.0.0.1:8787
# 其他主机：复制 data\agent.token 后 --token-file <path>，或设置 VA_AGENT_TOKEN

# 前端开发模式（热更新，/api 代理到 8787）
cd web
npm install
npm run dev                           # http://127.0.0.1:5173
npm run build                         # 产物输出到 web/dist，由 Go 二进制托管

# 数据库备份（服务运行中也可执行，生成一致性快照）
.\bin\vulnagent.exe backup --out ..\data\backup-20261023.db

# 在线拉取 EPSS（也可在控制台「情报同步」点击在线刷新）
.\bin\vulnagent.exe sync --epss

# 语言生态精确匹配（Go / npm / PyPI / Maven / NuGet / Debian / Alpine）
.\bin\vulnagent.exe osvscan --all

# 发布与自更新：发布机生成密钥并签名，Agent 侧校验后替换
.\bin\vulnagent.exe keygen --out .\release-keys
.\bin\vulnagent.exe sign --key .\release-keys\update.key --binary .\bin\vulnagent.exe \
  --url https://dl.example.com/vulnagent.exe --version 0.2.0
.\bin\vulnagent.exe self-update --manifest .\manifest.json --pubkey .\release-keys\update.pub

# 容器化（单镜像，内含前端产物与字体）
docker build -t vulnagent:0.1.0 .
docker run -d --name vulnagent -p 8787:8787 -v vulnagent-data:/app/data \
  -e VA_COOKIE_SECURE=1 -e VULNAGENT_CVE_API_KEY=xxx vulnagent:0.1.0

# systemd / K8s 交付物见 deploy/ 目录（server.service、agent.service+timer、k8s/*.yaml）
```

演示账号（仅 `VA_SEED_DEMO=on` 时存在）：`admin / Admin@12345`（管理员）、`operator / Ops@12345`（运维）、`viewer / View@12345`（只读）。生产模式默认不创建，仅用 `VA_ADMIN_PASSWORD` 初始化管理员。

### 12.3 已实现

| 能力 | 说明 |
|---|---|
| 认证与 RBAC | 会话 Cookie；admin 管策略/账号/同步，operator 可处置与触发扫描，viewer 只读 |
| 概览 | P0–P3 计数与占比、14 天趋势、Top 风险组件、情报/Agent 状态、最近审计事件 |
| 漏洞清单 | 优先级/状态/关键词筛选、分页、详情抽屉（风险构成四因子、修复建议命令、POC、处理记录） |
| 资产 | 主机列表、资产详情（组件清单 + 关联漏洞）、CPE 映射与推断标记 |
| 自检 | 16 项真实检查，一键运行并落库，含历史记录与告警建议 |
| 审计与设置 | 审计日志分页、风险权重与阈值调整（保存后重算全部 findings） |
| 采集器 | 单二进制子命令；Linux 解析 dpkg/rpm/apk，Windows 读取注册表卸载项，附带自身依赖 SBOM，统一产出 PURL |
| Agent 上报 | Bearer 令牌鉴权；按 hostname upsert 资产、整体替换组件清单、清理失效漏洞并立即匹配 |
| 情报同步 | 真实调用漏洞平台 `/api/cve/`、`/api/poc/`（公开接口免鉴权，可选 `X-API-Key`、429/5xx 重试、按 `updated_at` 游标增量）；兼容 `desc`/`description` 与 `CWE-xxx` 形式；CVSS 3.1 分值本地计算；支持 `vulnagent sync --bundle` 离线包导入 |
| OSV 精确匹配 | 按「包名+版本+生态」查询 OSV（Go/npm/PyPI/Maven/NuGet/Debian/Alpine 等），补齐平台缺失的受影响版本区间与修复版本；上报后异步执行，也可手动/定时触发 |
| SSH 兜底 | 控制面 SSH 直连执行只读脚本（dpkg/rpm/apk），支持口令/私钥与主机指纹校验，结果复用同一套入库与匹配管道 |
| EPSS 导入 | 支持上传 FIRST CSV，或从 `epss.cyentia.com` 在线拉取全量 gzip CSV；更新 CVE 的 EPSS 后同步漏洞快照并按当前策略重算风险分 |
| 产品映射 | `(eco, name) → 产品名` 映射，内置常见别名，控制台可增删改，保存后自动重匹配全部资产 |
| 复扫闭环 | 重新匹配后自动收敛：升级至修复版本 / 不再命中 → verified，组件移除 → closed，并写入事件与审计 |
| 本地工单 | 控制面自建工单（`VA-YYYY-NNNN`），一个漏洞至多一张、建单幂等；状态与责任人随漏洞处置同步，提供 `GET /api/v1/tickets` 列表与 `ticket.created` webhook |
| 主机遥测 | Agent 上报 CPU/内存/磁盘/网络/负载/进程性能时序与硬件、服务、监听端口；Linux 走 `/proc`、`/sys`、systemd/ss，Windows 走 PowerShell/CIM；资产详情支持趋势图与设备详情 |
| 主机作业通道 | Agent pull 拉取作业，领取时原子抢占；服务端指数退避 + 抖动安排重试；作业幂等键 10 分钟内去重；执行结果写 `host_jobs` 与 `host_job_attempts`；作业带 HMAC 签名，同资产运行中不派发新作业 |
| 受控主机执行 | `run_host_command`（argv 白名单）、`read_host_file`、`write_host_file`（白名单目录 + 原子写 + 自动备份）、`service_action`；全部走审批，高风险需口令再认证 |
| 提权 helper | `vulnagent helper` 仅接受白名单动作；Linux 通过 `sudo -n` 调用，Windows 需 Agent 以管理员/SYSTEM 运行 |
| 上下文记忆 | 会话超过 20 条后自动压缩早期消息为摘要；48KB 字符预算从最新消息回溯保留；长期记忆 `agent_memories` 支持 global/asset 作用域，`remember`/`recall_memory` 工具与对话自动召回 |
| 操作轨迹 | `GET /api/v1/trajectory` 聚合审计、主机作业与工具调用，按时间倒序；控制台「轨迹」页支持按类型过滤 |
| 快照与回滚 | `snapshot` 动作把文件复制到内容寻址快照目录并写 manifest（SHA-256 校验）；`restore_snapshot` 校验 ID/路径/哈希后原子恢复 |
| 漏洞自动修复 | `apply_remediation` 按 finding 的修复版本生成包升级作业，支持 dry-run；成功后异步复扫收敛，失败保留输出供回滚 |
| 运维执行策略 | 设置中心可配置只读模式、每资产每小时作业上限与作业保留天数；服务端入队强制校验，超期作业启动时清理 |
| 定时/批量复扫 | 控制面常驻 ticker 每 `VA_RESCAN_INTERVAL`（默认 30m）全量收敛；`POST /api/v1/scans` 支持指定资产或全量；单资产 `VA_RESCAN_DEBOUNCE`（默认 10m）防抖，命中窗口返回 `skipped` |
| PDF 报告 | 漏洞页按当前筛选导出 A4 中文报告（概览卡片 + 明细），内嵌思源黑体保证离线可用，`operator+` 权限，导出写审计 |
| 账号与登录防护 | 控制台可新建/改角色/停用/重置口令；本人口令修改后其他会话下线；同账号+IP 连错 5 次锁定 5 分钟；失败与锁定写审计 |
| 会话与安全头 | 空闲 30 min 滑动过期（`VA_SESSION_IDLE`）、Cookie `HttpOnly/SameSite=Lax`、HTTPS 或 `VA_COOKIE_SECURE=1` 时启用 `Secure`；nosniff / frame-deny / no-referrer，写操作同源校验 |
| Agent 令牌轮换 | `admin` 一键轮换，旧令牌立即失效，新令牌仅返回一次并写入 `agent.token`（0600） |
| CSV 导出 | 漏洞清单按当前筛选导出 CSV（UTF-8 BOM、上限 5000 条），写 `report.export_csv` 审计 |
| Webhook 通知 | 新增 P0/P1、工单创建、同步失败、自检失败四类事件，HMAC 签名 + 3 次退避重试，设置页可视化配置与测试 |
| 数据备份 | `vulnagent backup --out <file>` 走 SQLite `VACUUM INTO`，服务运行中可生成一致性快照 |
| 运行模式 | 默认不灌演示数据；仅 `VA_SEED_DEMO=on/1/true/yes` 时灌入演示资产并标记 `demo_mode`。生产模式用 `VA_ADMIN_PASSWORD` 初始化管理员，`/healthz` 与前端「演示数据」标识保持一致 |
| 观测 | `GET /api/v1/metrics` 输出 Prometheus 文本指标（漏洞按优先级/状态、资产、组件、CVE、在线 Agent、最近自检失败数），支持 Agent Bearer 令牌抓取 |
| 自更新签名链 | `keygen` 生成 Ed25519 密钥对，`sign` 产出带签名清单，`self-update` 校验签名 + SHA-256 后原子替换并保留 `.old`；已实测篡改清单被拒 |
| 交付物 | 多阶段 Dockerfile（前端 + Go 单镜像）、systemd server/agent 单元与 timer、K8s Deployment/Service/PVC 与 Agent CronJob |
| 版本区间匹配 | dpkg / rpm / apk / semver 比较器 + `cve_affected` 左闭右开区间；演示数据同样由该规则生成，不再精确比对版本号 |
| 演示数据 | 完全入库的真实 CVE 编号与组件版本，界面标注「演示数据」 |

### 12.4 自检项清单（`POST /api/v1/selfcheck/run`）

| 分组 | 检查项 id | 判定 |
|---|---|---|
| 数据库 | `db.integrity` / `db.volume` / `db.latency` | quick_check、表与行数、实测读写耗时（>200ms 警告） |
| 情报同步 | `intel.cve_lag` / `intel.epss_coverage` / `intel.poc_feed` | 滞后 >6h 警告、>48h 失败；EPSS 覆盖 <80% 警告 |
| 采集链路 | `collect.agent_online` / `collect.stale_agents` / `collect.last_report` | 在线率 <80% 警告、<50% 失败；离线 >24h 警告 |
| 平台自身 | `self.sbom_findings` / `self.build_info` / `self.disk` / `self.intel_api` | 自身 P0/P1 >0 失败；情报接口 6s 探测不可达告警 |
| 权限与审计 | `auth.default_password` / `auth.rbac` / `audit.enabled` | 初始口令未改警告；仅 admin 角色告警；审计可写 |

整体状态取最差项；每次运行写一条审计记录，仅保留最近 10 次历史。

### 12.5 尚未实现（下一步）

- OIDC 单点登录、按 scope 签发的细粒度 API Token
- 告警规则细化（Agent 离线超 24h、P0 新增未确认超 4h 的自动升级与提醒）
- 邮件 / IM 直连通道，以及工单外部联动（Jira、飞书审批回写；当前仅通用 Webhook 推送）
- CI 流水线（go vet/test、前端构建、govulncheck、镜像构建与签名产物）
- 组件清单前端虚拟滚动（200+ 行已可流畅渲染，万台资产需要窗口化）
- 产品映射字典扩充（当前内置 7 条常见别名，后续接入 NVD CPE 字典自动生成）
- Windows 注册表软件的 CPE 版本区间匹配（当前语言生态走 OSV，Windows 应用暂无自动匹配源）
- macOS 采集（当前 Linux dpkg/rpm/apk 与 Windows 注册表，macOS 仅提示不支持）

