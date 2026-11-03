# 多集群与项目运维设计（v1.3）

日期：2026-11-03
状态：已落地（含异步任务、数据库深检、多 Agent 身份、SLO 与依赖根因分析）

## 1. 背景与目标

控制面、业务后端、数据库与目标资产经常分布在不同主机和网段。VulnAgent 首版是单二进制 + SQLite，无法假设所有组件都在同一台机器上。本设计解决三个问题：

1. 用「项目 → 集群 → 节点」描述真实部署拓扑，而不是只看单台资产。
2. 对后端、数据库、缓存、代理与扫描目标做统一健康检查与容量提示。
3. 对可 SSH 到达的节点复用现有只读采集，把主机资产与漏洞自动归入所属集群。

## 2. 非目标（首版不做）

- 不做多个控制面之间的数据联邦或双向同步；仍是单控制面管理多个集群。
- 默认不保存数据库账号；仅在显式配置只读账号后执行版本、连接数与容量查询，不代理业务查询、不读取业务数据。
- 不做控制面高可用/多活；SQLite 单写者模型保持不变。
- 不自动修复或变更目标主机；扫描始终只读。

## 3. 领域模型

| 实体 | 说明 | 关键字段 |
|---|---|---|
| Project | 业务项目，按团队/系统聚合 | name、owner、description |
| Cluster | 项目下的部署单元 | project_id、name、environment、provider、region、slo_target、slo_window_hours |
| ClusterNode | 集群中的角色节点 | role、host、port、url、ssh_host_id、check_type、path |
| ClusterNodeRelation | 节点依赖边 | from_node_id（依赖方）、to_node_id（被依赖方）、kind=depends_on |
| ClusterNodeCheck | 每次检查的时序样本 | cluster_id、node_id、status、latency_ms、detail、checked_at |
| Asset | 现有资产，新增 `cluster_id` 关联 | hostname、ip、os_family |
| Finding | 现有漏洞，通过资产间接归入集群 | priority、status |

节点角色：`backend`、`database`、`cache`、`proxy`、`storage`、`scan_target`。

## 4. 典型场景

控制面在 A 主机，业务后端在 B 主机，数据库在 C 主机：

1. 管理员创建项目「核心交易」，再创建集群「prod-a」。
2. 在集群中添加节点：
   - `backend-1`：role=backend，url=`http://B:8787/api/v1/healthz`。
   - `mysql-1`：role=database，host=C，port=3306，check_type=tcp。
   - `sqlite-1`：role=database，ssh_host_id=已保存的 C 主机，path=`/var/lib/app/app.db`，check_type=ssh_file。
   - `scan-target-1`：role=scan_target，ssh_host_id=已保存的 B/C 主机。
3. 「检查全部」创建后台任务，页面轮询得到 HTTP/TCP/SSH/文件检查结果与延迟；数据库节点可额外配置只读连接做深检。
4. 「扫描全部」创建后台任务，对关联 SSH 的节点执行只读软件清单采集，资产自动写入并设置 `cluster_id`。
5. 集群详情汇总节点健康、关联资产与 P0–P3 未关闭漏洞；已有资产也可手动关联，资产与漏洞数字可直接跳转到带集群范围的清单。

## 5. 健康检查策略

| 节点角色/检查方式 | 行为 | 成功条件 |
|---|---|---|
| backend / http | GET 节点 URL 或 `http://host:port/api/v1/healthz` | 2xx–3xx |
| database / tcp | TCP 连接 host:port | 连接成功 |
| database / 深检 | 配置 `dbEngine` 后使用只读账号连接 MySQL/PostgreSQL，读取版本、连接数、容量与运行时长 | 连接与只读查询均成功 |
| database / ssh_file | SSH 执行 `test -f`、`stat`、`df -Pk` | 文件存在且可读 |
| scan_target / ssh | 复用 SSH 连接池执行 `echo` | 认证与命令执行成功 |
| cache/proxy/storage / tcp | TCP 连接 | 连接成功 |

检查结果保存在节点上（status、latency_ms、detail、checked_at），数据库深检另存 `db_detail`/`db_checked_at`；同时每次检查写入 `cluster_node_checks` 作为 30 天时序历史，供 SLO、趋势与异常检测使用。

### 5.1 SLO 与错误预算

- 每个集群配置 `slo_target`（默认 99.9%）与 `slo_window_hours`（默认 720 小时）。
- 窗口可用率 = 窗口内成功检查数 / 总检查数；错误预算允许失败率 = `1 - sloTarget/100`。
- 错误预算剩余 = `(1 - 失败率/允许失败率) × 100`，燃烧率 = `失败率/允许失败率`，预计耗尽时间按剩余预算与当前燃烧率估算。
- 多窗口燃烧率使用 1h / 6h / 24h / 3d，阈值参考 Google SRE Workbook 的 multiwindow multi-burn-rate 实践：1h 14.4x、6h 6x、24h 3x、3d 1x。
- 研究依据：SLO/error budget 已成为 AIOps 与 SRE 的通用治理框架，单纯阈值告警无法区分短时抖动与持续预算消耗；多窗口燃烧率能降低误报并给出可执行的预算结论。

### 5.2 趋势与异常检测

- 每个节点保存最近 40 次检查结果用于迷你趋势图；连续失败次数单独展示。
- 延迟基线使用成功检查的中位数与 MAD（Median Absolute Deviation），异常分数采用 modified z-score：`0.6745 × (x - median) / MAD`。
- `|z| ≥ 3.5`，或当前延迟超过基线两倍且多 200ms 时标记「延迟异常」；样本少于 3 条不判定异常，避免冷启动误报。
- 研究依据：Iglewicz 与 Hoaglin 的 modified z-score 对离群值稳健，NIST 工程统计手册推荐以 3.5 作为潜在离群点阈值；相比均值/标准差，不会被历史尖峰拉偏。

### 5.3 依赖拓扑与根因排序

- `cluster_node_relations` 保存 `from_node_id → to_node_id` 的 `depends_on` 边：前者依赖后者。
- 影响范围：从被依赖节点出发，沿反向边做传递闭包，得到全部受影响的下游节点；节点表展示「影响 N」。
- 根因评分：失败 +60、延迟异常 +20、每个下游影响 +8、数据库/缓存/存储共享基础依赖 +5；若自身依赖的上游也失败，按每个上游 -15 表示故障传播，最终取前 5 条。
- Agent 通过 `cluster_reliability` 工具读取 `rootCauses`、`impactNodes`、`burnRates` 与异常节点，先解释根因与影响面，再决定后续主机操作。
- 研究依据：TA-RCD、GALA、LATSRCA 等 2025–2026 工作都表明，把服务依赖图作为约束能显著缩小根因候选并减少 LLM 幻觉；本实现采用可解释的规则化图传播，不引入黑盒模型。

### 5.4 调度与保留

- `VA_CLUSTER_CHECK_INTERVAL` 控制定时检查，默认 `10m`，`0/off` 关闭；到点对含节点的集群创建 `check` 任务，已有排队/执行中任务的集群跳过，避免重叠。
- 检查历史与已完成任务保留 30 天；任务清理在定时调度中执行，检查历史在每次写入时清理。
- 手动「检查集群」、Agent `check_cluster` 与定时任务共用同一套检查与历史写入逻辑，结果一致。

## 6. 漏洞扫描与资产归并

- 只有关联 `ssh_host_id` 的节点可扫描，复用 `sshscan` 只读采集；不保存新的目标机凭据。
- 扫描结果通过现有 `ingestComponents` 进入资产与漏洞流水线。
- 扫描成功后自动执行 `UPDATE assets SET cluster_id=?`，把资产归入该集群；通过注册令牌绑定集群的 Agent 上报时同样自动归集。
- Agent 采集的资产可在集群详情中手动关联；解除关联只清空 `cluster_id`，不删除资产。
- 无 SSH 的后端节点仍可做健康检查，但页面会提示「不可扫描」。
- 单节点检查/扫描保留同步接口；整集群执行走异步任务，避免网关超时。

## 7. 权限与审计

| 操作 | 最低角色 |
|---|---|
| 查看项目/集群/节点/资产/任务 | viewer |
| 修改项目/集群信息 | admin |
| 节点 CRUD、检查、扫描、关联资产、数据库只读凭据 | operator |
| 创建/删除项目、创建/删除集群 | admin |
| 注册令牌、吊销 Agent、下发 Agent 命令 | operator |

所有写操作与检查/扫描写审计（`project.*`、`cluster.*`、`cluster.node.*`、`cluster.job.*`、`cluster.assets.*`）；数据库密码只记录「已配置」，不写日志或审计正文。

## 8. 接口

- `GET/POST /api/v1/projects`，`PATCH/DELETE /api/v1/projects/{id}`
- `GET/POST /api/v1/clusters`，`GET/PATCH/DELETE /api/v1/clusters/{id}`
- `POST /api/v1/clusters/{id}/nodes`
- `PATCH/DELETE /api/v1/cluster-nodes/{id}`
- `POST /api/v1/clusters/{id}/check`、`POST /api/v1/cluster-nodes/{id}/check`
- `POST /api/v1/clusters/{id}/scan`、`POST /api/v1/cluster-nodes/{id}/scan`
- `POST /api/v1/clusters/{id}/jobs`、`GET /api/v1/clusters/{id}/jobs`
- `GET /api/v1/cluster-jobs/{id}`、`POST /api/v1/cluster-jobs/{id}/cancel`
- `POST /api/v1/clusters/{id}/assets`、`DELETE /api/v1/clusters/{id}/assets/{assetId}`
- 资产/漏洞/报告接口支持 `clusterId` 过滤

## 9. 迁移与兼容

- 迁移 `0022` 新增 `projects`、`clusters`、`cluster_nodes`，并为 `assets` 增加 `cluster_id`（默认 0）。
- 迁移 `0023` 新增 `cluster_jobs`，保存异步任务进度与逐节点结果。
- 迁移 `0024` 为 `cluster_nodes` 增加数据库深检字段，密码使用 AES-256-GCM 加密。
- 迁移 `0025` 新增 `agents`、`agent_enroll_tokens`、`agent_commands`。
- 既有资产、漏洞、扫描、Agent 流程不受影响；未关联资产的 `cluster_id=0`；旧版全局 Agent 令牌继续可用。
- 删除项目会级联删除集群/节点并清空资产关联，但保留资产与漏洞数据。

## 10. 验收要点

- 创建项目/集群/节点后能检查 HTTP、TCP、SSH 与 SQLite 文件。
- 整集群检查/扫描返回任务 ID，进度逐步增长，完成后逐节点结果正确，可取消。
- 配置 MySQL/PostgreSQL 只读连接后能返回版本、连接数与容量；未配置时仍走 TCP。
- 关联 SSH 的节点扫描后资产自动归入集群，集群详情统计正确。
- 运维不能创建/删除项目或集群；只读角色不能修改任何节点或数据库凭据。
- 删除项目/集群后资产仍保留且 `cluster_id=0`。
- 注册令牌只能使用一次，Agent 心跳后在线，吊销后心跳返回 401。

## 11. 异步任务设计

- 任务表 `cluster_jobs`：`id`、`cluster_id`、`kind(check|scan)`、`status`、`total/done/failed`、`items(JSON)`、`created_by`、时间戳。
- 创建任务后立即返回，后台 goroutine 以最多 3 个并发执行节点；每完成一个节点更新 `done` 与 `items`。
- 状态收敛：全部成功 `succeeded`；部分失败 `partial`；全部失败 `failed`；取消/重启中断 `canceled`。
- 取消通过进程内 `context.CancelFunc` 传播；服务重启时启动阶段把未完成任务批量标记中断。
- 前端每 1.5 秒轮询任务详情，完成后刷新集群统计并提示结果。

## 12. 数据库深度检查

- 节点新增 `db_engine`、`db_name`、`db_user`、`db_secret`、`db_ssl_mode`、`db_detail`、`db_checked_at`。
- 仅当 `db_engine` 非空时启用；密码与 SSH 凭据共用 AES-256-GCM 密钥，接口只返回 `hasDbSecret`。
- MySQL 查询 `VERSION()`、`Threads_connected`、`max_connections`、`Uptime` 与 `information_schema.tables` 容量；PostgreSQL 查询 `server_version`、`pg_stat_activity`、`max_connections`、`pg_database_size` 与启动时长。
- 连接超时 6 秒、整体 8 秒；错误信息会剔除口令并截断。
- 建议使用独立只读账号并限制来源地址；控制面不代理业务 SQL。

## 13. 多 Agent 身份

- 一次性注册令牌绑定项目/集群，默认 60 分钟有效；Agent 首次注册换取 `Agent ID + secret`，本机保存 `agent.identity.json`（0600）。
- Agent 请求使用 `X-Agent-Id` + `X-Agent-Secret`；服务端只保存 secret 的 SHA-256 摘要，吊销后所有接口立即拒绝。
- 心跳每 15 秒一次，3 分钟内视为在线；控制台可下发 `ping`/`collect`，Agent 拉取后回传结果。
- 绑定集群的 Agent 上报资产时自动写入 `cluster_id`。
- 主机作业签名密钥按身份派生：旧版使用全局令牌，单机身份使用 `sha256("vulnagent-job:"+secret)`，防止跨 Agent 伪造作业。
