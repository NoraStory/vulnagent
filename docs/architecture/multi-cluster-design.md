# 多集群与项目运维设计（v1.2）

日期：2026-11-02
状态：已落地（含异步任务、数据库深检与多 Agent 身份）

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
| Cluster | 项目下的部署单元 | project_id、name、environment、provider、region |
| ClusterNode | 集群中的角色节点 | role、host、port、url、ssh_host_id、check_type、path |
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

检查结果保存在节点上（status、latency_ms、detail、checked_at），数据库深检另存 `db_detail`/`db_checked_at`；不做时序存储。

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
