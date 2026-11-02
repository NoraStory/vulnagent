# 多集群与项目运维设计（v1）

日期：2026-11-02
状态：已落地首版

## 1. 背景与目标

控制面、业务后端、数据库与目标资产经常分布在不同主机和网段。VulnAgent 首版是单二进制 + SQLite，无法假设所有组件都在同一台机器上。本设计解决三个问题：

1. 用「项目 → 集群 → 节点」描述真实部署拓扑，而不是只看单台资产。
2. 对后端、数据库、缓存、代理与扫描目标做统一健康检查与容量提示。
3. 对可 SSH 到达的节点复用现有只读采集，把主机资产与漏洞自动归入所属集群。

## 2. 非目标（首版不做）

- 不做多个控制面之间的数据联邦或双向同步；仍是单控制面管理多个集群。
- 不代理数据库查询、不保存数据库账号，只做 TCP/文件级检查，避免扩大凭据面。
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
3. 「检查全部」得到 HTTP/TCP/SSH/文件检查结果与延迟。
4. 「扫描全部」对关联 SSH 的节点执行只读软件清单采集，资产自动写入并设置 `cluster_id`。
5. 集群详情汇总节点健康、关联资产与 P0–P3 未关闭漏洞；已有资产也可手动关联。

## 5. 健康检查策略

| 节点角色/检查方式 | 行为 | 成功条件 |
|---|---|---|
| backend / http | GET 节点 URL 或 `http://host:port/api/v1/healthz` | 2xx–3xx |
| database / tcp | TCP 连接 host:port | 连接成功 |
| database / ssh_file | SSH 执行 `test -f`、`stat`、`df -Pk` | 文件存在且可读 |
| scan_target / ssh | 复用 SSH 连接池执行 `echo` | 认证与命令执行成功 |
| cache/proxy/storage / tcp | TCP 连接 | 连接成功 |

检查结果保存在节点上（status、latency_ms、detail、checked_at），不做时序存储。

## 6. 漏洞扫描与资产归并

- 只有关联 `ssh_host_id` 的节点可扫描，复用 `sshscan` 只读采集；不保存新的目标机凭据。
- 扫描结果通过现有 `ingestComponents` 进入资产与漏洞流水线。
- 扫描成功后自动执行 `UPDATE assets SET cluster_id=?`，把资产归入该集群。
- Agent 采集的资产可在集群详情中手动关联；解除关联只清空 `cluster_id`，不删除资产。
- 无 SSH 的后端节点仍可做健康检查，但页面会提示「不可扫描」。

## 7. 权限与审计

| 操作 | 最低角色 |
|---|---|
| 查看项目/集群/节点/资产 | viewer |
| 修改集群信息、节点 CRUD、检查、扫描、关联资产 | operator |
| 创建/删除项目、创建/删除集群 | admin |

所有写操作与检查/扫描写审计（`project.*`、`cluster.*`、`cluster.node.*`、`cluster.assets.*`），不记录节点凭据（节点不保存凭据）。

## 8. 接口

- `GET/POST /api/v1/projects`，`PATCH/DELETE /api/v1/projects/{id}`
- `GET/POST /api/v1/clusters`，`GET/PATCH/DELETE /api/v1/clusters/{id}`
- `POST /api/v1/clusters/{id}/nodes`
- `PATCH/DELETE /api/v1/cluster-nodes/{id}`
- `POST /api/v1/clusters/{id}/check`、`POST /api/v1/cluster-nodes/{id}/check`
- `POST /api/v1/clusters/{id}/scan`、`POST /api/v1/cluster-nodes/{id}/scan`
- `POST /api/v1/clusters/{id}/assets`、`DELETE /api/v1/clusters/{id}/assets/{assetId}`

## 9. 迁移与兼容

- 迁移 0022 新增 `projects`、`clusters`、`cluster_nodes`，并为 `assets` 增加 `cluster_id`（默认 0）。
- 既有资产、漏洞、扫描、Agent 流程不受影响；未关联资产的 `cluster_id=0`。
- 删除项目会级联删除集群/节点并清空资产关联，但保留资产与漏洞数据。

## 10. 验收要点

- 创建项目/集群/节点后能检查 HTTP、TCP、SSH 与 SQLite 文件。
- 关联 SSH 的节点扫描后资产自动归入集群，集群详情统计正确。
- 运维不能创建/删除项目或集群；只读角色不能修改任何节点。
- 删除项目/集群后资产仍保留且 `cluster_id=0`。
