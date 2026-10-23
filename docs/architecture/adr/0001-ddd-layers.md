# ADR 0001：采用 DDD 四层结构（渐进式）

- 状态：已接受
- 日期：2026-10-24

## 背景

当前后端为单一 `package main`，30+ 文件、74 个 `App` 方法；handler 内直接写 SQL（102 处），领域逻辑（匹配、状态机、评分）直接依赖 `database/sql` 与 `net/http`，难以测试与替换。

## 决策

采用 `domain / application / infrastructure / interfaces` 四层，按阶段渐进迁移：

1. 先抽纯领域（risk、vuln、version、asset）。
2. 再定义端口并由 SQLite 实现仓储。
3. 然后把用例收敛到 application service，handler 只做 DTO。
4. 最后把 CLI 与 main 变为薄接口。

迁移期允许旧文件保留别名/薄包装，完成后删除。

## 依赖规则

- `domain` 仅依赖标准库。
- `application` 仅依赖 `domain` 与 `application/ports`。
- `infrastructure` 实现端口。
- `interfaces` 依赖 `application`，不得持有 `*sql.DB`。
- `app` 是唯一组装点。

## 后果

- 领域可单测、可替换存储/HTTP。
- 迁移期间代码会短暂重复，需要按阶段清理。
- 现有 HTTP API 与 JSON 保持不变，避免前端同步返工。
