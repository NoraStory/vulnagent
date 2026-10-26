# ADR 0002：Agent Harness 作为叠加层，提权防护优先

- 状态：已接受
- 日期：2026-10-24

## 背景

需要引入 LLM 助手，但现有扫描管道是确定性、可审计的。直接让模型驱动扫描会引入越权、幻觉与不可复现风险。

## 决策

1. Harness 是叠加层，只通过工具调用既有应用服务，不接管扫描。
2. 工具注册表静态编译，无动态 MCP、无 shell、无任意 SQL/URL。
3. 身份只来自服务端会话；执行前重新鉴权。
4. 读工具走独立 `mode=ro` 数据库连接；写工具必须人工批准。
5. 审批绑定 `session + user + tool + 参数 SHA-256 + TTL`，一次性消费。
6. high 风险工具（同步、状态修改）要求 5 分钟内口令再认证。
7. 模型接入走 OpenAI 兼容协议，Key 只从环境变量读取，未配置即关闭。

## 对标

- MCP 工具注解（readOnly/destructive/idempotent/openWorld）
- OpenHands `confirm_risky`
- LangGraph Human-in-the-loop interrupt
- OWASP LLM08 Excessive Agency / AI Agent Security Cheat Sheet
- CAI / PentestGPT 的防御性工具分层（不采纳 exploit 类能力）

## 后果

- 写操作多一步审批，但可审计、可拒绝、可回放。
- 工具数量受控（v1 上限 16 个），攻击面可控。
- 需要在数据库中新增会话/消息/工具调用表。

## 落地情况（2026-10-24）

- 工具 32 个：只读/诊断、写操作分级，技能文档与主机语义诊断已接入（详见 `docs/architecture/detailed-design.md` 7.5.3）。
- 九道闸门全部实现于 `server/internal/application/harness/service.go`：静态工具表、参数 ≤ 64KB、角色裁剪、20 次/分钟、风险分级、参数指纹、一次性消费 + 10 分钟 TTL、5 分钟口令再认证窗口、每轮 6 步上限。
- 数据表：`agent_sessions`、`agent_messages`、`agent_tool_calls`、`agent_approvals`（`0002_harness.sql`）。
- 模型：`internal/infrastructure/llm/openai`，环境变量 `VA_LLM_BASE_URL` / `VA_LLM_API_KEY` / `VA_LLM_MODEL`。
- 前端：助手页 `/assistant`，SSE 流式渲染消息、工具调用与审批卡。
