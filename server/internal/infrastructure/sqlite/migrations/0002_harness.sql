-- 0002 Agent Harness：会话、消息、工具调用与审批
CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    role TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_owner ON agent_sessions(owner, updated_at DESC);

CREATE TABLE IF NOT EXISTS agent_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_calls TEXT NOT NULL DEFAULT '[]',
    tool_call_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_messages_session ON agent_messages(session_id, id);

CREATE TABLE IF NOT EXISTS agent_tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    args_hash TEXT NOT NULL,
    risk TEXT NOT NULL DEFAULT 'low',
    status TEXT NOT NULL DEFAULT 'running',
    result TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    approver TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_tool_calls_session ON agent_tool_calls(session_id, id);

CREATE TABLE IF NOT EXISTS agent_approvals (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    call_id TEXT NOT NULL DEFAULT '',
    risk TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT '',
    consumed_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_approvals_session ON agent_approvals(session_id, status);
