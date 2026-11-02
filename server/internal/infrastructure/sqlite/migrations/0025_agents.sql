-- 0025 多 Agent：一次性注册令牌、Agent 身份、心跳与命令通道
CREATE TABLE IF NOT EXISTS agents (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    hostname       TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    os_version     TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL DEFAULT '',
    project_id     INTEGER NOT NULL DEFAULT 0,
    cluster_id     INTEGER NOT NULL DEFAULT 0,
    secret_hash    TEXT NOT NULL,
    enrolled_by    TEXT NOT NULL DEFAULT '',
    enrolled_at    TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL DEFAULT '',
    last_ip        TEXT NOT NULL DEFAULT '',
    revoked_at     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agents_cluster ON agents(cluster_id);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
    id            TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    name_hint     TEXT NOT NULL DEFAULT '',
    project_id    INTEGER NOT NULL DEFAULT 0,
    cluster_id    INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT NOT NULL,
    used_at       TEXT NOT NULL DEFAULT '',
    used_by_agent TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_enroll_tokens_expires ON agent_enroll_tokens(expires_at);

CREATE TABLE IF NOT EXISTS agent_commands (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    params       TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending',
    output       TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    claimed_at   TEXT NOT NULL DEFAULT '',
    finished_at  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON agent_commands(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_commands_status ON agent_commands(agent_id, status);
