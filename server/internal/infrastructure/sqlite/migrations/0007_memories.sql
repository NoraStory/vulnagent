-- 0007 Agent 长期记忆
CREATE TABLE IF NOT EXISTS agent_memories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scope          TEXT NOT NULL DEFAULT 'global',
    scope_key      TEXT NOT NULL DEFAULT '',
    content        TEXT NOT NULL,
    source_session TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_memories_scope ON agent_memories(scope, scope_key, updated_at DESC);
