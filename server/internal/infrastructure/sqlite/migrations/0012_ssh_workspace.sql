-- SSH 工作台：会话录制与快捷命令（脚本库）
CREATE TABLE IF NOT EXISTS ssh_recordings (
    session_id TEXT PRIMARY KEY,
    host_id INTEGER NOT NULL,
    host_name TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    chunks INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ssh_recordings_started ON ssh_recordings(started_at DESC);

CREATE TABLE IF NOT EXISTS ssh_recording_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    offset_ms INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_recording_chunks_session ON ssh_recording_chunks(session_id, seq);

CREATE TABLE IF NOT EXISTS ssh_snippets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    command TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    usage_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ssh_snippets_usage ON ssh_snippets(usage_count DESC, updated_at DESC);
