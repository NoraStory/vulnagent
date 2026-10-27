-- SSH 终端面板：加密保存的主机凭据、会话记录与关键事件
CREATE TABLE IF NOT EXISTS ssh_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    auth_type TEXT NOT NULL DEFAULT 'password',
    secret TEXT NOT NULL DEFAULT '',
    passphrase TEXT NOT NULL DEFAULT '',
    host_key TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_connected_at TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_hosts_addr ON ssh_hosts(host, port, username);

CREATE TABLE IF NOT EXISTS ssh_sessions (
    id TEXT PRIMARY KEY,
    host_id INTEGER NOT NULL,
    host_name TEXT NOT NULL,
    addr TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'connecting',
    error TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL DEFAULT '',
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ssh_sessions_started ON ssh_sessions(started_at DESC);

CREATE TABLE IF NOT EXISTS ssh_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'input',
    data TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_events_session ON ssh_events(session_id, id);
