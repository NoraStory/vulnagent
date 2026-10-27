-- 会话协同：一次性分享链接（只读或可写），带过期时间
CREATE TABLE IF NOT EXISTS ssh_share_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    host_name TEXT NOT NULL DEFAULT '',
    permission TEXT NOT NULL DEFAULT 'read',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_share_links_session ON ssh_share_links(session_id, expires_at);
