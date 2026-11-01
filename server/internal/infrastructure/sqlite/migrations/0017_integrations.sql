-- 0017 云厂商与外部 CMDB 集成源
CREATE TABLE IF NOT EXISTS integration_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    secret TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 360,
    last_run_at TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    last_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, name)
);

CREATE INDEX IF NOT EXISTS idx_integration_sources_kind ON integration_sources(kind, enabled);
