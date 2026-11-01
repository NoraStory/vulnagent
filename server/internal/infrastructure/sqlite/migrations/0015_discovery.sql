-- 0015 网段发现：任务进度、取消标记与候选资产
ALTER TABLE discovery_jobs ADD COLUMN scanned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE discovery_jobs ADD COLUMN options TEXT NOT NULL DEFAULT '{}';
ALTER TABLE discovery_jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS discovery_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    open_ports TEXT NOT NULL DEFAULT '',
    services TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '',
    matched_asset_id INTEGER NOT NULL DEFAULT 0,
    decision TEXT NOT NULL DEFAULT 'new',
    confidence REAL NOT NULL DEFAULT 0,
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL DEFAULT '',
    asset_id INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT '',
    UNIQUE(job_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_job ON discovery_candidates(job_id, decision);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_ip ON discovery_candidates(ip);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_status ON discovery_jobs(status, id DESC);
