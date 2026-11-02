-- 0023 集群异步检查/扫描任务：避免长请求超时，支持进度与取消
CREATE TABLE IF NOT EXISTS cluster_jobs (
    id          TEXT PRIMARY KEY,
    cluster_id  INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'check',
    status      TEXT NOT NULL DEFAULT 'queued',
    total       INTEGER NOT NULL DEFAULT 0,
    done        INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    message     TEXT NOT NULL DEFAULT '',
    items       TEXT NOT NULL DEFAULT '[]',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cluster_jobs_cluster ON cluster_jobs(cluster_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cluster_jobs_status ON cluster_jobs(status, created_at);
