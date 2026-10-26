-- 0006 主机作业：下行执行通道、重试与结果回传
CREATE TABLE IF NOT EXISTS host_jobs (
    id              TEXT PRIMARY KEY,
    asset_id        INTEGER NOT NULL,
    action          TEXT NOT NULL,
    params          TEXT NOT NULL DEFAULT '{}',
    risk            TEXT NOT NULL DEFAULT 'high',
    status          TEXT NOT NULL DEFAULT 'pending',
    requested_by    TEXT NOT NULL DEFAULT '',
    approval_id     TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL DEFAULT '',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    next_run_at     TEXT NOT NULL DEFAULT '',
    output          TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    exit_code       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT '',
    finished_at     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_host_jobs_asset ON host_jobs(asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_host_jobs_status ON host_jobs(status, next_run_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_jobs_idem ON host_jobs(idempotency_key) WHERE idempotency_key <> '';

CREATE TABLE IF NOT EXISTS host_job_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    attempt    INTEGER NOT NULL,
    status     TEXT NOT NULL,
    output     TEXT NOT NULL DEFAULT '',
    error      TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_host_job_attempts_job ON host_job_attempts(job_id, id);
