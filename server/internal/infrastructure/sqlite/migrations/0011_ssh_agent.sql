-- SSH Agent 自动执行：运行记录与逐步轨迹
CREATE TABLE IF NOT EXISTS ssh_agent_runs (
    id TEXT PRIMARY KEY,
    host_id INTEGER NOT NULL,
    host_name TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    goal TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'safe',
    status TEXT NOT NULL DEFAULT 'running',
    steps INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ssh_agent_runs_started ON ssh_agent_runs(started_at DESC);

CREATE TABLE IF NOT EXISTS ssh_agent_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    thought TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    output TEXT NOT NULL DEFAULT '',
    risk TEXT NOT NULL DEFAULT 'normal',
    approved TEXT NOT NULL DEFAULT '',
    exit_code INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_agent_steps_run ON ssh_agent_steps(run_id, idx);
