-- 0005 主机遥测：性能时序、硬件清单、服务与监听端口
CREATE TABLE IF NOT EXISTS host_metrics (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      INTEGER NOT NULL,
    ts            TEXT NOT NULL,
    cpu_percent   REAL NOT NULL DEFAULT 0,
    load1         REAL NOT NULL DEFAULT 0,
    load5         REAL NOT NULL DEFAULT 0,
    load15        REAL NOT NULL DEFAULT 0,
    mem_used      INTEGER NOT NULL DEFAULT 0,
    mem_total     INTEGER NOT NULL DEFAULT 0,
    swap_used     INTEGER NOT NULL DEFAULT 0,
    swap_total    INTEGER NOT NULL DEFAULT 0,
    disk_read_bps REAL NOT NULL DEFAULT 0,
    disk_write_bps REAL NOT NULL DEFAULT 0,
    net_rx_bps    REAL NOT NULL DEFAULT 0,
    net_tx_bps    REAL NOT NULL DEFAULT 0,
    uptime_sec    INTEGER NOT NULL DEFAULT 0,
    process_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_host_metrics_asset_ts ON host_metrics(asset_id, ts DESC);

-- 最新一次硬件/服务/端口快照；整体替换，避免逐行 diff
CREATE TABLE IF NOT EXISTS asset_telemetry (
    asset_id      INTEGER PRIMARY KEY,
    collected_at  TEXT NOT NULL,
    metrics_json  TEXT NOT NULL DEFAULT '{}',
    hardware_json TEXT NOT NULL DEFAULT '{}',
    services_json TEXT NOT NULL DEFAULT '[]',
    ports_json    TEXT NOT NULL DEFAULT '[]'
);
