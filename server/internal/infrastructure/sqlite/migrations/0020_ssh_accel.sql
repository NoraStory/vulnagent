CREATE TABLE IF NOT EXISTS ssh_accel_baselines (
  host_id    INTEGER PRIMARY KEY,
  profile    TEXT NOT NULL,
  metrics    TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
