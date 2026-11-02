CREATE TABLE IF NOT EXISTS projects (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  owner       TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clusters (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL,
  name        TEXT NOT NULL,
  environment TEXT NOT NULL DEFAULT 'prod',
  provider    TEXT NOT NULL DEFAULT '',
  region      TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_clusters_project ON clusters(project_id);

CREATE TABLE IF NOT EXISTS cluster_nodes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_id   INTEGER NOT NULL,
  name         TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'backend',
  host         TEXT NOT NULL DEFAULT '',
  port         INTEGER NOT NULL DEFAULT 0,
  url          TEXT NOT NULL DEFAULT '',
  ssh_host_id  INTEGER NOT NULL DEFAULT 0,
  check_type   TEXT NOT NULL DEFAULT 'auto',
  path         TEXT NOT NULL DEFAULT '',
  note         TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'unknown',
  latency_ms   INTEGER NOT NULL DEFAULT 0,
  detail       TEXT NOT NULL DEFAULT '',
  checked_at   TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cluster_nodes_cluster ON cluster_nodes(cluster_id);

ALTER TABLE assets ADD COLUMN cluster_id INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_assets_cluster ON assets(cluster_id);
