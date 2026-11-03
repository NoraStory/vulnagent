-- 集群可靠性：SLO 配置、节点检查历史与节点依赖关系

ALTER TABLE clusters ADD COLUMN slo_target REAL NOT NULL DEFAULT 99.9;
ALTER TABLE clusters ADD COLUMN slo_window_hours INTEGER NOT NULL DEFAULT 720;

CREATE TABLE IF NOT EXISTS cluster_node_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cluster_node_checks_cluster ON cluster_node_checks(cluster_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_cluster_node_checks_node ON cluster_node_checks(node_id, checked_at);

CREATE TABLE IF NOT EXISTS cluster_node_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER NOT NULL,
    from_node_id INTEGER NOT NULL,
    to_node_id INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'depends_on',
    created_at TEXT NOT NULL,
    UNIQUE(from_node_id, to_node_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_cluster_node_relations_cluster ON cluster_node_relations(cluster_id);
