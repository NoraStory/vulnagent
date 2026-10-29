-- 0014 资产 CMDB：扩展资产档案字段、标识、标签、关系、变更历史与发现任务
ALTER TABLE assets ADD COLUMN asset_type TEXT NOT NULL DEFAULT 'server';
ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE assets ADD COLUMN business_system TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN department TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN owner_email TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN location TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN cloud_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN cloud_account TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN region TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN instance_id TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN mac TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN serial TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN os_arch TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN kernel TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN virtualized TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN merged_into INTEGER NOT NULL DEFAULT 0;
ALTER TABLE assets ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS asset_identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY(asset_id, tag)
);

CREATE TABLE IF NOT EXISTS asset_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_asset_id INTEGER NOT NULL,
    to_asset_id INTEGER NOT NULL,
    relation TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT '',
    UNIQUE(from_asset_id, to_asset_id, relation)
);

CREATE TABLE IF NOT EXISTS asset_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT NOT NULL DEFAULT '',
    new_value TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    cidrs TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    total INTEGER NOT NULL DEFAULT 0,
    found INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS discovery_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    hostname TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    banner TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'candidate',
    asset_id INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT '',
    UNIQUE(job_id, ip, port)
);

CREATE INDEX IF NOT EXISTS idx_assets_business ON assets(business_system);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_cloud ON assets(cloud_provider, instance_id);
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_asset ON asset_identifiers(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags(tag);
CREATE INDEX IF NOT EXISTS idx_asset_relations_from ON asset_relations(from_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_relations_to ON asset_relations(to_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_changes_asset ON asset_changes(asset_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_discovery_results_job ON discovery_results(job_id);

INSERT OR IGNORE INTO asset_identifiers(asset_id, kind, value, source, created_at)
    SELECT id, 'hostname', hostname, 'autodiscover', '' FROM assets WHERE TRIM(hostname) <> '';

INSERT OR IGNORE INTO asset_identifiers(asset_id, kind, value, source, created_at)
    SELECT id, 'ip', ip, 'autodiscover', '' FROM assets WHERE TRIM(ip) <> '';

UPDATE assets SET updated_at = last_seen_at WHERE updated_at = '';
