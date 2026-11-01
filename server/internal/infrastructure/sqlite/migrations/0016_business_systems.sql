-- 0016 业务系统重要性与资产治理
CREATE TABLE IF NOT EXISTS business_systems (
    name TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'normal',
    owner TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO business_systems(name, tier, owner, description, updated_at)
    SELECT DISTINCT business_system, 'normal', '', '自资产档案导入', ''
    FROM assets WHERE TRIM(business_system) <> '';

CREATE INDEX IF NOT EXISTS idx_asset_changes_field ON asset_changes(field, created_at);
