package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/asset"
)

// AssetRepo 资产与软件成分的 SQLite 仓储
type AssetRepo struct {
	db *sql.DB
}

// NewAssetRepo 构造资产仓储
func NewAssetRepo(db *sql.DB) *AssetRepo { return &AssetRepo{db: db} }

var _ ports.AssetRepository = (*AssetRepo)(nil)

// Get 按 ID 读取资产
func (r *AssetRepo) Get(ctx context.Context, id int64) (asset.Asset, error) {
	var a asset.Asset
	var exposure, tier string
	err := r.db.QueryRowContext(ctx, `SELECT id, hostname, ip, os_family, os_version, env,
		exposure, tier, owner, source, agent_status, last_seen_at FROM assets WHERE id = ?`, id).
		Scan(&a.ID, &a.Hostname, &a.IP, &a.OSFamily, &a.OSVersion, &a.Env,
			&exposure, &tier, &a.Owner, &a.Source, &a.AgentStatus, &a.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return asset.Asset{}, ports.ErrNotFound
	}
	if err != nil {
		return asset.Asset{}, err
	}
	a.Exposure = asset.Exposure(exposure)
	a.Tier = asset.Tier(tier)
	return a, nil
}

// IDs 返回全部资产 ID
func (r *AssetRepo) IDs(ctx context.Context) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM assets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Components 返回资产当前软件成分快照
func (r *AssetRepo) Components(ctx context.Context, assetID int64) ([]asset.Component, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, purl, eco, name, version, vendor, product, inferred
		FROM components WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []asset.Component
	for rows.Next() {
		var c asset.Component
		var inferred int
		if err := rows.Scan(&c.ID, &c.AssetID, &c.PURL, &c.Eco, &c.Name, &c.Version, &c.Vendor, &c.Product, &inferred); err != nil {
			return nil, err
		}
		c.Inferred = inferred != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertReported 按主机名写入或刷新资产，返回资产 ID
func (r *AssetRepo) UpsertReported(ctx context.Context, hostname, ip, osFamily, osVersion, source, agentStatus, seenAt string) (int64, error) {
	_, err := r.db.ExecContext(ctx, `INSERT INTO assets(hostname, ip, os_family, os_version, env, exposure, tier, owner,
		source, agent_status, last_seen_at) VALUES(?,?,?,?, 'prod', 'internal', 'normal', '', ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET ip = excluded.ip, os_family = excluded.os_family,
		os_version = excluded.os_version,
		source = CASE WHEN assets.source = 'agent' THEN 'agent' ELSE excluded.source END,
		agent_status = CASE WHEN excluded.agent_status = 'online' THEN 'online' ELSE assets.agent_status END,
		last_seen_at = excluded.last_seen_at`,
		hostname, ip, osFamily, osVersion, source, agentStatus, seenAt)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE hostname = ?`, hostname).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ReplaceComponents 整体替换资产组件快照
func (r *AssetRepo) ReplaceComponents(ctx context.Context, assetID int64, components []asset.Component) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM components WHERE asset_id = ?`, assetID); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO components(asset_id, purl, eco, name, version, vendor, product, inferred)
		VALUES(?,?,?,?,?,?,?,0)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, c := range components {
		if _, err := stmt.ExecContext(ctx, assetID, c.PURL, c.Eco, c.Name, c.Version, c.Vendor, c.Product); err != nil {
			return err
		}
	}
	return tx.Commit()
}
