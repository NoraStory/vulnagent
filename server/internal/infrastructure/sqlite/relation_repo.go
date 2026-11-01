package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// Relations 返回资产的全部关系（出入方向以该资产为视角）
func (r *AssetRepo) Relations(ctx context.Context, assetID int64) ([]ports.AssetRelation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT r.id, r.from_asset_id, r.to_asset_id, r.relation, r.created_at,
		a.id, a.hostname, a.ip, a.business_system, a.env, a.asset_type,
		COALESCE((SELECT MAX(f.risk) FROM findings f WHERE f.asset_id = a.id), 0)
		FROM asset_relations r
		JOIN assets a ON a.id = CASE WHEN r.from_asset_id = ? THEN r.to_asset_id ELSE r.from_asset_id END
		WHERE r.from_asset_id = ? OR r.to_asset_id = ?
		ORDER BY r.id DESC`, assetID, assetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.AssetRelation, 0)
	for rows.Next() {
		var item ports.AssetRelation
		item.Direction = "out"
		if err := rows.Scan(&item.ID, &item.FromAssetID, &item.ToAssetID, &item.Relation, &item.CreatedAt,
			&item.Asset.ID, &item.Asset.Hostname, &item.Asset.IP, &item.Asset.BusinessSystem,
			&item.Asset.Env, &item.Asset.AssetType, &item.Asset.Risk); err != nil {
			return nil, err
		}
		if item.FromAssetID != assetID {
			item.Direction = "in"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// CreateRelation 幂等创建资产关系
func (r *AssetRepo) CreateRelation(ctx context.Context, from, to int64, relation, now string) (int64, error) {
	if _, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO asset_relations(from_asset_id, to_asset_id, relation, created_at)
		VALUES(?,?,?,?)`, from, to, relation, now); err != nil {
		return 0, err
	}
	var id int64
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM asset_relations
		WHERE from_asset_id = ? AND to_asset_id = ? AND relation = ?`, from, to, relation).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// DeleteRelation 删除一条关系
func (r *AssetRepo) DeleteRelation(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM asset_relations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// RelationEdges 返回拓扑使用的全部关系边（不含合并关系）
func (r *AssetRepo) RelationEdges(ctx context.Context) ([]ports.TopologyEdge, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, from_asset_id, to_asset_id, relation FROM asset_relations
		WHERE relation <> 'merged_into' ORDER BY id DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.TopologyEdge, 0)
	for rows.Next() {
		var edge ports.TopologyEdge
		if err := rows.Scan(&edge.ID, &edge.FromAssetID, &edge.ToAssetID, &edge.Relation); err != nil {
			return nil, err
		}
		out = append(out, edge)
	}
	return out, rows.Err()
}

// HasAsset 判断资产是否存在
func (r *AssetRepo) HasAsset(ctx context.Context, id int64) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE id = ?`, id).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return count > 0, err
}
