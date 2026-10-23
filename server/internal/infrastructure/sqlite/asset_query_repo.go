package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

var _ ports.AssetQueryRepository = (*AssetRepo)(nil)

const assetSelect = `SELECT a.id, a.hostname, a.ip, a.os_family, a.os_version, a.env, a.exposure, a.tier,
	a.owner, a.source, a.agent_status, a.last_seen_at,
	(SELECT COUNT(*) FROM components c WHERE c.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.priority = 'P0'),
	COALESCE((SELECT MAX(f.risk) FROM findings f WHERE f.asset_id = a.id), 0)
	FROM assets a`

func scanAssetItem(sc interface{ Scan(...any) error }) (ports.AssetListItem, error) {
	var it ports.AssetListItem
	err := sc.Scan(&it.ID, &it.Hostname, &it.IP, &it.OSFamily, &it.OSVersion, &it.Env, &it.Exposure, &it.Tier,
		&it.Owner, &it.Source, &it.AgentStatus, &it.LastSeen,
		&it.Components, &it.Findings, &it.P0, &it.Risk)
	return it, err
}

// List 返回当前页资产与总条数
func (r *AssetRepo) List(ctx context.Context, query string, limit, offset int) ([]ports.AssetListItem, int, error) {
	where := "1=1"
	args := []any{}
	if query != "" {
		like := "%" + query + "%"
		where = "(a.hostname LIKE ? OR a.owner LIKE ? OR a.ip LIKE ?)"
		args = append(args, like, like, like)
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets a WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := r.db.QueryContext(ctx, assetSelect+" WHERE "+where+" ORDER BY a.id ASC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ports.AssetListItem, 0, limit)
	for rows.Next() {
		it, err := scanAssetItem(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, it)
	}
	return items, total, rows.Err()
}

// Detail 按 ID 读取资产汇总
func (r *AssetRepo) Detail(ctx context.Context, id int64) (ports.AssetListItem, error) {
	it, err := scanAssetItem(r.db.QueryRowContext(ctx, assetSelect+" WHERE a.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.AssetListItem{}, ports.ErrNotFound
	}
	return it, err
}

// ComponentRows 返回资产组件清单
func (r *AssetRepo) ComponentRows(ctx context.Context, assetID int64) ([]ports.AssetComponentRow, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT c.purl, c.name, c.version, c.eco, c.vendor, c.product, c.inferred,
		(SELECT COUNT(*) FROM findings f WHERE f.asset_id = c.asset_id AND f.purl = c.purl)
		FROM components c WHERE c.asset_id = ? ORDER BY c.eco ASC, c.name ASC`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.AssetComponentRow, 0)
	for rows.Next() {
		var c ports.AssetComponentRow
		var inferred int
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &c.Eco, &c.Vendor, &c.Product, &inferred, &c.Findings); err != nil {
			return nil, err
		}
		c.Inferred = inferred != 0
		out = append(out, c)
	}
	return out, rows.Err()
}
