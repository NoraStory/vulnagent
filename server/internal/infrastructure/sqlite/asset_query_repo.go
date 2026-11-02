package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"vulnagent/server/internal/application/ports"
)

var _ ports.AssetQueryRepository = (*AssetRepo)(nil)

const assetSelect = `SELECT a.id, a.hostname, a.ip, a.os_family, a.os_version, a.env, a.exposure, a.tier,
	a.owner, a.source, a.agent_status, a.last_seen_at,
	a.asset_type, a.status, a.business_system, a.department, a.owner_email, a.location,
	a.cloud_provider, a.cloud_account, a.region, a.instance_id, a.mac, a.serial,
	a.os_arch, a.kernel, a.virtualized, a.merged_into,
	COALESCE((SELECT group_concat(t.tag, '|') FROM asset_tags t WHERE t.asset_id = a.id), ''),
	(SELECT COUNT(*) FROM components c WHERE c.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.priority = 'P0'),
	COALESCE((SELECT MAX(f.risk) FROM findings f WHERE f.asset_id = a.id), 0)
	FROM assets a`

func scanAssetItem(sc interface{ Scan(...any) error }) (ports.AssetListItem, error) {
	var it ports.AssetListItem
	var tags string
	err := sc.Scan(&it.ID, &it.Hostname, &it.IP, &it.OSFamily, &it.OSVersion, &it.Env, &it.Exposure, &it.Tier,
		&it.Owner, &it.Source, &it.AgentStatus, &it.LastSeen,
		&it.AssetType, &it.Status, &it.BusinessSystem, &it.Department, &it.OwnerEmail, &it.Location,
		&it.CloudProvider, &it.CloudAccount, &it.Region, &it.InstanceID, &it.MAC, &it.Serial,
		&it.OSArch, &it.Kernel, &it.Virtualized, &it.MergedInto, &tags,
		&it.Components, &it.Findings, &it.P0, &it.Risk)
	if tags != "" {
		it.Tags = strings.Split(tags, "|")
	}
	return it, err
}

// List 返回当前页资产与总条数
func (r *AssetRepo) List(ctx context.Context, filter ports.AssetFilter, limit, offset int) ([]ports.AssetListItem, int, error) {
	where, args := assetFilterSQL(filter)
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

func assetFilterSQL(filter ports.AssetFilter) (string, []any) {
	conds := []string{"1=1"}
	args := []any{}
	if !filter.IncludeArchived {
		conds = append(conds, "a.merged_into = 0")
	}
	if filter.ClusterID > 0 {
		conds = append(conds, "a.cluster_id = ?")
		args = append(args, filter.ClusterID)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(a.hostname LIKE ? OR a.owner LIKE ? OR a.ip LIKE ? OR a.business_system LIKE ? OR a.serial LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	for _, item := range []struct {
		column string
		value  string
	}{
		{"a.env", filter.Env},
		{"a.exposure", filter.Exposure},
		{"a.tier", filter.Tier},
		{"a.status", filter.Status},
		{"a.asset_type", filter.AssetType},
		{"a.business_system", filter.BusinessSystem},
		{"a.owner", filter.Owner},
		{"a.cloud_provider", filter.CloudProvider},
	} {
		if v := strings.TrimSpace(item.value); v != "" {
			conds = append(conds, item.column+" = ?")
			args = append(args, v)
		}
	}
	return strings.Join(conds, " AND "), args
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
