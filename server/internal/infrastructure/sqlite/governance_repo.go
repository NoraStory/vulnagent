package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"vulnagent/server/internal/application/ports"
)

// GovernanceRepo 资产治理待办的查询仓储
type GovernanceRepo struct {
	db *sql.DB
}

// NewGovernanceRepo 构造治理仓储
func NewGovernanceRepo(db *sql.DB) *GovernanceRepo { return &GovernanceRepo{db: db} }

const duplicateGroupsSQL = `SELECT kind, value FROM (
	SELECT 'ip' AS kind, ip AS value FROM assets WHERE TRIM(ip) <> '' AND merged_into = 0 GROUP BY ip HAVING COUNT(*) > 1
	UNION ALL
	SELECT 'serial' AS kind, serial AS value FROM assets WHERE TRIM(serial) <> '' AND merged_into = 0 GROUP BY serial HAVING COUNT(*) > 1
	UNION ALL
	SELECT 'mac' AS kind, mac AS value FROM assets WHERE TRIM(mac) <> '' AND merged_into = 0 GROUP BY mac HAVING COUNT(*) > 1
)`

// Summary 返回四类治理待办的数量
func (r *GovernanceRepo) Summary(ctx context.Context, staleCutoff, changeCutoff string) (ports.GovernanceSummary, error) {
	var out ports.GovernanceSummary
	queries := []struct {
		target *int
		query  string
		args   []any
	}{
		{&out.OwnerMissing, `SELECT COUNT(*) FROM assets WHERE merged_into = 0 AND status = 'active' AND TRIM(owner) = ''`, nil},
		{&out.Stale, `SELECT COUNT(*) FROM assets WHERE merged_into = 0 AND status = 'active' AND source = 'agent'
			AND (last_seen_at = '' OR last_seen_at < ?)`, []any{staleCutoff}},
		{&out.Duplicate, `SELECT COUNT(*) FROM (` + duplicateGroupsSQL + `)`, nil},
		{&out.ExposureChanged, `SELECT COUNT(*) FROM asset_changes WHERE field = 'exposure' AND created_at <> '' AND created_at >= ?`,
			[]any{changeCutoff}},
	}
	for _, item := range queries {
		if err := r.db.QueryRowContext(ctx, item.query, item.args...).Scan(item.target); err != nil {
			return out, err
		}
	}
	return out, nil
}

// List 按类型返回治理待办
func (r *GovernanceRepo) List(ctx context.Context, typ, staleCutoff, changeCutoff string, limit, offset int) ([]ports.GovernanceItem, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	switch typ {
	case "owner_missing":
		return r.listOwnerMissing(ctx, limit, offset)
	case "stale":
		return r.listStale(ctx, staleCutoff, limit, offset)
	case "duplicate":
		return r.listDuplicate(ctx, limit, offset)
	case "exposure_changed":
		return r.listExposureChanged(ctx, changeCutoff, limit, offset)
	default:
		return []ports.GovernanceItem{}, 0, nil
	}
}

func (r *GovernanceRepo) listOwnerMissing(ctx context.Context, limit, offset int) ([]ports.GovernanceItem, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE merged_into = 0 AND status = 'active' AND TRIM(owner) = ''`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, hostname, ip, business_system, owner, status, source, last_seen_at
		FROM assets WHERE merged_into = 0 AND status = 'active' AND TRIM(owner) = '' ORDER BY id DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ports.GovernanceItem, 0, limit)
	for rows.Next() {
		item := ports.GovernanceItem{Type: "owner_missing", Detail: "未设置责任人"}
		if err := rows.Scan(&item.AssetID, &item.Hostname, &item.IP, &item.BusinessSystem, &item.Owner,
			&item.Status, &item.Source, &item.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

func (r *GovernanceRepo) listStale(ctx context.Context, cutoff string, limit, offset int) ([]ports.GovernanceItem, int, error) {
	where := `merged_into = 0 AND status = 'active' AND source = 'agent' AND (last_seen_at = '' OR last_seen_at < ?)`
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE `+where, cutoff).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, hostname, ip, business_system, owner, status, source, last_seen_at
		FROM assets WHERE `+where+` ORDER BY last_seen_at ASC, id ASC LIMIT ? OFFSET ?`, cutoff, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ports.GovernanceItem, 0, limit)
	for rows.Next() {
		item := ports.GovernanceItem{Type: "stale", Detail: "长期未上报"}
		if err := rows.Scan(&item.AssetID, &item.Hostname, &item.IP, &item.BusinessSystem, &item.Owner,
			&item.Status, &item.Source, &item.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

func (r *GovernanceRepo) listExposureChanged(ctx context.Context, cutoff string, limit, offset int) ([]ports.GovernanceItem, int, error) {
	where := `c.field = 'exposure' AND c.created_at <> '' AND c.created_at >= ?`
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_changes c WHERE `+where, cutoff).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT c.asset_id, a.hostname, a.ip, a.business_system, a.owner, a.status,
		a.source, a.last_seen_at, c.old_value, c.new_value, c.created_at
		FROM asset_changes c LEFT JOIN assets a ON a.id = c.asset_id
		WHERE `+where+` ORDER BY c.id DESC LIMIT ? OFFSET ?`, cutoff, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ports.GovernanceItem, 0, limit)
	for rows.Next() {
		item := ports.GovernanceItem{Type: "exposure_changed"}
		var hostname, ip, business, owner, status, source, lastSeen sql.NullString
		if err := rows.Scan(&item.AssetID, &hostname, &ip, &business, &owner, &status, &source, &lastSeen,
			&item.OldValue, &item.NewValue, &item.UpdatedAt); err != nil {
			return nil, 0, err
		}
		item.Hostname, item.IP, item.BusinessSystem = hostname.String, ip.String, business.String
		item.Owner, item.Status, item.Source, item.LastSeen = owner.String, status.String, source.String, lastSeen.String
		item.Detail = fmt.Sprintf("暴露面 %s → %s", item.OldValue, item.NewValue)
		out = append(out, item)
	}
	return out, total, rows.Err()
}

func (r *GovernanceRepo) listDuplicate(ctx context.Context, limit, offset int) ([]ports.GovernanceItem, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+duplicateGroupsSQL+`)`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, duplicateGroupsSQL+` ORDER BY kind, value LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	type group struct{ kind, value string }
	groups := make([]group, 0, limit)
	for rows.Next() {
		var g group
		if err := rows.Scan(&g.kind, &g.value); err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := make([]ports.GovernanceItem, 0, len(groups))
	for _, g := range groups {
		column := map[string]string{"ip": "ip", "serial": "serial", "mac": "mac"}[g.kind]
		memberRows, err := r.db.QueryContext(ctx, `SELECT id, hostname, ip FROM assets
			WHERE merged_into = 0 AND `+column+` = ? ORDER BY id`, g.value)
		if err != nil {
			return nil, 0, err
		}
		members := make([]ports.GovernancePeer, 0, 4)
		for memberRows.Next() {
			var peer ports.GovernancePeer
			if err := memberRows.Scan(&peer.ID, &peer.Hostname, &peer.IP); err != nil {
				memberRows.Close()
				return nil, 0, err
			}
			members = append(members, peer)
		}
		memberRows.Close()
		if len(members) == 0 {
			continue
		}
		label := map[string]string{"ip": "IP", "serial": "序列号", "mac": "MAC"}[g.kind]
		item := ports.GovernanceItem{
			Type:           "duplicate",
			AssetID:        members[0].ID,
			Hostname:       members[0].Hostname,
			IP:             members[0].IP,
			Detail:         fmt.Sprintf("%s %s 关联 %d 台资产", label, g.value, len(members)),
			Related:        members,
			BusinessSystem: "",
		}
		out = append(out, item)
	}
	return out, total, nil
}
