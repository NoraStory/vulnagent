package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/platform/clock"
)

// assetFieldColumns 允许通过 API 更新的资产字段（键为 JSON 字段，值为数据库列名）
var assetFieldColumns = map[string]string{
	"hostname":       "hostname",
	"ip":             "ip",
	"osFamily":       "os_family",
	"osVersion":      "os_version",
	"osArch":         "os_arch",
	"kernel":         "kernel",
	"env":            "env",
	"exposure":       "exposure",
	"tier":           "tier",
	"assetType":      "asset_type",
	"status":         "status",
	"owner":          "owner",
	"ownerEmail":     "owner_email",
	"department":     "department",
	"businessSystem": "business_system",
	"location":       "location",
	"cloudProvider":  "cloud_provider",
	"cloudAccount":   "cloud_account",
	"region":         "region",
	"instanceId":     "instance_id",
	"mac":            "mac",
	"serial":         "serial",
	"virtualized":    "virtualized",
}

// AssetFieldColumns 返回允许更新的字段名，供上层做参数校验
func AssetFieldColumns() map[string]string {
	out := make(map[string]string, len(assetFieldColumns))
	for k, v := range assetFieldColumns {
		out[k] = v
	}
	return out
}

// Identifiers 返回资产全部标识
func (r *AssetRepo) Identifiers(ctx context.Context, assetID int64) ([]ports.AssetIdentifier, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, kind, value, source, created_at
		FROM asset_identifiers WHERE asset_id = ? ORDER BY id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.AssetIdentifier, 0)
	for rows.Next() {
		var item ports.AssetIdentifier
		if err := rows.Scan(&item.ID, &item.AssetID, &item.Kind, &item.Value, &item.Source, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Changes 返回资产最近的变更记录
func (r *AssetRepo) Changes(ctx context.Context, assetID int64, limit int) ([]ports.AssetChange, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, field, old_value, new_value, actor, source, created_at
		FROM asset_changes WHERE asset_id = ? ORDER BY id DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.AssetChange, 0)
	for rows.Next() {
		var item ports.AssetChange
		if err := rows.Scan(&item.ID, &item.AssetID, &item.Field, &item.OldValue, &item.NewValue,
			&item.Actor, &item.Source, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Tags 返回资产标签
func (r *AssetRepo) Tags(ctx context.Context, assetID int64) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tag FROM asset_tags WHERE asset_id = ? ORDER BY tag`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

// SetTags 整体替换资产标签，并记录一条标签变更
func (r *AssetRepo) SetTags(ctx context.Context, assetID int64, tags []string, actor, source string) error {
	old, err := r.Tags(ctx, assetID)
	if err != nil {
		return err
	}
	cleaned := cleanTags(tags)
	if equalStrings(old, cleaned) {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_tags WHERE asset_id = ?`, assetID); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO asset_tags(asset_id, tag) VALUES(?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, tag := range cleaned {
		if _, err := stmt.ExecContext(ctx, assetID, tag); err != nil {
			return err
		}
	}
	if err := insertAssetChange(ctx, tx, assetID, "tags", strings.Join(old, ","), strings.Join(cleaned, ","), actor, source); err != nil {
		return err
	}
	return tx.Commit()
}

func cleanTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || len(tag) > 64 || strings.Contains(tag, "|") || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// UpdateFields 更新资产档案字段并记录逐字段变更，返回实际发生的变更
func (r *AssetRepo) UpdateFields(ctx context.Context, assetID int64, updates map[string]string, actor, source string) ([]ports.AssetChange, error) {
	keys := make([]string, 0, len(updates))
	for key := range updates {
		if _, ok := assetFieldColumns[key]; !ok {
			return nil, fmt.Errorf("不支持的资产字段: %s", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil, nil
	}

	cols := make([]string, 0, len(keys))
	for _, key := range keys {
		cols = append(cols, assetFieldColumns[key])
	}
	selectSQL := "SELECT " + strings.Join(cols, ", ") + " FROM assets WHERE id = ?"
	cur := make([]string, len(cols))
	dest := make([]any, len(cols))
	for i := range cur {
		dest[i] = &cur[i]
	}
	if err := r.db.QueryRowContext(ctx, selectSQL, assetID).Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrNotFound
		}
		return nil, err
	}

	setParts := make([]string, 0, len(keys)+1)
	args := make([]any, 0, len(keys)+2)
	changes := make([]ports.AssetChange, 0, len(keys))
	for i, key := range keys {
		next := strings.TrimSpace(updates[key])
		if next == cur[i] {
			continue
		}
		setParts = append(setParts, assetFieldColumns[key]+" = ?")
		args = append(args, next)
		changes = append(changes, ports.AssetChange{
			AssetID:  assetID,
			Field:    key,
			OldValue: cur[i],
			NewValue: next,
			Actor:    actor,
			Source:   source,
		})
	}
	if len(changes) == 0 {
		return nil, nil
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, nowString(), assetID)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "UPDATE assets SET "+strings.Join(setParts, ", ")+" WHERE id = ?", args...); err != nil {
		return nil, err
	}
	for i := range changes {
		if err := insertAssetChange(ctx, tx, assetID, changes[i].Field, changes[i].OldValue, changes[i].NewValue, actor, source); err != nil {
			return nil, err
		}
		changes[i].CreatedAt = nowString()
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changes, nil
}

func insertAssetChange(ctx context.Context, tx *sql.Tx, assetID int64, field, oldValue, newValue, actor, source string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO asset_changes(asset_id, field, old_value, new_value, actor, source, created_at)
		VALUES(?,?,?,?,?,?,?)`, assetID, field, oldValue, newValue, actor, source, nowString())
	return err
}

// AddIdentifiers 追加资产标识（重复标识自动忽略）
func (r *AssetRepo) AddIdentifiers(ctx context.Context, assetID int64, kind, source string, values []string) error {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO asset_identifiers(asset_id, kind, value, source, created_at)
			VALUES(?,?,?,?,?)`, assetID, kind, value, source, nowString()); err != nil {
			return err
		}
	}
	return nil
}

// FindByIdentity 按标识查找资产，返回资产 ID 与是否存在
func (r *AssetRepo) FindByIdentity(ctx context.Context, kind, value string) (int64, bool, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `SELECT asset_id FROM asset_identifiers WHERE kind = ? AND value = ?`, kind, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// FindByHostname 按主机名查找资产
func (r *AssetRepo) FindByHostname(ctx context.Context, hostname string) (int64, bool, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE hostname = ?`, hostname).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// Create 新建资产档案并写入标签与标识
func (r *AssetRepo) Create(ctx context.Context, fields map[string]string, tags []string, identifiers map[string]string) (int64, error) {
	now := nowString()
	cols := []string{"hostname", "ip", "os_family", "os_version", "os_arch", "kernel", "env", "exposure", "tier",
		"asset_type", "status", "owner", "owner_email", "department", "business_system", "location",
		"cloud_provider", "cloud_account", "region", "instance_id", "mac", "serial", "virtualized",
		"source", "agent_status", "last_seen_at", "created_at", "updated_at"}
	defaults := map[string]string{
		"env": "prod", "exposure": "internal", "tier": "normal", "asset_type": "server", "status": "active",
		"source": "import", "agent_status": "none",
	}
	values := make([]any, 0, len(cols))
	for _, col := range cols {
		value := ""
		for key, mapped := range assetFieldColumns {
			if mapped == col {
				value = fields[key]
				break
			}
		}
		if value == "" {
			value = defaults[col]
		}
		if col == "created_at" || col == "updated_at" {
			value = now
		}
		values = append(values, value)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	res, err := tx.ExecContext(ctx, "INSERT INTO assets("+strings.Join(cols, ", ")+") VALUES("+placeholders+")", values...)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for kind, value := range identifiers {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO asset_identifiers(asset_id, kind, value, source, created_at)
			VALUES(?,?,?,'import',?)`, id, kind, value, now); err != nil {
			return 0, err
		}
	}
	for _, tag := range cleanTags(tags) {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO asset_tags(asset_id, tag) VALUES(?, ?)`, id, tag); err != nil {
			return 0, err
		}
	}
	if err := insertAssetChange(ctx, tx, id, "created", "", "导入创建资产", "import", "import"); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// MergeStats 资产合并搬运的条目计数
type MergeStats struct {
	Components  int `json:"components"`
	Findings    int `json:"findings"`
	Tickets     int `json:"tickets"`
	Identifiers int `json:"identifiers"`
	Tags        int `json:"tags"`
	Relations   int `json:"relations"`
}

// Merge 把 source 资产的组件、漏洞、工单、标识、标签与关系搬运到 target，
// 并把 source 标记为已合并（保留记录，不物理删除）。
func (r *AssetRepo) Merge(ctx context.Context, sourceID, targetID int64, actor string) (MergeStats, error) {
	var stats MergeStats
	if sourceID == targetID {
		return stats, fmt.Errorf("不能把资产合并到自身")
	}
	var sourceHost, targetHost string
	if err := r.db.QueryRowContext(ctx, `SELECT hostname FROM assets WHERE id = ?`, sourceID).Scan(&sourceHost); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return stats, ports.ErrNotFound
		}
		return stats, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT hostname FROM assets WHERE id = ?`, targetID).Scan(&targetHost); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return stats, ports.ErrNotFound
		}
		return stats, err
	}

	now := nowString()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, err
	}
	defer func() { _ = tx.Rollback() }()

	count := func(sqlText string, args ...any) (int, error) {
		res, err := tx.ExecContext(ctx, sqlText, args...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}

	if stats.Components, err = count(`INSERT INTO components(asset_id, purl, eco, name, version, vendor, product, inferred)
		SELECT ?, purl, eco, name, version, vendor, product, inferred FROM components WHERE asset_id = ?
		ON CONFLICT(asset_id, purl) DO UPDATE SET eco = excluded.eco, name = excluded.name,
		version = excluded.version, vendor = excluded.vendor, product = excluded.product, inferred = excluded.inferred`,
		targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM components WHERE asset_id = ?`, sourceID); err != nil {
		return stats, err
	}

	if stats.Findings, err = count(`INSERT OR IGNORE INTO findings(asset_id, purl, component_name, component_version, eco,
		cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, status, inferred,
		fixed_version, assignee, ticket_id, first_seen, last_seen)
		SELECT ?, purl, component_name, component_version, eco, cve_id, cvss, epss, exploit, asset_weight,
		risk, priority, score_breakdown, status, inferred, fixed_version, assignee, ticket_id, first_seen, last_seen
		FROM findings WHERE asset_id = ?`, targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE asset_id = ?`, sourceID); err != nil {
		return stats, err
	}

	if stats.Tickets, err = count(`UPDATE tickets SET asset_id = ?, updated_at = ? WHERE asset_id = ?`, targetID, now, sourceID); err != nil {
		return stats, err
	}

	if stats.Identifiers, err = count(`UPDATE OR IGNORE asset_identifiers SET asset_id = ? WHERE asset_id = ?`, targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_identifiers WHERE asset_id = ?`, sourceID); err != nil {
		return stats, err
	}

	if stats.Tags, err = count(`INSERT OR IGNORE INTO asset_tags(asset_id, tag) SELECT ?, tag FROM asset_tags WHERE asset_id = ?`,
		targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_tags WHERE asset_id = ?`, sourceID); err != nil {
		return stats, err
	}

	if stats.Relations, err = count(`UPDATE OR IGNORE asset_relations SET from_asset_id = ? WHERE from_asset_id = ?`,
		targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE OR IGNORE asset_relations SET to_asset_id = ? WHERE to_asset_id = ?`,
		targetID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_relations WHERE from_asset_id = ? OR to_asset_id = ?`, sourceID, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_relations WHERE from_asset_id = to_asset_id`); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO asset_relations(from_asset_id, to_asset_id, relation, created_at)
		VALUES(?,?, 'merged_into', ?)`, sourceID, targetID, now); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE discovery_results SET asset_id = ? WHERE asset_id = ?`, targetID, sourceID); err != nil {
		return stats, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE assets SET status = 'merged', merged_into = ?, updated_at = ? WHERE id = ?`,
		targetID, now, sourceID); err != nil {
		return stats, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET updated_at = ? WHERE id = ?`, now, targetID); err != nil {
		return stats, err
	}
	if err := insertAssetChange(ctx, tx, sourceID, "merged_into", "", targetHost, actor, "merge"); err != nil {
		return stats, err
	}
	if err := insertAssetChange(ctx, tx, targetID, "merged_from", "", sourceHost, actor, "merge"); err != nil {
		return stats, err
	}

	if err := tx.Commit(); err != nil {
		return stats, err
	}
	return stats, nil
}

// nowString 返回统一格式的当前时间
func nowString() string {
	return clock.FormatNow()
}
