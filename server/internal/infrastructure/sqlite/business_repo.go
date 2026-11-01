package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"vulnagent/server/internal/application/ports"
)

// BusinessRepo 业务系统重要性的 SQLite 仓储
type BusinessRepo struct {
	db *sql.DB
}

// NewBusinessRepo 构造业务系统仓储
func NewBusinessRepo(db *sql.DB) *BusinessRepo { return &BusinessRepo{db: db} }

// List 返回业务系统列表；资产档案中存在但未登记的业务系统按一般业务补齐
func (r *BusinessRepo) List(ctx context.Context) ([]ports.BusinessSystem, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT name, tier, owner, description, updated_at FROM business_systems`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := map[string]ports.BusinessSystem{}
	for rows.Next() {
		var item ports.BusinessSystem
		if err := rows.Scan(&item.Name, &item.Tier, &item.Owner, &item.Description, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items[item.Name] = item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	countRows, err := r.db.QueryContext(ctx, `SELECT business_system, COUNT(*) FROM assets
		WHERE TRIM(business_system) <> '' AND merged_into = 0 GROUP BY business_system`)
	if err != nil {
		return nil, err
	}
	defer countRows.Close()
	counts := map[string]int{}
	for countRows.Next() {
		var name string
		var count int
		if err := countRows.Scan(&name, &count); err != nil {
			return nil, err
		}
		counts[name] = count
		if _, ok := items[name]; !ok {
			items[name] = ports.BusinessSystem{Name: name, Tier: "normal"}
		}
	}
	if err := countRows.Err(); err != nil {
		return nil, err
	}

	out := make([]ports.BusinessSystem, 0, len(items))
	for name, item := range items {
		item.AssetCount = counts[name]
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Upsert 新建或更新业务系统重要性
func (r *BusinessRepo) Upsert(ctx context.Context, item ports.BusinessSystem, updatedAt string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO business_systems(name, tier, owner, description, updated_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET tier = excluded.tier, owner = excluded.owner,
		description = excluded.description, updated_at = excluded.updated_at`,
		item.Name, item.Tier, item.Owner, item.Description, updatedAt)
	return err
}

// Delete 删除业务系统登记；资产上的 business_system 字段保留
func (r *BusinessRepo) Delete(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM business_systems WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// GetTier 返回业务系统重要性，未登记时返回 normal
func (r *BusinessRepo) GetTier(ctx context.Context, name string) (string, error) {
	var tier string
	err := r.db.QueryRowContext(ctx, `SELECT tier FROM business_systems WHERE name = ?`, name).Scan(&tier)
	if errors.Is(err, sql.ErrNoRows) {
		return "normal", nil
	}
	return tier, err
}
