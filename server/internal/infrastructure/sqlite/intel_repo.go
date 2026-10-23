package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

// IntelRepo 漏洞情报的 SQLite 仓储
type IntelRepo struct {
	db *sql.DB
}

// NewIntelRepo 构造情报仓储
func NewIntelRepo(db *sql.DB) *IntelRepo { return &IntelRepo{db: db} }

var _ ports.IntelRepository = (*IntelRepo)(nil)

// CVEMeta 返回全部 CVE 的评分元数据
func (r *IntelRepo) CVEMeta(ctx context.Context) (map[string]ports.CVEMeta, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT cve_id, cvss_score, epss, exploit_state, fixed_version FROM cves`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	meta := make(map[string]ports.CVEMeta)
	for rows.Next() {
		var id string
		var m ports.CVEMeta
		if err := rows.Scan(&id, &m.Score, &m.EPSS, &m.Exploit, &m.Fixed); err != nil {
			return nil, err
		}
		meta[id] = m
	}
	return meta, rows.Err()
}

// AffectedByProduct 返回受影响区间，键为小写产品名
func (r *IntelRepo) AffectedByProduct(ctx context.Context) (map[string][]vuln.AffectedRange, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT cve_id, product, version_start_incl, version_end_excl, fixed_version
		FROM cve_affected`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byProduct := make(map[string][]vuln.AffectedRange)
	for rows.Next() {
		var item vuln.AffectedRange
		if err := rows.Scan(&item.CveID, &item.Product, &item.VersionStartIncl, &item.VersionEndExcl, &item.FixedVersion); err != nil {
			return nil, err
		}
		key := strings.ToLower(item.Product)
		byProduct[key] = append(byProduct[key], item)
	}
	return byProduct, rows.Err()
}

// AffectedFor 返回指定 CVE + 产品的受影响区间
func (r *IntelRepo) AffectedFor(ctx context.Context, cveID, product string) ([]vuln.AffectedRange, bool, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT version_start_incl, version_end_excl
		FROM cve_affected WHERE cve_id = ? AND lower(product) = ?`, cveID, strings.ToLower(product))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []vuln.AffectedRange
	for rows.Next() {
		item := vuln.AffectedRange{CveID: cveID, Product: product}
		if err := rows.Scan(&item.VersionStartIncl, &item.VersionEndExcl); err != nil {
			return nil, false, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, len(out) > 0, nil
}

// ProductMappings 返回组件名到产品名映射，键为 eco|name（小写）
func (r *IntelRepo) ProductMappings(ctx context.Context) (map[string]ports.ProductMapping, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT eco, name, product, confidence, source, updated_at FROM product_map`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]ports.ProductMapping)
	for rows.Next() {
		var m ports.ProductMapping
		if err := rows.Scan(&m.Eco, &m.Name, &m.Product, &m.Confidence, &m.Source, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out[strings.ToLower(m.Eco)+"|"+strings.ToLower(m.Name)] = m
	}
	return out, rows.Err()
}

// UpsertCVE 写入或更新单条漏洞元数据
func (r *IntelRepo) UpsertCVE(ctx context.Context, in ports.CVEInput) error {
	var count int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cves WHERE cve_id = ?`, in.ID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err := r.db.ExecContext(ctx, `INSERT INTO cves(cve_id, title, description, cvss_vector, cvss_score, severity,
			cwe_id, cwe_cn, published_at, updated_at, record_state, official, epss, exploit_state, fixed_version)
			VALUES(?,?,?,?,?,?,?,?,?,?,'published',1,0,'none','')`,
			in.ID, in.Title, in.Description, in.Vector, in.Score, in.Severity,
			in.CWEID, in.CWECN, in.PublishedAt, in.UpdatedAt)
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE cves SET title = ?, description = ?, cvss_vector = ?,
		cvss_score = ?, severity = ?, cwe_id = ?, cwe_cn = ?, published_at = ?, updated_at = ? WHERE cve_id = ?`,
		in.Title, in.Description, in.Vector, in.Score, in.Severity,
		in.CWEID, in.CWECN, in.PublishedAt, in.UpdatedAt, in.ID)
	return err
}

// CVEExists 判断情报库中是否已有该 CVE
func (r *IntelRepo) CVEExists(ctx context.Context, cveID string) (bool, error) {
	var count int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cves WHERE cve_id = ?`, cveID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// AddPOC 幂等写入一条 POC 链接
func (r *IntelRepo) AddPOC(ctx context.Context, cveID, link, insertedAt string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO cve_poc(cve_id, link, inserted_at) VALUES(?,?,?)`,
		cveID, link, insertedAt)
	if err != nil {
		return false, err
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

// UpsertAffected 写入或更新受影响区间
func (r *IntelRepo) UpsertAffected(ctx context.Context, cveID, product, startIncl, endExcl, fixed string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
		VALUES(?,?,?,?,?)
		ON CONFLICT(cve_id, product) DO UPDATE SET
		version_start_incl = excluded.version_start_incl,
		version_end_excl = excluded.version_end_excl,
		fixed_version = excluded.fixed_version`,
		cveID, product, startIncl, endExcl, fixed)
	return err
}

// LatestCVEUpdate 返回最新情报更新时间
func (r *IntelRepo) LatestCVEUpdate(ctx context.Context) (string, error) {
	var latest string
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(updated_at), '') FROM cves`).Scan(&latest)
	return latest, err
}

// LatestPOCUpdate 返回最新 POC 写入时间
func (r *IntelRepo) LatestPOCUpdate(ctx context.Context) (string, error) {
	var latest string
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(inserted_at), '') FROM cve_poc`).Scan(&latest)
	return latest, err
}

// SearchCVEs 按关键词搜索情报
func (r *IntelRepo) SearchCVEs(ctx context.Context, query string, limit int) ([]ports.CVERow, error) {
	like := "%" + query + "%"
	rows, err := r.db.QueryContext(ctx, `SELECT cve_id, title, description, severity, cvss_score, epss,
		exploit_state, cwe_id, cwe_cn, published_at, updated_at, fixed_version
		FROM cves WHERE cve_id LIKE ? OR title LIKE ? OR description LIKE ?
		ORDER BY epss DESC, cvss_score DESC LIMIT ?`, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.CVERow, 0, limit)
	for rows.Next() {
		var c ports.CVERow
		if err := rows.Scan(&c.ID, &c.Title, &c.Description, &c.Severity, &c.Score, &c.EPSS,
			&c.Exploit, &c.CWEID, &c.CWECN, &c.PublishedAt, &c.UpdatedAt, &c.Fixed); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCVE 读取单条情报及受影响区间
func (r *IntelRepo) GetCVE(ctx context.Context, cveID string) (ports.CVERow, []ports.AffectedRow, error) {
	var c ports.CVERow
	err := r.db.QueryRowContext(ctx, `SELECT cve_id, title, description, severity, cvss_score, epss,
		exploit_state, cwe_id, cwe_cn, published_at, updated_at, fixed_version FROM cves WHERE cve_id = ?`, cveID).
		Scan(&c.ID, &c.Title, &c.Description, &c.Severity, &c.Score, &c.EPSS,
			&c.Exploit, &c.CWEID, &c.CWECN, &c.PublishedAt, &c.UpdatedAt, &c.Fixed)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.CVERow{}, nil, ports.ErrNotFound
	}
	if err != nil {
		return ports.CVERow{}, nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT product, version_start_incl, version_end_excl, fixed_version
		FROM cve_affected WHERE cve_id = ? ORDER BY product`, cveID)
	if err != nil {
		return c, nil, err
	}
	defer rows.Close()
	var affected []ports.AffectedRow
	for rows.Next() {
		var a ports.AffectedRow
		if err := rows.Scan(&a.Product, &a.StartIncl, &a.EndExcl, &a.Fixed); err != nil {
			return c, nil, err
		}
		affected = append(affected, a)
	}
	return c, affected, rows.Err()
}

// ProductMapList 按关键词过滤返回映射列表
func (r *IntelRepo) ProductMapList(ctx context.Context, query string, limit int) ([]ports.ProductMapping, error) {
	where := "1=1"
	args := []any{}
	if query != "" {
		like := "%" + strings.ToLower(query) + "%"
		where = "(lower(name) LIKE ? OR lower(product) LIKE ? OR lower(eco) LIKE ?)"
		args = append(args, like, like, like)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `SELECT eco, name, product, confidence, source, updated_at
		FROM product_map WHERE `+where+` ORDER BY eco, name LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.ProductMapping, 0, 32)
	for rows.Next() {
		var m ports.ProductMapping
		if err := rows.Scan(&m.Eco, &m.Name, &m.Product, &m.Confidence, &m.Source, &m.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

// UpsertProductMapping 新增或更新映射
func (r *IntelRepo) UpsertProductMapping(ctx context.Context, m ports.ProductMapping, updatedAt string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO product_map(eco, name, product, confidence, source, updated_at)
		VALUES(?,?,?,?, 'manual', ?)
		ON CONFLICT(eco, name) DO UPDATE SET product = excluded.product,
		confidence = excluded.confidence, source = 'manual', updated_at = excluded.updated_at`,
		m.Eco, m.Name, m.Product, m.Confidence, updatedAt)
	return err
}

// DeleteProductMapping 删除映射
func (r *IntelRepo) DeleteProductMapping(ctx context.Context, eco, name string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM product_map WHERE eco = ? AND name = ?`, eco, name)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ports.ErrNotFound
	}
	return nil
}
