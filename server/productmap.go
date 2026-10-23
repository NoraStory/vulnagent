package main

import (
	"database/sql"
	"strings"
)

// productMapping 组件名到漏洞库产品名的映射（用于包名与上游产品名不一致的场景）
type productMapping struct {
	Eco        string  `json:"eco"`
	Name       string  `json:"name"`
	Product    string  `json:"product"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
	UpdatedAt  string  `json:"updatedAt"`
}

// builtinMappings 常见发行版包名 → 上游产品名（可在控制台修改或删除）
var builtinMappings = []productMapping{
	{Eco: "deb", Name: "node-lodash", Product: "lodash", Confidence: 1.0},
	{Eco: "deb", Name: "node-axios", Product: "axios", Confidence: 1.0},
	{Eco: "deb", Name: "node-express", Product: "express", Confidence: 0.9},
	{Eco: "deb", Name: "python3-requests", Product: "requests", Confidence: 1.0},
	{Eco: "deb", Name: "python3-django", Product: "django", Confidence: 1.0},
	{Eco: "deb", Name: "libssl3", Product: "openssl", Confidence: 0.8},
	{Eco: "rpm", Name: "openssl-libs", Product: "openssl", Confidence: 0.8},
}

// ensureProductMap 首次启动写入内置映射，返回新写入条数；用户删除后不会在重启时复活
func ensureProductMap(db *sql.DB) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM product_map`).Scan(&count); err != nil {
		return 0, err
	}
	if count > 0 {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO product_map(eco, name, product, confidence, source, updated_at)
		VALUES(?,?,?,?, 'builtin', ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	now := fmtT(nowT())
	inserted := 0
	for _, m := range builtinMappings {
		res, err := stmt.Exec(m.Eco, strings.ToLower(m.Name), strings.ToLower(m.Product), m.Confidence, now)
		if err != nil {
			return 0, err
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

// rematchAllAssets 映射变更后重新匹配所有资产（只新增/更新结论，不删除历史）
func (a *App) rematchAllAssets() (int, error) {
	return a.scanService(loadPolicy(a.db)).RematchAll("系统")
}
