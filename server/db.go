package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openDB 打开 SQLite 并初始化表结构，首次启动时自动建表
func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)",
		filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 纯 Go 驱动单连接即可满足演示规模，同时避免写冲突
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	for _, stmt := range schemaStatements {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("建表失败: %w", err)
		}
	}
	return db, nil
}

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		pwd_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0,
		last_login TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL UNIQUE,
		ip TEXT NOT NULL DEFAULT '',
		os_family TEXT NOT NULL DEFAULT '',
		os_version TEXT NOT NULL DEFAULT '',
		env TEXT NOT NULL DEFAULT '',
		exposure TEXT NOT NULL DEFAULT 'internal',
		tier TEXT NOT NULL DEFAULT 'normal',
		owner TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT 'agent',
		agent_status TEXT NOT NULL DEFAULT 'none',
		last_seen_at TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS components (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL,
		purl TEXT NOT NULL,
		eco TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		vendor TEXT NOT NULL DEFAULT '',
		product TEXT NOT NULL DEFAULT '',
		inferred INTEGER NOT NULL DEFAULT 0,
		UNIQUE(asset_id, purl)
	)`,
	`CREATE TABLE IF NOT EXISTS cves (
		cve_id TEXT PRIMARY KEY,
		title TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT '',
		cvss_vector TEXT NOT NULL DEFAULT '',
		cvss_score REAL NOT NULL DEFAULT 0,
		severity TEXT NOT NULL DEFAULT 'medium',
		cwe_id INTEGER NOT NULL DEFAULT 0,
		cwe_cn TEXT NOT NULL DEFAULT '',
		published_at TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT '',
		record_state TEXT NOT NULL DEFAULT 'published',
		official INTEGER NOT NULL DEFAULT 1,
		epss REAL NOT NULL DEFAULT 0,
		exploit_state TEXT NOT NULL DEFAULT 'none',
		fixed_version TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS cve_poc (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT NOT NULL,
		link TEXT NOT NULL,
		inserted_at TEXT NOT NULL DEFAULT '',
		UNIQUE(cve_id, link)
	)`,
	`CREATE TABLE IF NOT EXISTS cve_affected (
		cve_id TEXT NOT NULL,
		product TEXT NOT NULL,
		version_start_incl TEXT NOT NULL DEFAULT '',
		version_end_excl TEXT NOT NULL DEFAULT '',
		fixed_version TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (cve_id, product)
	)`,
	`CREATE TABLE IF NOT EXISTS product_map (
		eco TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL,
		product TEXT NOT NULL,
		confidence REAL NOT NULL DEFAULT 1.0,
		source TEXT NOT NULL DEFAULT 'manual',
		updated_at TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (eco, name)
	)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL,
		purl TEXT NOT NULL,
		component_name TEXT NOT NULL,
		component_version TEXT NOT NULL,
		eco TEXT NOT NULL DEFAULT '',
		cve_id TEXT NOT NULL,
		cvss REAL NOT NULL DEFAULT 0,
		epss REAL NOT NULL DEFAULT 0,
		exploit TEXT NOT NULL DEFAULT 'none',
		asset_weight REAL NOT NULL DEFAULT 0,
		risk INTEGER NOT NULL DEFAULT 0,
		priority TEXT NOT NULL DEFAULT 'P3',
		score_breakdown TEXT NOT NULL DEFAULT '[]',
		status TEXT NOT NULL DEFAULT 'open',
		inferred INTEGER NOT NULL DEFAULT 0,
		fixed_version TEXT NOT NULL DEFAULT '',
		assignee TEXT NOT NULL DEFAULT '',
		ticket_id TEXT NOT NULL DEFAULT '',
		first_seen TEXT NOT NULL DEFAULT '',
		last_seen TEXT NOT NULL DEFAULT '',
		UNIQUE(asset_id, purl, cve_id)
	)`,
	`CREATE TABLE IF NOT EXISTS finding_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		finding_id INTEGER NOT NULL,
		event TEXT NOT NULL,
		actor TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		actor TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		target TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		ua TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS sync_cursors (
		source TEXT PRIMARY KEY,
		last_run_at TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'ok',
		count INTEGER NOT NULL DEFAULT 0,
		error TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS risk_policy (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		weights TEXT NOT NULL,
		thresholds TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS selfcheck_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id TEXT NOT NULL UNIQUE,
		started_at TEXT NOT NULL,
		finished_at TEXT NOT NULL,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL,
		triggered_by TEXT NOT NULL DEFAULT '',
		passed INTEGER NOT NULL DEFAULT 0,
		warnings INTEGER NOT NULL DEFAULT 0,
		failed INTEGER NOT NULL DEFAULT 0,
		checks TEXT NOT NULL DEFAULT '[]'
	)`,
	`CREATE TABLE IF NOT EXISTS latency_probe (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS agent_tokens (
		token_hash TEXT PRIMARY KEY,
		created_at TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS app_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS notify_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		webhook_url TEXT NOT NULL DEFAULT '',
		secret TEXT NOT NULL DEFAULT '',
		events TEXT NOT NULL DEFAULT '[]',
		last_event TEXT NOT NULL DEFAULT '',
		last_status TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		last_sent_at TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT ''
	)`,
	`INSERT OR IGNORE INTO notify_settings(id, webhook_url, secret, events, updated_at)
		VALUES(1, '', '', '["finding.new","sync.failed","ticket.created","selfcheck.failed"]', '')`,
	`CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id)`,
	`CREATE INDEX IF NOT EXISTS idx_components_asset ON components(asset_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id)`,
	`CREATE INDEX IF NOT EXISTS idx_poc_cve ON cve_poc(cve_id)`,
	`CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected(product)`,
	`CREATE INDEX IF NOT EXISTS idx_product_map_product ON product_map(product)`,
}

// defaultDataDir 数据目录，可通过 VA_DATA_DIR 覆盖
const defaultDataDir = `e:\桌面管理\安全漏洞Agent\data`

func dataDirFromEnv() string {
	if v := os.Getenv("VA_DATA_DIR"); v != "" {
		return v
	}
	return defaultDataDir
}
