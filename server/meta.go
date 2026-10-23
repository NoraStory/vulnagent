package main

import (
	"database/sql"

	"vulnagent/server/internal/platform/config"
)

// seedDemoEnabled 是否灌入演示数据；生产部署设置 VA_SEED_DEMO=off
func seedDemoEnabled() bool { return config.Load().SeedDemo }

func setMeta(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO app_meta(key, value, updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, fmtT(nowT()))
	return err
}

func getMeta(db *sql.DB, key string) string {
	var value string
	if err := db.QueryRow(`SELECT value FROM app_meta WHERE key = ?`, key).Scan(&value); err != nil {
		return ""
	}
	return value
}

// demoMode 当前库是否使用演示数据（由 seedDemo 写入标记）
func (a *App) demoMode() bool {
	return getMeta(a.db, "demo_mode") == "1"
}
