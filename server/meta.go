package main

import (
	"context"
	"database/sql"

	"vulnagent/server/internal/infrastructure/sqlite"
	"vulnagent/server/internal/platform/config"
)

// seedDemoEnabled 是否灌入演示数据；生产部署设置 VA_SEED_DEMO=off
func seedDemoEnabled() bool { return config.Load().SeedDemo }

// setMeta 写入应用元数据，实现见 sqlite.PolicyRepo
func setMeta(db *sql.DB, key, value string) error {
	return sqlite.NewPolicyRepo(db).SetMeta(context.Background(), key, value, fmtT(nowT()))
}

// getMeta 读取应用元数据，实现见 sqlite.PolicyRepo
func getMeta(db *sql.DB, key string) string {
	return sqlite.NewPolicyRepo(db).Meta(context.Background(), key)
}

// demoMode 当前库是否使用演示数据（由 seedDemo 写入标记）
func (a *App) demoMode() bool {
	return getMeta(a.db, "demo_mode") == "1"
}
