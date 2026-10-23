package main

import (
	"database/sql"

	"vulnagent/server/internal/infrastructure/sqlite"
	"vulnagent/server/internal/platform/config"
)

// openDB 打开数据库并执行迁移，实现见 internal/infrastructure/sqlite
func openDB(path string) (*sql.DB, error) { return sqlite.Open(path) }

// dataDirFromEnv 数据目录，配置解析见 internal/platform/config
func dataDirFromEnv() string { return config.Load().DataDir }
