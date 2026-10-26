package main

import (
	"database/sql"
	"path/filepath"

	"vulnagent/server/internal/infrastructure/sqlite"
	"vulnagent/server/internal/platform/config"
)

// 仓储按需构造：都只是持有 *sql.DB 的轻量结构体，
// 这样测试中直接构造 &App{db: db} 也能正常工作。
func (a *App) assetRepo() *sqlite.AssetRepo { return sqlite.NewAssetRepo(a.db) }

func (a *App) intelRepo() *sqlite.IntelRepo { return sqlite.NewIntelRepo(a.db) }

func (a *App) findingRepo() *sqlite.FindingRepo { return sqlite.NewFindingRepo(a.db) }

func (a *App) identityRepo() *sqlite.IdentityRepo { return sqlite.NewIdentityRepo(a.db) }

func (a *App) auditRepo() *sqlite.AuditRepo { return sqlite.NewAuditRepo(a.db) }

func (a *App) policyRepo() *sqlite.PolicyRepo { return sqlite.NewPolicyRepo(a.db) }

func (a *App) notifyRepo() *sqlite.NotifyRepo { return sqlite.NewNotifyRepo(a.db) }

func (a *App) syncRepo() *sqlite.SyncRepo { return sqlite.NewSyncRepo(a.db) }

func (a *App) statsRepo() *sqlite.StatsRepo { return sqlite.NewStatsRepo(a.db) }

func (a *App) harnessRepo() *sqlite.HarnessRepo { return sqlite.NewHarnessRepo(a.db) }

func (a *App) ticketRepo() *sqlite.TicketRepo { return sqlite.NewTicketRepo(a.db) }

func (a *App) telemetryRepo() *sqlite.TelemetryRepo { return sqlite.NewTelemetryRepo(a.db) }

func (a *App) jobRepo() *sqlite.JobRepo { return sqlite.NewJobRepo(a.db) }

func (a *App) memoryRepo() *sqlite.MemoryRepo { return sqlite.NewMemoryRepo(a.db) }

// readDB 返回 Harness 读工具专用的只读连接；打开失败时回落到主连接
func (a *App) readDB() *sql.DB {
	a.roOnce.Do(func() {
		a.roDB, a.roErr = sqlite.OpenReadOnly(filepath.Join(a.dataDir, config.DefaultDBFile))
	})
	if a.roErr != nil || a.roDB == nil {
		return a.db
	}
	return a.roDB
}
