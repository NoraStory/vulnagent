package main

import "vulnagent/server/internal/infrastructure/sqlite"

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
