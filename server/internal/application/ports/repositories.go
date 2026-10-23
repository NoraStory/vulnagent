// Package ports 定义应用层对基础设施的依赖契约。
// 端口只依赖领域模型与标准库，不出现 database/sql、HTTP 等实现细节。
package ports

import (
	"context"
	"errors"

	"vulnagent/server/internal/domain/asset"
	"vulnagent/server/internal/domain/vuln"
)

// ErrNotFound 记录不存在
var ErrNotFound = errors.New("记录不存在")

// CVEMeta 情报元数据，匹配阶段只读取评分相关字段
type CVEMeta struct {
	Score   float64
	EPSS    float64
	Exploit string
	Fixed   string
}

// ProductMapping 组件名到漏洞库产品名的映射
type ProductMapping struct {
	Eco        string
	Name       string
	Product    string
	Confidence float64
	Source     string
	UpdatedAt  string
}

// MatchInput 一次匹配命中的落库输入
type MatchInput struct {
	AssetID      int64
	Component    asset.Component
	CVEID        string
	CVSS         float64
	EPSS         float64
	Exploit      string
	AssetWeight  float64
	Risk         int
	Priority     string
	Breakdown    string
	Inferred     bool
	FixedVersion string
	Now          string
}

// ReconcileRow 复扫收敛需要的最小字段
type ReconcileRow struct {
	ID               int64
	CVEID            string
	Status           string
	FixedVersion     string
	ComponentName    string
	ComponentVersion string
	Eco              string
}

// AssetRepository 资产与软件成分读取端口
type AssetRepository interface {
	// Get 按 ID 读取资产，不存在时返回 ErrNotFound
	Get(ctx context.Context, id int64) (asset.Asset, error)
	// IDs 返回全部资产 ID（按 ID 升序）
	IDs(ctx context.Context) ([]int64, error)
	// Components 返回资产当前软件成分快照
	Components(ctx context.Context, assetID int64) ([]asset.Component, error)
	// UpsertReported 按主机名写入或刷新资产，返回资产 ID
	UpsertReported(ctx context.Context, hostname, ip, osFamily, osVersion, source, agentStatus, seenAt string) (int64, error)
	// ReplaceComponents 整体替换资产组件快照
	ReplaceComponents(ctx context.Context, assetID int64, components []asset.Component) error
}

// CVEInput 写入情报库的一条漏洞元数据
type CVEInput struct {
	ID          string
	Title       string
	Description string
	Vector      string
	Score       float64
	Severity    string
	CWEID       int
	CWECN       string
	PublishedAt string
	UpdatedAt   string
}

// IntelRepository 漏洞情报读取端口
type IntelRepository interface {
	// CVEMeta 返回全部 CVE 的评分元数据，键为 CVE ID
	CVEMeta(ctx context.Context) (map[string]CVEMeta, error)
	// AffectedByProduct 返回受影响区间，键为小写产品名
	AffectedByProduct(ctx context.Context) (map[string][]vuln.AffectedRange, error)
	// AffectedFor 返回指定 CVE + 产品的受影响区间；found 表示是否存在区间记录
	AffectedFor(ctx context.Context, cveID, product string) ([]vuln.AffectedRange, bool, error)
	// ProductMappings 返回组件名到产品名映射，键为 eco|name（小写）
	ProductMappings(ctx context.Context) (map[string]ProductMapping, error)
	// ProductMapList 按关键词过滤返回映射列表
	ProductMapList(ctx context.Context, query string, limit int) ([]ProductMapping, error)
	// UpsertProductMapping 新增或更新映射
	UpsertProductMapping(ctx context.Context, m ProductMapping, updatedAt string) error
	// DeleteProductMapping 删除映射，不存在时返回 ErrNotFound
	DeleteProductMapping(ctx context.Context, eco, name string) error
	// UpsertCVE 写入或更新单条漏洞元数据
	UpsertCVE(ctx context.Context, in CVEInput) error
	// CVEExists 判断情报库中是否已有该 CVE
	CVEExists(ctx context.Context, cveID string) (bool, error)
	// AddPOC 幂等写入一条 POC 链接，inserted 表示本次是否新增
	AddPOC(ctx context.Context, cveID, link, insertedAt string) (inserted bool, err error)
	// UpsertAffected 写入或更新受影响区间
	UpsertAffected(ctx context.Context, cveID, product, startIncl, endExcl, fixed string) error
	// LatestCVEUpdate 返回最新情报更新时间，空库时返回空串
	LatestCVEUpdate(ctx context.Context) (string, error)
	// LatestPOCUpdate 返回最新 POC 写入时间，空库时返回空串
	LatestPOCUpdate(ctx context.Context) (string, error)
}

// FindingRepository 漏洞记录写入与收敛端口
type FindingRepository interface {
	// UpsertMatch 落库一次匹配命中：已存在则刷新评分字段并保留处置状态，
	// created 表示本次是否新增。
	UpsertMatch(ctx context.Context, in MatchInput) (created bool, err error)
	// ActiveForReconcile 返回仍处于处置流程中的记录
	ActiveForReconcile(ctx context.Context, assetID int64) ([]ReconcileRow, error)
	// MarkStatus 更新状态并追加一条处置事件
	MarkStatus(ctx context.Context, id int64, status, now, event, actor, detail string) error
	// ListForRecompute 返回重算风险分所需的全部记录
	ListForRecompute(ctx context.Context) ([]RecomputeRow, error)
	// BulkUpdateScores 在单个事务内批量刷新评分字段
	BulkUpdateScores(ctx context.Context, updates []ScoreUpdate) error
	// SyncEPSSSnapshot 把 CVE 的最新 EPSS 同步到漏洞快照
	SyncEPSSSnapshot(ctx context.Context) error
	// UpsertOSV 落库一次 OSV 命中：只刷新评分与组件字段，不改 EPSS/在野利用
	UpsertOSV(ctx context.Context, in MatchInput) (created bool, err error)
}
