package main

import (
	"vulnagent/server/internal/application/scan"
	"vulnagent/server/internal/domain/vuln"
)

// AffectedRange 兼容别名，领域实现见 internal/domain/vuln
type AffectedRange = vuln.AffectedRange

// scanService 构造扫描编排器，策略在此加载后向下传递
func (a *App) scanService(policy RiskPolicy) *scan.Service {
	return &scan.Service{
		Assets:   a.assetRepo(),
		Intel:    a.intelRepo(),
		Findings: a.findingRepo(),
		Policy:   policy,
		Publish:  a.dispatch,
	}
}

// matchAssetFindings 对单个资产执行一次匹配，返回新增与更新的漏洞条数。
func (a *App) matchAssetFindings(policy RiskPolicy, assetID int64) (int, int, error) {
	res, err := a.scanService(policy).MatchAsset(assetID)
	return res.Created, res.Updated, err
}
