package main

import "vulnagent/server/internal/domain/risk"

// 兼容别名：Phase 1 保持既有调用点与 JSON 字段不变，Phase 6 移除。
// 领域实现见 internal/domain/risk。
type (
	WeightSet    = risk.Weights
	ThresholdSet = risk.Thresholds
	RiskPolicy   = risk.Policy
	ScoreFactor  = risk.Factor
)

func defaultPolicy() RiskPolicy { return risk.DefaultPolicy() }

func unmarshalPolicy(weightsJSON, thresholdsJSON string) RiskPolicy {
	return risk.UnmarshalPolicy(weightsJSON, thresholdsJSON)
}

func marshalBreakdown(b []ScoreFactor) string { return risk.MarshalBreakdown(b) }

func assetWeight(exposure, tier string) float64 { return risk.AssetWeight(exposure, tier) }
