package main

import (
	"context"
	"log/slog"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

// AffectedRange 兼容别名，领域实现见 internal/domain/vuln
type AffectedRange = vuln.AffectedRange

// matchAssetFindings 对单个资产执行一次匹配，返回新增与更新的漏洞条数。
// 已有漏洞保留处置状态、责任人与工单，只刷新评分相关字段。
// 新增的 P0/P1 会异步推送到已配置的 Webhook。
func (a *App) matchAssetFindings(policy RiskPolicy, assetID int64) (int, int, error) {
	ctx := context.Background()
	host, err := a.assetRepo().Get(ctx, assetID)
	if err != nil {
		return 0, 0, err
	}

	metas, err := a.intelRepo().CVEMeta(ctx)
	if err != nil {
		return 0, 0, err
	}
	ranges, err := a.intelRepo().AffectedByProduct(ctx)
	if err != nil {
		return 0, 0, err
	}
	mappings, err := a.intelRepo().ProductMappings(ctx)
	if err != nil {
		return 0, 0, err
	}
	comps, err := a.assetRepo().Components(ctx, assetID)
	if err != nil {
		return 0, 0, err
	}

	exposure, tier := string(host.Exposure), string(host.Tier)
	now := fmtT(nowT())
	created, updated := 0, 0
	fresh := make([]map[string]any, 0, 4)

	for _, comp := range comps {
		seenCVE := make(map[string]bool)
		// apply 按给定产品名匹配；inferred 表示命中的是映射产品而非原始包名
		apply := func(key string, inferred bool) error {
			if key == "" {
				return nil
			}
			for _, r := range ranges[key] {
				if seenCVE[r.CveID] || !r.Matches(comp.Eco, comp.Version) {
					continue
				}
				meta, ok := metas[r.CveID]
				if !ok {
					continue
				}
				risk, priority, breakdown := policy.Score(meta.Score, meta.EPSS, meta.Exploit, exposure, tier)
				fixed := r.FixedVersion
				if fixed == "" {
					fixed = meta.Fixed
				}
				wasCreated, err := a.findingRepo().UpsertMatch(ctx, ports.MatchInput{
					AssetID:      assetID,
					Component:    comp,
					CVEID:        r.CveID,
					CVSS:         meta.Score,
					EPSS:         meta.EPSS,
					Exploit:      meta.Exploit,
					AssetWeight:  assetWeight(exposure, tier),
					Risk:         risk,
					Priority:     priority,
					Breakdown:    marshalBreakdown(breakdown),
					Inferred:     inferred,
					FixedVersion: fixed,
					Now:          now,
				})
				if err != nil {
					return err
				}
				if wasCreated {
					created++
					if priority == "P0" || priority == "P1" {
						fresh = append(fresh, map[string]any{
							"assetId":      assetID,
							"hostname":     host.Hostname,
							"cveId":        r.CveID,
							"priority":     priority,
							"risk":         risk,
							"component":    comp.Name,
							"version":      comp.Version,
							"fixedVersion": fixed,
							"inferred":     inferred,
						})
					}
				} else {
					updated++
				}
				seenCVE[r.CveID] = true
			}
			return nil
		}

		if mapping, ok := mappings[strings.ToLower(comp.Eco)+"|"+strings.ToLower(comp.Name)]; ok {
			if err := apply(strings.ToLower(mapping.Product), true); err != nil {
				return created, updated, err
			}
		}
		if err := apply(strings.ToLower(comp.Product), false); err != nil {
			return created, updated, err
		}
		if err := apply(strings.ToLower(comp.Name), false); err != nil {
			return created, updated, err
		}
	}

	slog.Info("资产匹配完成", "assetId", assetID, "components", len(comps), "created", created, "updated", updated)
	if len(fresh) > 0 {
		a.dispatch("finding.new", map[string]any{
			"assetId":  assetID,
			"hostname": host.Hostname,
			"count":    len(fresh),
			"findings": fresh,
		})
	}
	return created, updated, nil
}
