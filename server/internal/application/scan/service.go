// Package scan 是扫描相关用例的应用服务：把「入库 → 匹配 → 收敛」编排在一起，
// 领域规则来自 domain 包，数据访问来自 ports 端口。
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/asset"
	"vulnagent/server/internal/domain/risk"
	"vulnagent/server/internal/domain/version"
	"vulnagent/server/internal/platform/clock"
)

// Service 扫描编排器。策略在构造时固定，避免一次扫描内多次读库。
type Service struct {
	Assets   ports.AssetRepository
	Intel    ports.IntelRepository
	Findings ports.FindingRepository
	Policy   risk.Policy
	// Publish 在写入成功后发布领域事件，可为 nil
	Publish func(event string, data map[string]any)
}

// MatchResult 一次匹配的结果
type MatchResult struct {
	Created int
	Updated int
}

// ReconcileResult 复扫收敛结果
type ReconcileResult struct {
	Verified int
	Closed   int
	Reopened int
	Kept     int
}

// MatchAsset 对单个资产执行一次版本区间匹配。
// 已有漏洞保留处置状态、责任人与工单，只刷新评分相关字段。
func (s *Service) MatchAsset(assetID int64) (MatchResult, error) {
	var out MatchResult
	ctx := context.Background()
	host, err := s.Assets.Get(ctx, assetID)
	if err != nil {
		return out, err
	}
	metas, err := s.Intel.CVEMeta(ctx)
	if err != nil {
		return out, err
	}
	ranges, err := s.Intel.AffectedByProduct(ctx)
	if err != nil {
		return out, err
	}
	mappings, err := s.Intel.ProductMappings(ctx)
	if err != nil {
		return out, err
	}
	comps, err := s.Assets.Components(ctx, assetID)
	if err != nil {
		return out, err
	}

	exposure, tier := string(host.Exposure), string(host.Tier)
	now := clock.FormatNow()
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
				riskScore, priority, breakdown := s.Policy.Score(meta.Score, meta.EPSS, meta.Exploit, exposure, tier)
				fixed := r.FixedVersion
				if fixed == "" {
					fixed = meta.Fixed
				}
				wasCreated, err := s.Findings.UpsertMatch(ctx, ports.MatchInput{
					AssetID:      assetID,
					Component:    comp,
					CVEID:        r.CveID,
					CVSS:         meta.Score,
					EPSS:         meta.EPSS,
					Exploit:      meta.Exploit,
					AssetWeight:  risk.AssetWeight(exposure, tier),
					Risk:         riskScore,
					Priority:     priority,
					Breakdown:    risk.MarshalBreakdown(breakdown),
					Inferred:     inferred,
					FixedVersion: fixed,
					Now:          now,
				})
				if err != nil {
					return err
				}
				if wasCreated {
					out.Created++
					if priority == "P0" || priority == "P1" {
						fresh = append(fresh, map[string]any{
							"assetId":      assetID,
							"hostname":     host.Hostname,
							"cveId":        r.CveID,
							"priority":     priority,
							"risk":         riskScore,
							"component":    comp.Name,
							"version":      comp.Version,
							"fixedVersion": fixed,
							"inferred":     inferred,
						})
					}
				} else {
					out.Updated++
				}
				seenCVE[r.CveID] = true
			}
			return nil
		}

		if mapping, ok := mappings[strings.ToLower(comp.Eco)+"|"+strings.ToLower(comp.Name)]; ok {
			if err := apply(strings.ToLower(mapping.Product), true); err != nil {
				return out, err
			}
		}
		if err := apply(strings.ToLower(comp.Product), false); err != nil {
			return out, err
		}
		if err := apply(strings.ToLower(comp.Name), false); err != nil {
			return out, err
		}
	}

	slog.Info("资产匹配完成", "assetId", assetID, "components", len(comps),
		"created", out.Created, "updated", out.Updated)
	if len(fresh) > 0 && s.Publish != nil {
		s.Publish("finding.new", map[string]any{
			"assetId":  assetID,
			"hostname": host.Hostname,
			"count":    len(fresh),
			"findings": fresh,
		})
	}
	return out, nil
}

// Reconcile 复扫后收敛漏洞状态，只处理未闭环的记录：
//   - 组件已移除 → closed
//   - 当前版本 >= 修复版本 → verified
//   - 已不在受影响区间内 → verified
//   - 仍然命中 → 保持不变
//
// 组件以「名称 + 生态」关联当前快照（PURL 含版本号，升级后会变化）；
// 同名多副本时取最低版本判断，避免仍有旧副本却提前标记已修复。
func (s *Service) Reconcile(assetID int64, actor string) (ReconcileResult, error) {
	var out ReconcileResult
	ctx := context.Background()

	comps, err := s.Assets.Components(ctx, assetID)
	if err != nil {
		return out, err
	}
	installed := make(map[string][]asset.Component)
	for _, c := range comps {
		key := strings.ToLower(c.Name) + "|" + strings.ToLower(c.Eco)
		installed[key] = append(installed[key], c)
	}

	rows, err := s.Findings.ActiveForReconcile(ctx, assetID)
	if err != nil {
		return out, err
	}

	type pending struct {
		row     ports.ReconcileRow
		current asset.Component
		removed bool
	}
	var items []pending
	for _, row := range rows {
		p := pending{row: row}
		key := strings.ToLower(row.ComponentName) + "|" + strings.ToLower(row.Eco)
		if candidate, ok := lowestInstalled(installed[key], row.Eco); ok {
			p.current = candidate
		} else {
			p.removed = true
		}
		items = append(items, p)
	}

	// stillAffected 判断当前版本是否仍落在该 CVE 的受影响区间内。
	// 没有区间数据时按「仍受影响」处理，避免误关闭。
	stillAffected := func(p pending) (bool, error) {
		if p.current.Product == "" {
			return true, nil
		}
		ranges, found, err := s.Intel.AffectedFor(ctx, p.row.CVEID, p.current.Product)
		if err != nil {
			return true, err
		}
		if !found {
			return true, nil
		}
		for _, r := range ranges {
			if r.Matches(p.current.Eco, p.current.Version) {
				return true, nil
			}
		}
		return false, nil
	}

	now := clock.FormatNow()
	for _, item := range items {
		switch {
		case item.row.Status == "verified":
			// 已验证的记录保持不动，除非版本回退后重新落入受影响区间
			if item.removed {
				out.Kept++
				continue
			}
			affected, err := stillAffected(item)
			if err != nil {
				return out, err
			}
			if !affected {
				out.Kept++
				continue
			}
			if err := s.Findings.MarkStatus(ctx, item.row.ID, "open", now,
				fmt.Sprintf("rescan: 版本回退，重新命中受影响区间（%s）", item.current.Version),
				actor, "当前组件版本重新落入受影响区间，自动重新打开"); err != nil {
				return out, err
			}
			out.Reopened++

		case item.removed:
			if err := s.Findings.MarkStatus(ctx, item.row.ID, "closed", now,
				fmt.Sprintf("rescan: 组件 %s 已从资产移除", item.row.ComponentName),
				actor, "复扫未发现该组件，自动关闭"); err != nil {
				return out, err
			}
			out.Closed++

		case item.row.FixedVersion != "" && version.Compare(item.current.Eco, item.current.Version, item.row.FixedVersion) >= 0:
			if err := s.Findings.MarkStatus(ctx, item.row.ID, "verified", now,
				fmt.Sprintf("rescan: 复扫通过（%s → %s）", item.row.ComponentVersion, item.current.Version),
				actor, "组件版本已不低于修复版本，自动验证通过"); err != nil {
				return out, err
			}
			out.Verified++

		default:
			affected, err := stillAffected(item)
			if err != nil {
				return out, err
			}
			if affected {
				out.Kept++
				continue
			}
			if err := s.Findings.MarkStatus(ctx, item.row.ID, "verified", now,
				"rescan: 不再命中受影响区间",
				actor, "情报区间已更新，当前版本不受影响，自动验证通过"); err != nil {
				return out, err
			}
			out.Verified++
		}
	}
	return out, nil
}

// RematchAll 映射或策略变更后重新匹配全部资产（只新增/更新结论，不删除历史）
func (s *Service) RematchAll(actor string) (int, error) {
	ids, err := s.Assets.IDs(context.Background())
	if err != nil {
		return 0, err
	}
	rematched := 0
	for _, id := range ids {
		if _, err := s.MatchAsset(id); err != nil {
			return rematched, err
		}
		if _, err := s.Reconcile(id, actor); err != nil {
			return rematched, err
		}
		rematched++
	}
	return rematched, nil
}

// IngestInput 一次清单入库的输入
type IngestInput struct {
	Hostname  string
	IP        string
	OSFamily  string
	OSVersion string
	Source    string
	// AgentStatus 由调用方按来源决定（agent 上报为 online）
	AgentStatus string
	Components  []asset.Component
}

// IngestResult 一次清单入库的结果
type IngestResult struct {
	AssetID    int64
	Components int
	Created    int
	Updated    int
	Verified   int
	Closed     int
	Reopened   int
}

// Ingest 统一入库路径：upsert 资产 → 整体替换组件 → 版本区间匹配 → 状态收敛。
// OSV 在线匹配属于外部 IO，由调用方在事务外异步触发。
func (s *Service) Ingest(in IngestInput) (IngestResult, error) {
	var out IngestResult
	ctx := context.Background()
	assetID, err := s.Assets.UpsertReported(ctx, in.Hostname, in.IP, in.OSFamily, in.OSVersion,
		in.Source, in.AgentStatus, clock.FormatNow())
	if err != nil {
		return out, err
	}
	out.AssetID = assetID
	if err := s.Assets.ReplaceComponents(ctx, assetID, in.Components); err != nil {
		return out, err
	}
	out.Components = len(in.Components)

	matched, err := s.MatchAsset(assetID)
	if err != nil {
		return out, err
	}
	out.Created, out.Updated = matched.Created, matched.Updated

	recon, err := s.Reconcile(assetID, "系统")
	if err != nil {
		slog.Warn("复扫收敛失败", "assetId", assetID, "err", err)
	} else {
		out.Verified, out.Closed, out.Reopened = recon.Verified, recon.Closed, recon.Reopened
	}
	return out, nil
}

// lowestInstalled 取同名的已安装组件中版本最低的一个
func lowestInstalled(list []asset.Component, eco string) (asset.Component, bool) {
	if len(list) == 0 {
		return asset.Component{}, false
	}
	best := list[0]
	for _, c := range list[1:] {
		if version.Compare(eco, c.Version, best.Version) < 0 {
			best = c
		}
	}
	return best, true
}
