package main

import (
	"context"
	"fmt"
	"strings"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/asset"
)

// reconcileResult 复扫收敛结果
type reconcileResult struct {
	Verified int // 组件已不低于修复版本，或不再命中受影响区间
	Closed   int // 组件已从资产移除
	Reopened int // 已验证的漏洞因版本回退重新命中
	Kept     int // 仍受影响或无需变更，保持原状态
}

// reconcileFindingStates 复扫后收敛漏洞状态，只处理未闭环的记录：
//   - 组件已移除 → closed
//   - 当前版本 >= 修复版本 → verified
//   - 已不在受影响区间内 → verified
//   - 仍然命中 → 保持不变
//
// 组件以「名称 + 生态」关联当前快照（PURL 含版本号，升级后会变化）；
// 同名多副本时取最低版本判断，避免仍有旧副本却提前标记已修复。
func (a *App) reconcileFindingStates(assetID int64, actor string) (reconcileResult, error) {
	var out reconcileResult
	ctx := context.Background()

	comps, err := a.assetRepo().Components(ctx, assetID)
	if err != nil {
		return out, err
	}
	installed := make(map[string][]asset.Component)
	for _, c := range comps {
		key := strings.ToLower(c.Name) + "|" + strings.ToLower(c.Eco)
		installed[key] = append(installed[key], c)
	}

	rows, err := a.findingRepo().ActiveForReconcile(ctx, assetID)
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
		ranges, found, err := a.intelRepo().AffectedFor(ctx, p.row.CVEID, p.current.Product)
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

	now := fmtT(nowT())
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
			if err := a.findingRepo().MarkStatus(ctx, item.row.ID, "open", now,
				fmt.Sprintf("rescan: 版本回退，重新命中受影响区间（%s）", item.current.Version),
				actor, "当前组件版本重新落入受影响区间，自动重新打开"); err != nil {
				return out, err
			}
			out.Reopened++

		case item.removed:
			if err := a.findingRepo().MarkStatus(ctx, item.row.ID, "closed", now,
				fmt.Sprintf("rescan: 组件 %s 已从资产移除", item.row.ComponentName),
				actor, "复扫未发现该组件，自动关闭"); err != nil {
				return out, err
			}
			out.Closed++

		case item.row.FixedVersion != "" && CompareVersion(item.current.Eco, item.current.Version, item.row.FixedVersion) >= 0:
			if err := a.findingRepo().MarkStatus(ctx, item.row.ID, "verified", now,
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
			if err := a.findingRepo().MarkStatus(ctx, item.row.ID, "verified", now,
				"rescan: 不再命中受影响区间",
				actor, "情报区间已更新，当前版本不受影响，自动验证通过"); err != nil {
				return out, err
			}
			out.Verified++
		}
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
		if CompareVersion(eco, c.Version, best.Version) < 0 {
			best = c
		}
	}
	return best, true
}
