package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// reconcileResult 复扫收敛结果
type reconcileResult struct {
	Verified int // 组件已不低于修复版本，或不再命中受影响区间
	Closed   int // 组件已从资产移除
	Reopened int // 已验证的漏洞因版本回退重新命中
	Kept     int // 仍受影响或无需变更，保持原状态
}

type installedComponent struct {
	name    string
	eco     string
	version string
	product string
}

// reconcileFindingStates 复扫后收敛漏洞状态，只处理未闭环的记录：
//   - 组件已移除 → closed
//   - 当前版本 >= 修复版本 → verified
//   - 已不在受影响区间内 → verified
//   - 仍然命中 → 保持不变
//
// 组件以「名称 + 生态」关联当前快照（PURL 含版本号，升级后会变化）；
// 同名多副本时取最低版本判断，避免仍有旧副本却提前标记已修复。
func reconcileFindingStates(db *sql.DB, assetID int64, actor string) (reconcileResult, error) {
	var out reconcileResult

	compRows, err := db.Query(`SELECT name, eco, version, product FROM components WHERE asset_id = ?`, assetID)
	if err != nil {
		return out, err
	}
	installed := make(map[string][]installedComponent)
	for compRows.Next() {
		var c installedComponent
		if err := compRows.Scan(&c.name, &c.eco, &c.version, &c.product); err != nil {
			compRows.Close()
			return out, err
		}
		key := strings.ToLower(c.name) + "|" + strings.ToLower(c.eco)
		installed[key] = append(installed[key], c)
	}
	compRows.Close()
	if err := compRows.Err(); err != nil {
		return out, err
	}

	rows, err := db.Query(`SELECT id, cve_id, status, fixed_version, component_name, component_version, eco
		FROM findings WHERE asset_id = ? AND status IN ('open','triaged','fixing','fixed','verified')`, assetID)
	if err != nil {
		return out, err
	}

	type pending struct {
		id                      int64
		cveID, status           string
		fixed, name, oldVersion string
		eco                     string
		current                 installedComponent
		removed                 bool
	}
	var items []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.cveID, &p.status, &p.fixed, &p.name, &p.oldVersion, &p.eco); err != nil {
			rows.Close()
			return out, err
		}
		key := strings.ToLower(p.name) + "|" + strings.ToLower(p.eco)
		if candidate, ok := lowestInstalled(installed[key], p.eco); ok {
			p.current = candidate
		} else {
			p.removed = true
		}
		items = append(items, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	now := fmtT(nowT())
	for _, item := range items {
		switch {
		case item.status == "verified":
			// 已验证的记录保持不动，除非版本回退后重新落入受影响区间
			if item.removed {
				out.Kept++
				continue
			}
			affected, err := stillAffected(db, item.cveID, item.current.product, item.current.eco, item.current.version)
			if err != nil {
				return out, err
			}
			if !affected {
				out.Kept++
				continue
			}
			if err := markFinding(db, item.id, "open", now,
				fmt.Sprintf("rescan: 版本回退，重新命中受影响区间（%s）", item.current.version),
				actor, "当前组件版本重新落入受影响区间，自动重新打开"); err != nil {
				return out, err
			}
			out.Reopened++

		case item.removed:
			if err := markFinding(db, item.id, "closed", now,
				fmt.Sprintf("rescan: 组件 %s 已从资产移除", item.name),
				actor, "复扫未发现该组件，自动关闭"); err != nil {
				return out, err
			}
			out.Closed++

		case item.fixed != "" && CompareVersion(item.current.eco, item.current.version, item.fixed) >= 0:
			if err := markFinding(db, item.id, "verified", now,
				fmt.Sprintf("rescan: 复扫通过（%s → %s）", item.oldVersion, item.current.version),
				actor, "组件版本已不低于修复版本，自动验证通过"); err != nil {
				return out, err
			}
			out.Verified++

		default:
			affected, err := stillAffected(db, item.cveID, item.current.product, item.current.eco, item.current.version)
			if err != nil {
				return out, err
			}
			if affected {
				out.Kept++
				continue
			}
			if err := markFinding(db, item.id, "verified", now,
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
func lowestInstalled(list []installedComponent, eco string) (installedComponent, bool) {
	if len(list) == 0 {
		return installedComponent{}, false
	}
	best := list[0]
	for _, c := range list[1:] {
		if CompareVersion(eco, c.version, best.version) < 0 {
			best = c
		}
	}
	return best, true
}

func markFinding(db *sql.DB, findingID int64, status, now, event, actor, detail string) error {
	if _, err := db.Exec(`UPDATE findings SET status = ?, last_seen = ? WHERE id = ?`,
		status, now, findingID); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO finding_events(finding_id, event, actor, detail, created_at)
		VALUES(?,?,?,?,?)`, findingID, event, actor, detail, now)
	return err
}

// stillAffected 判断当前版本是否仍落在该 CVE 的受影响区间内。
// 没有区间数据时按"仍受影响"处理，避免误关闭。
func stillAffected(db *sql.DB, cveID, product, eco, version string) (bool, error) {
	if product == "" {
		return true, nil
	}
	rows, err := db.Query(`SELECT version_start_incl, version_end_excl FROM cve_affected
		WHERE cve_id = ? AND lower(product) = ?`, cveID, strings.ToLower(product))
	if err != nil {
		return true, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
		var start, end string
		if err := rows.Scan(&start, &end); err != nil {
			return true, err
		}
		rangeRule := AffectedRange{CveID: cveID, Product: product, VersionStartIncl: start, VersionEndExcl: end}
		if rangeRule.Matches(eco, version) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return true, err
	}
	if !found {
		return true, nil
	}
	return false, nil
}
