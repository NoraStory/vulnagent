package main

import (
	"database/sql"
	"log/slog"
	"strings"
)

// AffectedRange 一条受影响版本区间（左闭右开）
type AffectedRange struct {
	CveID            string
	Product          string
	VersionStartIncl string
	VersionEndExcl   string
	FixedVersion     string
}

// Matches 判断组件版本是否落在区间内，ecosystem 决定版本比较规则
func (r AffectedRange) Matches(eco, version string) bool {
	if version == "" {
		return false
	}
	if r.VersionStartIncl != "" && CompareVersion(eco, version, r.VersionStartIncl) < 0 {
		return false
	}
	if r.VersionEndExcl != "" && CompareVersion(eco, version, r.VersionEndExcl) >= 0 {
		return false
	}
	return true
}

type cveMeta struct {
	score   float64
	epss    float64
	exploit string
	fixed   string
}

func loadCVEMeta(db *sql.DB) (map[string]cveMeta, error) {
	rows, err := db.Query(`SELECT cve_id, cvss_score, epss, exploit_state, fixed_version FROM cves`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	meta := make(map[string]cveMeta)
	for rows.Next() {
		var id string
		var m cveMeta
		if err := rows.Scan(&id, &m.score, &m.epss, &m.exploit, &m.fixed); err != nil {
			return nil, err
		}
		meta[id] = m
	}
	return meta, rows.Err()
}

func loadAffectedRanges(db *sql.DB) (map[string][]AffectedRange, error) {
	rows, err := db.Query(`SELECT cve_id, product, version_start_incl, version_end_excl, fixed_version FROM cve_affected`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byProduct := make(map[string][]AffectedRange)
	for rows.Next() {
		var r AffectedRange
		if err := rows.Scan(&r.CveID, &r.Product, &r.VersionStartIncl, &r.VersionEndExcl, &r.FixedVersion); err != nil {
			return nil, err
		}
		key := strings.ToLower(r.Product)
		byProduct[key] = append(byProduct[key], r)
	}
	return byProduct, rows.Err()
}

// matchAssetFindings 对单个资产执行一次匹配，返回新增与更新的漏洞条数。
// 已有漏洞保留处置状态、责任人与工单，只刷新评分相关字段。
// 新增的 P0/P1 会异步推送到已配置的 Webhook。
func (a *App) matchAssetFindings(policy RiskPolicy, assetID int64) (int, int, error) {
	db := a.db
	var exposure, tier, hostname string
	if err := db.QueryRow(`SELECT exposure, tier, hostname FROM assets WHERE id = ?`, assetID).
		Scan(&exposure, &tier, &hostname); err != nil {
		return 0, 0, err
	}

	metas, err := loadCVEMeta(db)
	if err != nil {
		return 0, 0, err
	}
	ranges, err := loadAffectedRanges(db)
	if err != nil {
		return 0, 0, err
	}
	mappings, err := loadProductMap(db)
	if err != nil {
		return 0, 0, err
	}

	type component struct {
		purl, name, version, eco, product string
	}
	rows, err := db.Query(`SELECT purl, name, version, eco, product FROM components WHERE asset_id = ?`, assetID)
	if err != nil {
		return 0, 0, err
	}
	var comps []component
	for rows.Next() {
		var c component
		if err := rows.Scan(&c.purl, &c.name, &c.version, &c.eco, &c.product); err != nil {
			rows.Close()
			return 0, 0, err
		}
		comps = append(comps, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

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
				if seenCVE[r.CveID] || !r.Matches(comp.eco, comp.version) {
					continue
				}
				meta, ok := metas[r.CveID]
				if !ok {
					continue
				}
				risk, priority, breakdown := policy.score(meta.score, meta.epss, meta.exploit, exposure, tier)
				fixed := r.FixedVersion
				if fixed == "" {
					fixed = meta.fixed
				}
				inferredFlag := 0
				if inferred {
					inferredFlag = 1
				}
				var existingID int64
				err := db.QueryRow(`SELECT id FROM findings WHERE asset_id = ? AND purl = ? AND cve_id = ?`,
					assetID, comp.purl, r.CveID).Scan(&existingID)
				switch {
				case err == sql.ErrNoRows:
					_, err = db.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco,
						cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, status, inferred,
						fixed_version, assignee, ticket_id, first_seen, last_seen)
						VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?, '', '', ?, ?)`,
						assetID, comp.purl, comp.name, comp.version, comp.eco, r.CveID, meta.score, meta.epss,
						meta.exploit, assetWeight(exposure, tier), risk, priority, marshalBreakdown(breakdown),
						inferredFlag, fixed, now, now)
					if err != nil {
						return err
					}
					created++
					if priority == "P0" || priority == "P1" {
						fresh = append(fresh, map[string]any{
							"assetId":      assetID,
							"hostname":     hostname,
							"cveId":        r.CveID,
							"priority":     priority,
							"risk":         risk,
							"component":    comp.name,
							"version":      comp.version,
							"fixedVersion": fixed,
							"inferred":     inferred,
						})
					}
				case err != nil:
					return err
				default:
					_, err = db.Exec(`UPDATE findings SET component_name = ?, component_version = ?, eco = ?,
						cvss = ?, epss = ?, exploit = ?, asset_weight = ?, risk = ?, priority = ?, score_breakdown = ?,
						inferred = MAX(inferred, ?), fixed_version = ?, last_seen = ? WHERE id = ?`,
						comp.name, comp.version, comp.eco, meta.score, meta.epss, meta.exploit,
						assetWeight(exposure, tier), risk, priority, marshalBreakdown(breakdown),
						inferredFlag, fixed, now, existingID)
					if err != nil {
						return err
					}
					updated++
				}
				seenCVE[r.CveID] = true
			}
			return nil
		}

		if mapping, ok := mappings[strings.ToLower(comp.eco)+"|"+strings.ToLower(comp.name)]; ok {
			if err := apply(strings.ToLower(mapping.Product), true); err != nil {
				return created, updated, err
			}
		}
		if err := apply(strings.ToLower(comp.product), false); err != nil {
			return created, updated, err
		}
		if err := apply(strings.ToLower(comp.name), false); err != nil {
			return created, updated, err
		}
	}

	slog.Info("资产匹配完成", "assetId", assetID, "components", len(comps), "created", created, "updated", updated)
	if len(fresh) > 0 {
		a.dispatch("finding.new", map[string]any{
			"assetId":  assetID,
			"hostname": hostname,
			"count":    len(fresh),
			"findings": fresh,
		})
	}
	return created, updated, nil
}
