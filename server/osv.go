package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultOSVURL = "https://api.osv.dev/v1/query"

func osvURLFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("VA_OSV_URL")); v != "" {
		return v
	}
	return defaultOSVURL
}

// OSV 生态映射：只处理有明确包名/版本语义的生态
var osvEcosystem = map[string]string{
	"golang":   "Go",
	"npm":      "npm",
	"pypi":     "PyPI",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"deb":      "Debian",
	"apk":      "Alpine",
	"gem":      "RubyGems",
	"cargo":    "crates.io",
	"composer": "Packagist",
}

type osvQueryRequest struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvEvent map[string]string

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Published        string         `json:"published"`
	Modified         string         `json:"modified"`
	Severity         []osvSeverity  `json:"severity"`
	Affected         []osvAffected  `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvComponent struct {
	purl, name, version, eco string
}

type osvResult struct {
	Assets     int `json:"assets"`
	Components int `json:"components"`
	Queried    int `json:"queried"`
	Vulns      int `json:"vulns"`
	Created    int `json:"created"`
	Updated    int `json:"updated"`
	Errors     int `json:"errors"`
}

// osvScanAssets 对所有（或指定）资产做 OSV 在线匹配
func (a *App) osvScanAssets(assetIDs []int64, all bool) (osvResult, error) {
	var total osvResult
	ids := assetIDs
	if all {
		rows, err := a.db.Query(`SELECT id FROM assets ORDER BY id`)
		if err != nil {
			return total, err
		}
		ids = nil
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return total, err
			}
			ids = append(ids, id)
		}
		rows.Close()
	}
	for _, id := range ids {
		res, err := a.osvScanAsset(id, "系统")
		if err != nil {
			slog.Warn("OSV 匹配失败", "assetId", id, "err", err)
			total.Errors++
			continue
		}
		total.Assets++
		total.Components += res.Components
		total.Queried += res.Queried
		total.Vulns += res.Vulns
		total.Created += res.Created
		total.Updated += res.Updated
		total.Errors += res.Errors
	}
	return total, nil
}

// osvScanAsset 对单个资产按组件查询 OSV，写入 CVE 元数据、区间与漏洞结论
func (a *App) osvScanAsset(assetID int64, actor string) (osvResult, error) {
	var res osvResult
	var exposure, tier string
	if err := a.db.QueryRow(`SELECT exposure, tier FROM assets WHERE id = ?`, assetID).Scan(&exposure, &tier); err != nil {
		return res, err
	}
	rows, err := a.db.Query(`SELECT purl, name, version, eco FROM components WHERE asset_id = ?`, assetID)
	if err != nil {
		return res, err
	}
	comps := make([]osvComponent, 0, 256)
	for rows.Next() {
		var c osvComponent
		if err := rows.Scan(&c.purl, &c.name, &c.version, &c.eco); err != nil {
			rows.Close()
			return res, err
		}
		if _, ok := osvEcosystem[strings.ToLower(c.eco)]; ok && c.version != "" {
			comps = append(comps, c)
		}
	}
	rows.Close()
	res.Components = len(comps)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	type compResult struct {
		comp  osvComponent
		vulns []osvVuln
		err   error
	}
	results := make([]compResult, len(comps))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, comp := range comps {
		wg.Add(1)
		go func(idx int, c osvComponent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vulns, err := osvQuery(ctx, c)
			results[idx] = compResult{comp: c, vulns: vulns, err: err}
		}(i, comp)
	}
	wg.Wait()

	policy := loadPolicy(a.db)
	now := fmtT(nowT())
	for _, item := range results {
		if item.err != nil {
			res.Errors++
			continue
		}
		res.Queried++
		for _, v := range item.vulns {
			if v.ID == "" {
				continue
			}
			res.Vulns++
			cveID := osvCVEID(v)
			vector, score := osvScore(v)
			fixed := osvFixed(v, item.comp)
			meta := intelItem{
				CveID:       cveID,
				Title:       osvTitle(v),
				Description: v.Details,
				CvssVector:  vector,
				PublishedAt: normalizeAPITime(v.Published),
				UpdatedAt:   normalizeAPITime(v.Modified),
			}
			if meta.UpdatedAt == "" {
				meta.UpdatedAt = now
			}
			if _, err := upsertCVE(a.db, meta); err != nil {
				slog.Warn("写入 OSV 漏洞元数据失败", "cve", cveID, "err", err)
				res.Errors++
			}
			product := strings.ToLower(item.comp.name)
			if _, err := a.db.Exec(`INSERT INTO cve_affected(cve_id, product, version_start_incl, version_end_excl, fixed_version)
				VALUES(?,?,?,?,?)
				ON CONFLICT(cve_id, product) DO UPDATE SET
				version_start_incl = excluded.version_start_incl,
				version_end_excl = excluded.version_end_excl,
				fixed_version = excluded.fixed_version`,
				cveID, product, "", fixed, fixed); err != nil {
				slog.Warn("写入 OSV 受影响区间失败", "cve", cveID, "err", err)
			}

			risk, priority, breakdown := policy.score(score, 0, "none", exposure, tier)
			var existingID int64
			err := a.db.QueryRow(`SELECT id FROM findings WHERE asset_id = ? AND purl = ? AND cve_id = ?`,
				assetID, item.comp.purl, cveID).Scan(&existingID)
			switch {
			case err == sql.ErrNoRows:
				_, err = a.db.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, eco,
					cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, status, inferred,
					fixed_version, assignee, ticket_id, first_seen, last_seen)
					VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'open', 0, ?, '', '', ?, ?)`,
					assetID, item.comp.purl, item.comp.name, item.comp.version, item.comp.eco,
					cveID, score, 0, "none", assetWeight(exposure, tier), risk, priority,
					marshalBreakdown(breakdown), fixed, now, now)
				if err == nil {
					res.Created++
				}
			case err != nil:
				res.Errors++
				continue
			default:
				_, err = a.db.Exec(`UPDATE findings SET component_name = ?, component_version = ?, eco = ?,
					cvss = ?, risk = ?, priority = ?, score_breakdown = ?, fixed_version = ?, last_seen = ?
					WHERE id = ?`,
					item.comp.name, item.comp.version, item.comp.eco, score, risk, priority,
					marshalBreakdown(breakdown), fixed, now, existingID)
				if err == nil {
					res.Updated++
				}
			}
			if err != nil {
				slog.Warn("写入 OSV 结论失败", "cve", cveID, "err", err)
				res.Errors++
			}
		}
	}
	if _, err := reconcileFindingStates(a.db, assetID, actor); err != nil {
		return res, err
	}
	slog.Info("OSV 匹配完成", "assetId", assetID, "components", res.Components,
		"queried", res.Queried, "vulns", res.Vulns, "created", res.Created, "updated", res.Updated)
	return res, nil
}

func osvQuery(ctx context.Context, comp osvComponent) ([]osvVuln, error) {
	body, _ := json.Marshal(osvQueryRequest{
		Version: osvVersion(comp),
		Package: osvPackage{Name: osvPackageName(comp), Ecosystem: osvEcosystem[strings.ToLower(comp.eco)]},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvURLFromEnv(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV 返回 HTTP %d", resp.StatusCode)
	}
	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Vulns, nil
}

func osvVersion(c osvComponent) string {
	v := strings.TrimSpace(c.version)
	if strings.EqualFold(c.eco, "golang") {
		v = strings.TrimPrefix(v, "v")
	}
	return v
}

func osvPackageName(c osvComponent) string {
	if strings.EqualFold(c.eco, "pypi") {
		return strings.ToLower(c.name)
	}
	return c.name
}

func osvCVEID(v osvVuln) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return alias
		}
	}
	return v.ID
}

func osvTitle(v osvVuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	if idx := strings.Index(v.Details, "."); idx > 10 {
		return v.Details[:idx]
	}
	return v.ID
}

func osvScore(v osvVuln) (string, float64) {
	for _, sev := range v.Severity {
		if strings.HasPrefix(strings.ToUpper(sev.Score), "CVSS:") {
			if score, err := BaseScore(sev.Score); err == nil && score > 0 {
				return sev.Score, score
			}
		}
	}
	if raw, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(raw) {
		case "CRITICAL":
			return "", 9.5
		case "HIGH":
			return "", 8.0
		case "MODERATE", "MEDIUM":
			return "", 5.5
		case "LOW":
			return "", 3.0
		}
	}
	return "", 0
}

// osvFixed 取受影响区间中的修复版本（用于展示与复扫判定）
func osvFixed(v osvVuln, comp osvComponent) string {
	for _, aff := range v.Affected {
		if !strings.EqualFold(aff.Package.Name, comp.name) {
			continue
		}
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if fixed := ev["fixed"]; fixed != "" {
					return fixed
				}
			}
		}
	}
	return ""
}
