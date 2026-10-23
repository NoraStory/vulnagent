package main

import (
	"net/http"
	"strconv"
	"strings"
)

type assetItem struct {
	ID          int64  `json:"id"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	OS          string `json:"os"`
	OSVersion   string `json:"osVersion"`
	Env         string `json:"env"`
	Exposure    string `json:"exposure"`
	Tier        string `json:"tier"`
	Owner       string `json:"owner"`
	Source      string `json:"source"`
	AgentStatus string `json:"agentStatus"`
	LastSeen    string `json:"lastSeen"`
	Components  int    `json:"components"`
	Findings    int    `json:"findings"`
	P0          int    `json:"p0"`
	Risk        int    `json:"risk"`
}

type assetComponent struct {
	Purl      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Inferred  bool   `json:"inferred"`
	Findings  int    `json:"findings"`
}

const assetSelect = `SELECT a.id, a.hostname, a.ip, a.os_family, a.os_version, a.env, a.exposure, a.tier,
	a.owner, a.source, a.agent_status, a.last_seen_at,
	(SELECT COUNT(*) FROM components c WHERE c.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id),
	(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.priority = 'P0'),
	COALESCE((SELECT MAX(f.risk) FROM findings f WHERE f.asset_id = a.id), 0)
	FROM assets a`

func scanAsset(sc interface{ Scan(...any) error }) (assetItem, error) {
	var it assetItem
	err := sc.Scan(&it.ID, &it.Hostname, &it.IP, &it.OS, &it.OSVersion, &it.Env, &it.Exposure, &it.Tier,
		&it.Owner, &it.Source, &it.AgentStatus, &it.LastSeen,
		&it.Components, &it.Findings, &it.P0, &it.Risk)
	return it, err
}

func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	page, size, offset := pageParams(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	where := "1=1"
	args := []any{}
	if q != "" {
		like := "%" + q + "%"
		where = "(a.hostname LIKE ? OR a.owner LIKE ? OR a.ip LIKE ?)"
		args = append(args, like, like, like)
	}

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM assets a WHERE `+where, args...).Scan(&total); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产列表失败")
		return
	}
	rows, err := a.db.Query(assetSelect+" WHERE "+where+" ORDER BY a.id ASC LIMIT ? OFFSET ?",
		append(args, size, offset)...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产列表失败")
		return
	}
	defer rows.Close()

	items := make([]assetItem, 0, size)
	for rows.Next() {
		it, err := scanAsset(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "解析资产数据失败")
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":     a.demoMode(),
		"total":    total,
		"page":     page,
		"pageSize": size,
		"items":    items,
	})
}

func (a *App) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	asset, err := scanAsset(a.db.QueryRow(assetSelect+" WHERE a.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
		return
	}

	compRows, err := a.db.Query(`SELECT c.purl, c.name, c.version, c.eco, c.vendor, c.product, c.inferred,
		(SELECT COUNT(*) FROM findings f WHERE f.asset_id = c.asset_id AND f.purl = c.purl)
		FROM components c WHERE c.asset_id = ? ORDER BY c.eco ASC, c.name ASC`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询组件清单失败")
		return
	}
	defer compRows.Close()
	components := make([]assetComponent, 0)
	for compRows.Next() {
		var c assetComponent
		if err := compRows.Scan(&c.Purl, &c.Name, &c.Version, &c.Ecosystem, &c.Vendor, &c.Product, &c.Inferred, &c.Findings); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "解析组件清单失败")
			return
		}
		components = append(components, c)
	}

	rows, err := a.db.Query(findingSelect+" WHERE f.asset_id = ? ORDER BY f.risk DESC, f.id ASC", id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产漏洞失败")
		return
	}
	defer rows.Close()
	findings := make([]findingItem, 0)
	for rows.Next() {
		it, err := scanFinding(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "解析资产漏洞失败")
			return
		}
		findings = append(findings, it)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"demo":       a.demoMode(),
		"asset":      asset,
		"components": components,
		"findings":   findings,
	})
}
