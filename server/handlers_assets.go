package main

import (
	"net/http"
	"strconv"
	"strings"

	"vulnagent/server/internal/application/ports"
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

func toAssetItem(it ports.AssetListItem) assetItem {
	return assetItem{
		ID:          it.ID,
		Hostname:    it.Hostname,
		IP:          it.IP,
		OS:          it.OSFamily,
		OSVersion:   it.OSVersion,
		Env:         it.Env,
		Exposure:    it.Exposure,
		Tier:        it.Tier,
		Owner:       it.Owner,
		Source:      it.Source,
		AgentStatus: it.AgentStatus,
		LastSeen:    it.LastSeen,
		Components:  it.Components,
		Findings:    it.Findings,
		P0:          it.P0,
		Risk:        it.Risk,
	}
}

func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	page, size, offset := pageParams(r)
	list, total, err := a.assetRepo().List(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), size, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产列表失败")
		return
	}
	items := make([]assetItem, 0, len(list))
	for _, it := range list {
		items = append(items, toAssetItem(it))
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
	detail, err := a.assetRepo().Detail(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
		return
	}

	compRows, err := a.assetRepo().ComponentRows(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询组件清单失败")
		return
	}
	components := make([]assetComponent, 0, len(compRows))
	for _, c := range compRows {
		components = append(components, assetComponent{
			Purl:      c.PURL,
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: c.Eco,
			Vendor:    c.Vendor,
			Product:   c.Product,
			Inferred:  c.Inferred,
			Findings:  c.Findings,
		})
	}

	findingRows, err := a.findingRepo().ListByAsset(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产漏洞失败")
		return
	}
	findings := make([]findingItem, 0, len(findingRows))
	for _, it := range findingRows {
		findings = append(findings, toFindingItem(it))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"demo":       a.demoMode(),
		"asset":      toAssetItem(detail),
		"components": components,
		"findings":   findings,
	})
}
