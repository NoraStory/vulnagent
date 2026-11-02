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
	OSArch      string `json:"osArch"`
	Kernel      string `json:"kernel"`
	Env         string `json:"env"`
	Exposure    string `json:"exposure"`
	Tier        string `json:"tier"`
	Owner       string `json:"owner"`
	Source      string `json:"source"`
	AgentStatus string `json:"agentStatus"`
	LastSeen    string `json:"lastSeen"`

	AssetType      string   `json:"assetType"`
	Status         string   `json:"status"`
	BusinessSystem string   `json:"businessSystem"`
	Department     string   `json:"department"`
	OwnerEmail     string   `json:"ownerEmail"`
	Location       string   `json:"location"`
	CloudProvider  string   `json:"cloudProvider"`
	CloudAccount   string   `json:"cloudAccount"`
	Region         string   `json:"region"`
	InstanceID     string   `json:"instanceId"`
	MAC            string   `json:"mac"`
	Serial         string   `json:"serial"`
	Virtualized    string   `json:"virtualized"`
	MergedInto     int64    `json:"mergedInto"`
	Tags           []string `json:"tags"`

	Components int `json:"components"`
	Findings   int `json:"findings"`
	P0         int `json:"p0"`
	Risk       int `json:"risk"`
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
	tags := it.Tags
	if tags == nil {
		tags = []string{}
	}
	return assetItem{
		ID:             it.ID,
		Hostname:       it.Hostname,
		IP:             it.IP,
		OS:             it.OSFamily,
		OSVersion:      it.OSVersion,
		OSArch:         it.OSArch,
		Kernel:         it.Kernel,
		Env:            it.Env,
		Exposure:       it.Exposure,
		Tier:           it.Tier,
		Owner:          it.Owner,
		Source:         it.Source,
		AgentStatus:    it.AgentStatus,
		LastSeen:       it.LastSeen,
		AssetType:      it.AssetType,
		Status:         it.Status,
		BusinessSystem: it.BusinessSystem,
		Department:     it.Department,
		OwnerEmail:     it.OwnerEmail,
		Location:       it.Location,
		CloudProvider:  it.CloudProvider,
		CloudAccount:   it.CloudAccount,
		Region:         it.Region,
		InstanceID:     it.InstanceID,
		MAC:            it.MAC,
		Serial:         it.Serial,
		Virtualized:    it.Virtualized,
		MergedInto:     it.MergedInto,
		Tags:           tags,
		Components:     it.Components,
		Findings:       it.Findings,
		P0:             it.P0,
		Risk:           it.Risk,
	}
}

// assetFilterFromQuery 解析资产列表筛选参数
func assetFilterFromQuery(r *http.Request) ports.AssetFilter {
	q := r.URL.Query()
	clusterID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("clusterId")), 10, 64)
	return ports.AssetFilter{
		Query:           strings.TrimSpace(q.Get("q")),
		Env:             strings.TrimSpace(q.Get("env")),
		Exposure:        strings.TrimSpace(q.Get("exposure")),
		Tier:            strings.TrimSpace(q.Get("tier")),
		Status:          strings.TrimSpace(q.Get("status")),
		AssetType:       strings.TrimSpace(q.Get("assetType")),
		BusinessSystem:  strings.TrimSpace(q.Get("businessSystem")),
		Owner:           strings.TrimSpace(q.Get("owner")),
		CloudProvider:   strings.TrimSpace(q.Get("cloudProvider")),
		ClusterID:       clusterID,
		IncludeArchived: q.Get("includeArchived") == "1" || q.Get("includeArchived") == "true",
	}
}

func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	page, size, offset := pageParams(r)
	list, total, err := a.assetRepo().List(r.Context(), assetFilterFromQuery(r), size, offset)
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

	identifiers, err := a.assetRepo().Identifiers(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产标识失败")
		return
	}
	changes, err := a.assetRepo().Changes(r.Context(), id, 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产变更失败")
		return
	}
	relations, err := a.assetRepo().Relations(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产关系失败")
		return
	}

	item := toAssetItem(detail)
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":        a.demoMode(),
		"asset":       item,
		"components":  components,
		"findings":    findings,
		"identifiers": identifiers,
		"changes":     changes,
		"relations":   relations,
	})
}
