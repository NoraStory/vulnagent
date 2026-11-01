package main

import (
	"net/http"

	"vulnagent/server/internal/application/ports"
)

const topologyAssetLimit = 300

// handleTopology 返回按业务系统/环境过滤的资产拓扑
func (a *App) handleTopology(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	filter := assetFilterFromQuery(r)
	list, total, err := a.assetRepo().List(r.Context(), filter, topologyAssetLimit, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询拓扑资产失败")
		return
	}
	nodeIDs := make(map[int64]bool, len(list))
	assets := make([]ports.TopologyAsset, 0, len(list))
	for _, it := range list {
		nodeIDs[it.ID] = true
		assets = append(assets, ports.TopologyAsset{
			ID:             it.ID,
			Hostname:       it.Hostname,
			IP:             it.IP,
			BusinessSystem: it.BusinessSystem,
			Env:            it.Env,
			Tier:           it.Tier,
			Exposure:       it.Exposure,
			AssetType:      it.AssetType,
			Status:         it.Status,
			Risk:           it.Risk,
			Findings:       it.Findings,
			Components:     it.Components,
		})
	}
	edges, err := a.assetRepo().RelationEdges(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产关系失败")
		return
	}
	relations := make([]ports.TopologyEdge, 0, len(edges))
	for _, edge := range edges {
		if nodeIDs[edge.FromAssetID] && nodeIDs[edge.ToAssetID] {
			relations = append(relations, edge)
		}
	}
	businessSystems, err := a.businessRepo().List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询业务系统失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"assets":          assets,
		"relations":       relations,
		"businessSystems": businessSystems,
		"truncated":       total > len(assets),
		"total":           total,
	})
}
