package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// projectRecord 业务项目（可包含多个集群）
type projectRecord struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Owner        string `json:"owner"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	ClusterCount int    `json:"clusterCount"`
	NodeCount    int    `json:"nodeCount"`
}

// clusterRecord 一个可运维的集群
type clusterRecord struct {
	ID           int64  `json:"id"`
	ProjectID    int64  `json:"projectId"`
	ProjectName  string `json:"projectName"`
	Name         string `json:"name"`
	Environment  string `json:"environment"`
	Provider     string `json:"provider"`
	Region       string `json:"region"`
	Description  string `json:"description"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	NodeCount    int    `json:"nodeCount"`
	HealthyNodes int    `json:"healthyNodes"`
	AssetCount   int    `json:"assetCount"`
	OpenFindings int    `json:"openFindings"`
	P0           int    `json:"p0"`
	P1           int    `json:"p1"`
}

// clusterNodeRecord 集群节点：后端、数据库、缓存、代理、存储或扫描目标
type clusterNodeRecord struct {
	ID          int64  `json:"id"`
	ClusterID   int64  `json:"clusterId"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	URL         string `json:"url"`
	SSHHostID   int64  `json:"sshHostId"`
	CheckType   string `json:"checkType"`
	Path        string `json:"path"`
	Note        string `json:"note"`
	DBEngine    string `json:"dbEngine"`
	DBName      string `json:"dbName"`
	DBUser      string `json:"dbUser"`
	DBSSLMode   string `json:"dbSslMode"`
	DBDetail    string `json:"dbDetail"`
	DBCheckedAt string `json:"dbCheckedAt"`
	HasDBSecret bool   `json:"hasDbSecret"`
	dbSecret    string
	Status      string `json:"status"`
	LatencyMs   int64  `json:"latencyMs"`
	Detail      string `json:"detail"`
	CheckedAt   string `json:"checkedAt"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type clusterAsset struct {
	ID          int64  `json:"id"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	OSFamily    string `json:"osFamily"`
	AgentStatus string `json:"agentStatus"`
	LastSeenAt  string `json:"lastSeenAt"`
}

type clusterDetail struct {
	Cluster  clusterRecord       `json:"cluster"`
	Nodes    []clusterNodeRecord `json:"nodes"`
	Assets   []clusterAsset      `json:"assets"`
	Findings map[string]int      `json:"findings"`
}

const clusterNodeColumns = `id, cluster_id, name, role, host, port, url, ssh_host_id, check_type, path, note,
	status, latency_ms, detail, checked_at, created_at, updated_at,
	db_engine, db_name, db_user, db_secret, db_ssl_mode, db_detail, db_checked_at`

func scanClusterNode(row interface{ Scan(dest ...any) error }) (clusterNodeRecord, error) {
	var node clusterNodeRecord
	err := row.Scan(&node.ID, &node.ClusterID, &node.Name, &node.Role, &node.Host, &node.Port, &node.URL,
		&node.SSHHostID, &node.CheckType, &node.Path, &node.Note, &node.Status, &node.LatencyMs,
		&node.Detail, &node.CheckedAt, &node.CreatedAt, &node.UpdatedAt,
		&node.DBEngine, &node.DBName, &node.DBUser, &node.dbSecret, &node.DBSSLMode, &node.DBDetail, &node.DBCheckedAt)
	node.HasDBSecret = node.dbSecret != ""
	return node, err
}

// ---------- 项目 ----------

func (a *App) listProjects(ctx context.Context) ([]projectRecord, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT p.id, p.name, p.description, p.owner, p.created_at, p.updated_at,
		(SELECT COUNT(*) FROM clusters c WHERE c.project_id = p.id),
		(SELECT COUNT(*) FROM cluster_nodes n JOIN clusters c2 ON c2.id = n.cluster_id WHERE c2.project_id = p.id)
		FROM projects p ORDER BY p.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]projectRecord, 0, 8)
	for rows.Next() {
		var item projectRecord
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Owner, &item.CreatedAt, &item.UpdatedAt,
			&item.ClusterCount, &item.NodeCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *App) handleProjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	items, err := a.listProjects(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取项目失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Owner       string `json:"owner"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 80 {
		writeErr(w, http.StatusBadRequest, "bad_request", "项目名称不能为空且不超过 80 字")
		return
	}
	now := fmtT(nowT())
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO projects(name, description, owner, created_at, updated_at)
		VALUES(?,?,?,?,?)`, name, strings.TrimSpace(in.Description), strings.TrimSpace(in.Owner), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "project_exists", "项目名称已存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建项目失败")
		return
	}
	id, _ := res.LastInsertId()
	a.audit(r, "project.create", name, fmt.Sprintf("创建项目 #%d（%s）", id, u.Username))
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
}

func (a *App) handleProjectUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "项目 ID 无效")
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Owner       *string `json:"owner"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	var current projectRecord
	err = a.db.QueryRowContext(r.Context(), `SELECT id, name, description, owner FROM projects WHERE id = ?`, id).
		Scan(&current.ID, &current.Name, &current.Description, &current.Owner)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取项目失败")
		return
	}
	if in.Name != nil {
		current.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		current.Description = strings.TrimSpace(*in.Description)
	}
	if in.Owner != nil {
		current.Owner = strings.TrimSpace(*in.Owner)
	}
	if current.Name == "" || len(current.Name) > 80 {
		writeErr(w, http.StatusBadRequest, "bad_request", "项目名称不能为空且不超过 80 字")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE projects SET name=?, description=?, owner=?, updated_at=? WHERE id=?`,
		current.Name, current.Description, current.Owner, fmtT(nowT()), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新项目失败")
		return
	}
	a.audit(r, "project.update", current.Name, "更新项目")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "项目 ID 无效")
		return
	}
	ctx := r.Context()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET cluster_id = 0 WHERE cluster_id IN
		(SELECT id FROM clusters WHERE project_id = ?)`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM cluster_nodes WHERE cluster_id IN
		(SELECT id FROM clusters WHERE project_id = ?)`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM clusters WHERE project_id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除项目失败")
		return
	}
	a.audit(r, "project.delete", fmt.Sprintf("project/%d", id), "删除项目及其集群/节点")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 集群 ----------

func (a *App) listClusters(ctx context.Context, projectID int64) ([]clusterRecord, error) {
	query := `SELECT c.id, c.project_id, p.name, c.name, c.environment, c.provider, c.region, c.description,
		c.created_at, c.updated_at,
		(SELECT COUNT(*) FROM cluster_nodes n WHERE n.cluster_id = c.id),
		(SELECT COUNT(*) FROM cluster_nodes n WHERE n.cluster_id = c.id AND n.status = 'ok'),
		(SELECT COUNT(*) FROM assets a WHERE a.cluster_id = c.id),
		(SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
			WHERE a.cluster_id = c.id AND f.status IN ('open','triaged','fixing')),
		(SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
			WHERE a.cluster_id = c.id AND f.status IN ('open','triaged','fixing') AND f.priority = 'P0'),
		(SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
			WHERE a.cluster_id = c.id AND f.status IN ('open','triaged','fixing') AND f.priority = 'P1')
		FROM clusters c JOIN projects p ON p.id = c.project_id`
	args := make([]any, 0, 1)
	if projectID > 0 {
		query += ` WHERE c.project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY p.name COLLATE NOCASE, c.name COLLATE NOCASE`
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]clusterRecord, 0, 8)
	for rows.Next() {
		var item clusterRecord
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ProjectName, &item.Name, &item.Environment,
			&item.Provider, &item.Region, &item.Description, &item.CreatedAt, &item.UpdatedAt,
			&item.NodeCount, &item.HealthyNodes, &item.AssetCount, &item.OpenFindings, &item.P0, &item.P1); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *App) handleClusters(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	projectID, _ := strconv.ParseInt(r.URL.Query().Get("projectId"), 10, 64)
	items, err := a.listClusters(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取集群失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func validEnvironment(value string) bool {
	switch value {
	case "prod", "staging", "dev", "test", "other":
		return true
	}
	return false
}

func (a *App) handleClusterCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var in struct {
		ProjectID   int64  `json:"projectId"`
		Name        string `json:"name"`
		Environment string `json:"environment"`
		Provider    string `json:"provider"`
		Region      string `json:"region"`
		Description string `json:"description"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 80 {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群名称不能为空且不超过 80 字")
		return
	}
	environment := strings.ToLower(strings.TrimSpace(in.Environment))
	if environment == "" {
		environment = "prod"
	}
	if !validEnvironment(environment) {
		writeErr(w, http.StatusBadRequest, "bad_request", "环境必须为 prod/staging/dev/test/other")
		return
	}
	var projectExists int
	if err := a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM projects WHERE id = ?`, in.ProjectID).Scan(&projectExists); err != nil || projectExists == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "项目不存在")
		return
	}
	now := fmtT(nowT())
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO clusters
		(project_id, name, environment, provider, region, description, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		in.ProjectID, name, environment, strings.TrimSpace(in.Provider), strings.TrimSpace(in.Region),
		strings.TrimSpace(in.Description), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "cluster_exists", "同一项目下集群名称已存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建集群失败")
		return
	}
	id, _ := res.LastInsertId()
	a.audit(r, "cluster.create", name, fmt.Sprintf("创建集群 #%d（项目 #%d）", id, in.ProjectID))
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
}

func (a *App) handleClusterDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	ctx := r.Context()
	clusters, err := a.listClusters(ctx, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取集群失败")
		return
	}
	var detail clusterDetail
	found := false
	for _, item := range clusters {
		if item.ID == id {
			detail.Cluster, found = item, true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	rows, err := a.db.QueryContext(ctx, `SELECT `+clusterNodeColumns+` FROM cluster_nodes
		WHERE cluster_id = ? ORDER BY role, name COLLATE NOCASE`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	defer rows.Close()
	detail.Nodes = make([]clusterNodeRecord, 0, 8)
	for rows.Next() {
		node, err := scanClusterNode(rows)
		if err != nil {
			continue
		}
		detail.Nodes = append(detail.Nodes, node)
	}
	detail.Assets = a.clusterAssets(ctx, id, 100)
	detail.Findings = a.clusterFindingSummary(ctx, id)
	writeJSON(w, http.StatusOK, detail)
}

func (a *App) clusterAssets(ctx context.Context, clusterID int64, limit int) []clusterAsset {
	if limit <= 0 {
		limit = 100
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id, hostname, ip, os_family, agent_status, last_seen_at
		FROM assets WHERE cluster_id = ? ORDER BY hostname COLLATE NOCASE LIMIT ?`, clusterID, limit)
	if err != nil {
		return []clusterAsset{}
	}
	defer rows.Close()
	items := make([]clusterAsset, 0, limit)
	for rows.Next() {
		var item clusterAsset
		if err := rows.Scan(&item.ID, &item.Hostname, &item.IP, &item.OSFamily, &item.AgentStatus, &item.LastSeenAt); err != nil {
			continue
		}
		items = append(items, item)
	}
	return items
}

func (a *App) clusterFindingSummary(ctx context.Context, clusterID int64) map[string]int {
	summary := map[string]int{"total": 0, "P0": 0, "P1": 0, "P2": 0, "P3": 0}
	rows, err := a.db.QueryContext(ctx, `SELECT f.priority, COUNT(*) FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE a.cluster_id = ? AND f.status IN ('open','triaged','fixing') GROUP BY f.priority`, clusterID)
	if err != nil {
		return summary
	}
	defer rows.Close()
	for rows.Next() {
		var priority string
		var count int
		if err := rows.Scan(&priority, &count); err != nil {
			continue
		}
		summary[priority] = count
		summary["total"] += count
	}
	return summary
}

func (a *App) handleClusterUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	var current clusterRecord
	err = a.db.QueryRowContext(r.Context(), `SELECT id, name, environment, provider, region, description FROM clusters WHERE id = ?`, id).
		Scan(&current.ID, &current.Name, &current.Environment, &current.Provider, &current.Region, &current.Description)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取集群失败")
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Environment *string `json:"environment"`
		Provider    *string `json:"provider"`
		Region      *string `json:"region"`
		Description *string `json:"description"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if in.Name != nil {
		current.Name = strings.TrimSpace(*in.Name)
	}
	if in.Environment != nil {
		env := strings.ToLower(strings.TrimSpace(*in.Environment))
		if !validEnvironment(env) {
			writeErr(w, http.StatusBadRequest, "bad_request", "环境必须为 prod/staging/dev/test/other")
			return
		}
		current.Environment = env
	}
	if in.Provider != nil {
		current.Provider = strings.TrimSpace(*in.Provider)
	}
	if in.Region != nil {
		current.Region = strings.TrimSpace(*in.Region)
	}
	if in.Description != nil {
		current.Description = strings.TrimSpace(*in.Description)
	}
	if current.Name == "" || len(current.Name) > 80 {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群名称不能为空且不超过 80 字")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE clusters SET name=?, environment=?, provider=?, region=?,
		description=?, updated_at=? WHERE id=?`, current.Name, current.Environment, current.Provider,
		current.Region, current.Description, fmtT(nowT()), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新集群失败")
		return
	}
	a.audit(r, "cluster.update", current.Name, "更新集群信息")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleClusterDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	ctx := r.Context()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除集群失败")
		return
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `UPDATE assets SET cluster_id = 0 WHERE cluster_id = ?`, id)
	if _, err := tx.ExecContext(ctx, `DELETE FROM cluster_nodes WHERE cluster_id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除集群失败")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM clusters WHERE id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除集群失败")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除集群失败")
		return
	}
	a.audit(r, "cluster.delete", fmt.Sprintf("cluster/%d", id), "删除集群及其节点")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 节点 ----------

func validNodeRole(role string) bool {
	switch role {
	case "backend", "database", "cache", "proxy", "storage", "scan_target":
		return true
	}
	return false
}

func validCheckType(checkType string) bool {
	switch checkType {
	case "auto", "http", "tcp", "ssh", "ssh_file":
		return true
	}
	return false
}

func (a *App) handleClusterNodeCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	var in struct {
		Name       string `json:"name"`
		Role       string `json:"role"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		URL        string `json:"url"`
		SSHHostID  int64  `json:"sshHostId"`
		CheckType  string `json:"checkType"`
		Path       string `json:"path"`
		Note       string `json:"note"`
		DBEngine   string `json:"dbEngine"`
		DBName     string `json:"dbName"`
		DBUser     string `json:"dbUser"`
		DBPassword string `json:"dbPassword"`
		DBSSLMode  string `json:"dbSslMode"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	node, err := normalizeClusterNode(in.Name, in.Role, in.Host, in.Port, in.URL, in.SSHHostID, in.CheckType, in.Path, in.Note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	dbEngine, dbName, dbUser, dbSSL, err := normalizeDBConfig(in.DBEngine, in.DBName, in.DBUser, in.DBSSLMode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	sealed := ""
	if strings.TrimSpace(in.DBPassword) != "" {
		if sealed, err = a.sealSSHSecret(in.DBPassword); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "加密数据库凭据失败")
			return
		}
	}
	var clusterExists int
	if err := a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM clusters WHERE id = ?`, clusterID).Scan(&clusterExists); err != nil || clusterExists == 0 {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	now := fmtT(nowT())
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO cluster_nodes
		(cluster_id, name, role, host, port, url, ssh_host_id, check_type, path, note,
		 status, latency_ms, detail, checked_at, created_at, updated_at,
		 db_engine, db_name, db_user, db_secret, db_ssl_mode)
		VALUES(?,?,?,?,?,?,?,?,?,?,'unknown',0,'','',?,?,?,?,?,?,?)`,
		clusterID, node.Name, node.Role, node.Host, node.Port, node.URL, node.SSHHostID, node.CheckType,
		node.Path, node.Note, now, now, dbEngine, dbName, dbUser, sealed, dbSSL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建节点失败")
		return
	}
	id, _ := res.LastInsertId()
	a.audit(r, "cluster.node.create", node.Name, fmt.Sprintf("集群 #%d 新增节点 %s（%s）", clusterID, node.Name, node.Role))
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
}

func normalizeClusterNode(name, role, host string, port int, url string, sshHostID int64, checkType, path, note string) (clusterNodeRecord, error) {
	node := clusterNodeRecord{
		Name: strings.TrimSpace(name), Role: strings.ToLower(strings.TrimSpace(role)),
		Host: strings.TrimSpace(host), Port: port, URL: strings.TrimSpace(url), SSHHostID: sshHostID,
		CheckType: strings.ToLower(strings.TrimSpace(checkType)), Path: strings.TrimSpace(path), Note: strings.TrimSpace(note),
	}
	if node.Name == "" || len(node.Name) > 80 {
		return node, errors.New("节点名称不能为空且不超过 80 字")
	}
	if !validNodeRole(node.Role) {
		return node, errors.New("节点角色必须为 backend/database/cache/proxy/storage/scan_target")
	}
	if node.CheckType == "" {
		node.CheckType = "auto"
	}
	if !validCheckType(node.CheckType) {
		return node, errors.New("检查方式必须为 auto/http/tcp/ssh/ssh_file")
	}
	if node.Port < 0 || node.Port > 65535 {
		return node, errors.New("端口必须在 0-65535 之间")
	}
	if node.URL != "" && !strings.HasPrefix(node.URL, "http://") && !strings.HasPrefix(node.URL, "https://") {
		return node, errors.New("URL 必须以 http:// 或 https:// 开头")
	}
	if node.Path != "" && !strings.HasPrefix(node.Path, "/") {
		return node, errors.New("文件路径必须是绝对路径")
	}
	if node.SSHHostID < 0 {
		return node, errors.New("SSH 主机 ID 无效")
	}
	if node.Host == "" && node.URL == "" && node.SSHHostID == 0 {
		return node, errors.New("至少填写主机、URL 或关联 SSH 主机之一")
	}
	return node, nil
}

// normalizeDBConfig 校验数据库只读连接配置
func normalizeDBConfig(engine, name, user, sslMode string) (string, string, string, string, error) {
	engine = strings.ToLower(strings.TrimSpace(engine))
	switch engine {
	case "", "mysql", "postgresql":
	default:
		return "", "", "", "", errors.New("数据库类型必须为 mysql 或 postgresql")
	}
	sslMode = strings.ToLower(strings.TrimSpace(sslMode))
	if sslMode == "" {
		sslMode = "disable"
	}
	if sslMode != "disable" && sslMode != "require" {
		return "", "", "", "", errors.New("SSL 模式必须为 disable 或 require")
	}
	name = strings.TrimSpace(name)
	user = strings.TrimSpace(user)
	if len(name) > 128 || len(user) > 128 {
		return "", "", "", "", errors.New("数据库名或用户名过长")
	}
	if engine != "" && user == "" {
		return "", "", "", "", errors.New("配置数据库深检时必须填写只读用户名")
	}
	return engine, name, user, sslMode, nil
}

func (a *App) getClusterNode(ctx context.Context, id int64) (clusterNodeRecord, error) {
	row := a.db.QueryRowContext(ctx, `SELECT `+clusterNodeColumns+` FROM cluster_nodes WHERE id = ?`, id)
	return scanClusterNode(row)
}

func (a *App) handleClusterNodeUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "节点 ID 无效")
		return
	}
	current, err := a.getClusterNode(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "节点不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	var in struct {
		Name          *string `json:"name"`
		Role          *string `json:"role"`
		Host          *string `json:"host"`
		Port          *int    `json:"port"`
		URL           *string `json:"url"`
		SSHHostID     *int64  `json:"sshHostId"`
		CheckType     *string `json:"checkType"`
		Path          *string `json:"path"`
		Note          *string `json:"note"`
		DBEngine      *string `json:"dbEngine"`
		DBName        *string `json:"dbName"`
		DBUser        *string `json:"dbUser"`
		DBPassword    *string `json:"dbPassword"`
		DBSSLMode     *string `json:"dbSslMode"`
		ClearDBSecret bool    `json:"clearDbSecret"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if in.Name != nil {
		current.Name = *in.Name
	}
	if in.Role != nil {
		current.Role = *in.Role
	}
	if in.Host != nil {
		current.Host = *in.Host
	}
	if in.Port != nil {
		current.Port = *in.Port
	}
	if in.URL != nil {
		current.URL = *in.URL
	}
	if in.SSHHostID != nil {
		current.SSHHostID = *in.SSHHostID
	}
	if in.CheckType != nil {
		current.CheckType = *in.CheckType
	}
	if in.Path != nil {
		current.Path = *in.Path
	}
	if in.Note != nil {
		current.Note = *in.Note
	}
	if in.DBEngine != nil {
		current.DBEngine = *in.DBEngine
	}
	if in.DBName != nil {
		current.DBName = *in.DBName
	}
	if in.DBUser != nil {
		current.DBUser = *in.DBUser
	}
	if in.DBSSLMode != nil {
		current.DBSSLMode = *in.DBSSLMode
	}
	next, err := normalizeClusterNode(current.Name, current.Role, current.Host, current.Port, current.URL,
		current.SSHHostID, current.CheckType, current.Path, current.Note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	dbEngine, dbName, dbUser, dbSSL, err := normalizeDBConfig(current.DBEngine, current.DBName, current.DBUser, current.DBSSLMode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	sealed := current.dbSecret
	if in.ClearDBSecret || dbEngine == "" {
		sealed = ""
	}
	if in.DBPassword != nil && strings.TrimSpace(*in.DBPassword) != "" {
		if sealed, err = a.sealSSHSecret(*in.DBPassword); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "加密数据库凭据失败")
			return
		}
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE cluster_nodes SET name=?, role=?, host=?, port=?, url=?,
		ssh_host_id=?, check_type=?, path=?, note=?, updated_at=?,
		db_engine=?, db_name=?, db_user=?, db_secret=?, db_ssl_mode=? WHERE id=?`,
		next.Name, next.Role, next.Host, next.Port, next.URL, next.SSHHostID, next.CheckType,
		next.Path, next.Note, fmtT(nowT()), dbEngine, dbName, dbUser, sealed, dbSSL, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新节点失败")
		return
	}
	a.audit(r, "cluster.node.update", next.Name, "更新集群节点")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleClusterNodeDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "节点 ID 无效")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM cluster_nodes WHERE id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除节点失败")
		return
	}
	a.audit(r, "cluster.node.delete", fmt.Sprintf("node/%d", id), "删除集群节点")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 健康检查 ----------

func (a *App) effectiveCheckType(node clusterNodeRecord) string {
	if node.CheckType != "" && node.CheckType != "auto" {
		return node.CheckType
	}
	switch node.Role {
	case "backend":
		return "http"
	case "database":
		if node.SSHHostID > 0 && node.Path != "" {
			return "ssh_file"
		}
		return "tcp"
	case "scan_target":
		return "ssh"
	default:
		return "tcp"
	}
}

func (a *App) checkClusterNode(ctx context.Context, node clusterNodeRecord) (string, int64, string) {
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	started := time.Now()
	checkType := a.effectiveCheckType(node)
	if checkType == "tcp" && node.DBEngine != "" {
		return a.checkClusterDatabase(checkCtx, node)
	}
	switch checkType {
	case "http":
		target := node.URL
		if target == "" {
			if node.Port <= 0 {
				return "failed", 0, "HTTP 检查需要 URL 或端口"
			}
			target = fmt.Sprintf("http://%s/api/v1/healthz", net.JoinHostPort(node.Host, strconv.Itoa(node.Port)))
		}
		client := &http.Client{Timeout: 8 * time.Second}
		req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, target, nil)
		if err != nil {
			return "failed", 0, "URL 无效"
		}
		resp, err := client.Do(req)
		if err != nil {
			return "failed", time.Since(started).Milliseconds(), truncateRunes(err.Error(), 200)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		latency := time.Since(started).Milliseconds()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return "ok", latency, fmt.Sprintf("HTTP %d · %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return "failed", latency, fmt.Sprintf("HTTP %d", resp.StatusCode)
	case "tcp":
		if node.Port <= 0 || node.Host == "" {
			return "failed", 0, "TCP 检查需要主机与端口"
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.Host, strconv.Itoa(node.Port)), 6*time.Second)
		if err != nil {
			return "failed", time.Since(started).Milliseconds(), truncateRunes(err.Error(), 200)
		}
		_ = conn.Close()
		return "ok", time.Since(started).Milliseconds(), "TCP 连接成功"
	case "ssh", "ssh_file":
		if node.SSHHostID <= 0 {
			return "failed", 0, "SSH 检查需要关联已保存的 SSH 主机"
		}
		host, err := a.getSSHHost(checkCtx, node.SSHHostID)
		if err != nil {
			return "failed", 0, "关联的 SSH 主机不存在"
		}
		client, _, release, err := a.acquireSSHHost(checkCtx, host)
		if err != nil {
			return "failed", time.Since(started).Milliseconds(), truncateRunes(err.Error(), 200)
		}
		defer release()
		if checkType == "ssh" {
			output, _, err := runSSHCommand(checkCtx, client, "echo vulnagent-ok", 5*time.Second)
			latency := time.Since(started).Milliseconds()
			if err != nil || !strings.Contains(output, "vulnagent-ok") {
				return "failed", latency, "SSH 命令执行失败"
			}
			return "ok", latency, "SSH 连接与命令执行正常"
		}
		if node.Path == "" {
			return "failed", 0, "文件检查需要绝对路径"
		}
		script := fmt.Sprintf(`p=%s
if [ ! -f "$p" ]; then echo "MISSING"; exit 3; fi
sz=$(stat -c %%s "$p" 2>/dev/null || wc -c < "$p")
echo "SIZE|$sz"
df -Pk "$(dirname "$p")" 2>/dev/null | awk 'NR==2 {print "DISK|"$2"|"$3"|"$4"|"$5}'`,
			shellQuote(node.Path))
		output, _, err := runSSHCommand(checkCtx, client, script, 10*time.Second)
		latency := time.Since(started).Milliseconds()
		if err != nil || strings.Contains(output, "MISSING") {
			return "failed", latency, "文件不存在或无法读取"
		}
		detail := "文件检查成功"
		for _, line := range strings.Split(output, "\n") {
			parts := strings.Split(strings.TrimSpace(line), "|")
			if len(parts) == 2 && parts[0] == "SIZE" {
				if size, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					detail = fmt.Sprintf("文件 %.1f MB", float64(size)/(1<<20))
				}
			}
			if len(parts) == 5 && parts[0] == "DISK" {
				detail += fmt.Sprintf("；分区使用 %s", parts[4])
			}
		}
		return "ok", latency, detail
	default:
		return "failed", 0, "不支持的检查方式"
	}
}

func (a *App) runClusterNodeCheck(ctx context.Context, node clusterNodeRecord) clusterNodeRecord {
	status, latency, detail := a.checkClusterNode(ctx, node)
	node.Status, node.LatencyMs, node.Detail = status, latency, truncateRunes(detail, 300)
	node.CheckedAt = fmtT(nowT())
	if node.DBEngine != "" {
		node.DBDetail = node.Detail
		node.DBCheckedAt = node.CheckedAt
		_, _ = a.db.ExecContext(ctx, `UPDATE cluster_nodes SET status=?, latency_ms=?, detail=?, checked_at=?,
			db_detail=?, db_checked_at=? WHERE id=?`,
			node.Status, node.LatencyMs, node.Detail, node.CheckedAt, node.DBDetail, node.DBCheckedAt, node.ID)
		return node
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE cluster_nodes SET status=?, latency_ms=?, detail=?, checked_at=? WHERE id=?`,
		node.Status, node.LatencyMs, node.Detail, node.CheckedAt, node.ID)
	return node
}

func (a *App) handleClusterNodeCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "节点 ID 无效")
		return
	}
	node, err := a.getClusterNode(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "节点不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	node = a.runClusterNodeCheck(r.Context(), node)
	a.audit(r, "cluster.node.check", node.Name, fmt.Sprintf("%s：%s", node.Status, truncateRunes(node.Detail, 120)))
	writeJSON(w, http.StatusOK, node)
}

func (a *App) handleClusterCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT `+clusterNodeColumns+` FROM cluster_nodes WHERE cluster_id = ?`, clusterID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	nodes := make([]clusterNodeRecord, 0, 8)
	for rows.Next() {
		node, err := scanClusterNode(rows)
		if err == nil {
			nodes = append(nodes, node)
		}
	}
	rows.Close()
	for index := range nodes {
		nodes[index] = a.runClusterNodeCheck(r.Context(), nodes[index])
	}
	a.audit(r, "cluster.check", fmt.Sprintf("cluster/%d", clusterID), fmt.Sprintf("检查 %d 个节点", len(nodes)))
	writeJSON(w, http.StatusOK, map[string]any{"items": nodes})
}

// ---------- 扫描 ----------

func (a *App) scanClusterNode(ctx context.Context, node clusterNodeRecord, actor string) (sshHostScanResult, error) {
	if node.SSHHostID <= 0 {
		return sshHostScanResult{}, &sshScanFailure{Status: 400, Code: "not_scannable",
			Message: "该节点未关联 SSH 主机，无法做只读漏洞扫描"}
	}
	host, err := a.getSSHHost(ctx, node.SSHHostID)
	if err != nil {
		return sshHostScanResult{}, &sshScanFailure{Status: 400, Code: "not_scannable", Message: "关联的 SSH 主机不存在"}
	}
	result, err := a.scanSSHHost(ctx, host, actor)
	if err != nil {
		return result, err
	}
	if result.AssetID > 0 {
		_, _ = a.db.ExecContext(ctx, `UPDATE assets SET cluster_id = ? WHERE id = ?`, node.ClusterID, result.AssetID)
	}
	return result, nil
}

func (a *App) handleClusterNodeScan(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "节点 ID 无效")
		return
	}
	node, err := a.getClusterNode(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "节点不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	result, err := a.scanClusterNode(ctx, node, u.Username)
	if err != nil {
		if failure, ok := err.(*sshScanFailure); ok {
			writeErr(w, failure.Status, failure.Code, failure.Message)
			return
		}
		writeErr(w, http.StatusBadGateway, "scan_failed", err.Error())
		return
	}
	a.audit(r, "cluster.scan", node.Name, fmt.Sprintf("集群 #%d 节点扫描：%d 个组件，新增 %d", node.ClusterID, result.Components, result.Created))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node": node, "result": result})
}

func (a *App) handleClusterScan(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT `+clusterNodeColumns+` FROM cluster_nodes WHERE cluster_id = ?`, clusterID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取节点失败")
		return
	}
	nodes := make([]clusterNodeRecord, 0, 8)
	for rows.Next() {
		node, err := scanClusterNode(rows)
		if err == nil {
			nodes = append(nodes, node)
		}
	}
	rows.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	type scanItem struct {
		NodeID     int64  `json:"nodeId"`
		NodeName   string `json:"nodeName"`
		Status     string `json:"status"`
		Message    string `json:"message"`
		AssetID    int64  `json:"assetId,omitempty"`
		Components int    `json:"components,omitempty"`
		Created    int    `json:"created,omitempty"`
		Updated    int    `json:"updated,omitempty"`
	}
	items := make([]scanItem, 0, len(nodes))
	okCount := 0
	for _, node := range nodes {
		item := scanItem{NodeID: node.ID, NodeName: node.Name}
		if node.SSHHostID <= 0 {
			item.Status, item.Message = "skipped", "未关联 SSH 主机"
			items = append(items, item)
			continue
		}
		result, err := a.scanClusterNode(ctx, node, u.Username)
		if err != nil {
			item.Status, item.Message = "failed", truncateRunes(err.Error(), 200)
			items = append(items, item)
			continue
		}
		item.Status = "ok"
		item.AssetID = result.AssetID
		item.Components = result.Components
		item.Created = result.Created
		item.Updated = result.Updated
		item.Message = fmt.Sprintf("%d 个组件，新增 %d / 更新 %d 条漏洞", result.Components, result.Created, result.Updated)
		okCount++
		items = append(items, item)
	}
	a.audit(r, "cluster.scan", fmt.Sprintf("cluster/%d", clusterID),
		fmt.Sprintf("扫描 %d 个节点，成功 %d 个", len(items), okCount))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "okCount": okCount, "total": len(items)})
}

// handleClusterAssetsLink 把已有资产手动归入集群（operator+）。
func (a *App) handleClusterAssetsLink(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	var in struct {
		AssetIDs []int64 `json:"assetIds"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if len(in.AssetIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "请选择至少一个资产")
		return
	}
	if len(in.AssetIDs) > 200 {
		writeErr(w, http.StatusBadRequest, "bad_request", "单次最多关联 200 个资产")
		return
	}
	var clusterExists int
	if err := a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM clusters WHERE id = ?`, clusterID).Scan(&clusterExists); err != nil || clusterExists == 0 {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	placeholders := make([]string, 0, len(in.AssetIDs))
	args := make([]any, 0, len(in.AssetIDs)+1)
	args = append(args, clusterID)
	for _, assetID := range in.AssetIDs {
		placeholders = append(placeholders, "?")
		args = append(args, assetID)
	}
	query := fmt.Sprintf(`UPDATE assets SET cluster_id = ? WHERE id IN (%s)`, strings.Join(placeholders, ","))
	if _, err := a.db.ExecContext(r.Context(), query, args...); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "关联资产失败")
		return
	}
	a.audit(r, "cluster.assets.link", fmt.Sprintf("cluster/%d", clusterID), fmt.Sprintf("关联 %d 个资产", len(in.AssetIDs)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(in.AssetIDs)})
}

// handleClusterAssetUnlink 解除单个资产与集群的关联（operator+）。
func (a *App) handleClusterAssetUnlink(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	assetID, err := strconv.ParseInt(r.PathValue("assetId"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "资产 ID 无效")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE assets SET cluster_id = 0 WHERE id = ? AND cluster_id = ?`,
		assetID, clusterID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "解除关联失败")
		return
	}
	a.audit(r, "cluster.assets.unlink", fmt.Sprintf("cluster/%d", clusterID), fmt.Sprintf("解除资产 #%d", assetID))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
