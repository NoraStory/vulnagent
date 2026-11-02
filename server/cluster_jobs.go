package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// clusterJobItem 单个节点的执行进度
type clusterJobItem struct {
	NodeID     int64  `json:"nodeId"`
	NodeName   string `json:"nodeName"`
	Status     string `json:"status"` // queued/running/ok/failed/skipped/canceled
	Message    string `json:"message"`
	LatencyMs  int64  `json:"latencyMs,omitempty"`
	AssetID    int64  `json:"assetId,omitempty"`
	Components int    `json:"components,omitempty"`
	Created    int    `json:"created,omitempty"`
	Updated    int    `json:"updated,omitempty"`
}

// clusterJobRecord 一次集群级检查或扫描任务
type clusterJobRecord struct {
	ID         string           `json:"id"`
	ClusterID  int64            `json:"clusterId"`
	Kind       string           `json:"kind"`   // check/scan
	Status     string           `json:"status"` // queued/running/succeeded/partial/failed/canceled
	Total      int              `json:"total"`
	Done       int              `json:"done"`
	Failed     int              `json:"failed"`
	Message    string           `json:"message"`
	Items      []clusterJobItem `json:"items"`
	CreatedBy  string           `json:"createdBy"`
	CreatedAt  string           `json:"createdAt"`
	StartedAt  string           `json:"startedAt"`
	FinishedAt string           `json:"finishedAt"`
}

const clusterJobColumns = `id, cluster_id, kind, status, total, done, failed, message, items,
	created_by, created_at, started_at, finished_at`

func scanClusterJob(row interface{ Scan(dest ...any) error }) (clusterJobRecord, error) {
	var job clusterJobRecord
	var raw string
	err := row.Scan(&job.ID, &job.ClusterID, &job.Kind, &job.Status, &job.Total, &job.Done, &job.Failed,
		&job.Message, &raw, &job.CreatedBy, &job.CreatedAt, &job.StartedAt, &job.FinishedAt)
	if err != nil {
		return job, err
	}
	job.Items = make([]clusterJobItem, 0, 8)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &job.Items)
	}
	return job, nil
}

func (a *App) clusterJobByID(ctx context.Context, id string) (clusterJobRecord, error) {
	return scanClusterJob(a.db.QueryRowContext(ctx, `SELECT `+clusterJobColumns+` FROM cluster_jobs WHERE id = ?`, id))
}

func (a *App) clusterJobsByCluster(ctx context.Context, clusterID int64, limit int) ([]clusterJobRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := a.db.QueryContext(ctx, `SELECT `+clusterJobColumns+` FROM cluster_jobs
		WHERE cluster_id = ? ORDER BY created_at DESC LIMIT ?`, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]clusterJobRecord, 0, limit)
	for rows.Next() {
		job, err := scanClusterJob(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, job)
	}
	return items, rows.Err()
}

// startClusterJob 创建并异步执行集群检查/扫描任务
func (a *App) startClusterJob(ctx context.Context, clusterID int64, kind, actor string) (clusterJobRecord, error) {
	var exists int
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clusters WHERE id = ?`, clusterID).Scan(&exists); err != nil {
		return clusterJobRecord{}, err
	}
	if exists == 0 {
		return clusterJobRecord{}, sql.ErrNoRows
	}
	rows, err := a.db.QueryContext(ctx, `SELECT `+clusterNodeColumns+` FROM cluster_nodes WHERE cluster_id = ? ORDER BY id`, clusterID)
	if err != nil {
		return clusterJobRecord{}, err
	}
	nodes := make([]clusterNodeRecord, 0, 8)
	for rows.Next() {
		node, err := scanClusterNode(rows)
		if err != nil {
			rows.Close()
			return clusterJobRecord{}, fmt.Errorf("读取节点失败：%w", err)
		}
		nodes = append(nodes, node)
	}
	rows.Close()
	if len(nodes) == 0 {
		return clusterJobRecord{}, errClusterJobEmpty
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return clusterJobRecord{}, err
	}
	items := make([]clusterJobItem, len(nodes))
	for i, node := range nodes {
		items[i] = clusterJobItem{NodeID: node.ID, NodeName: node.Name, Status: "queued"}
	}
	raw, _ := json.Marshal(items)
	job := clusterJobRecord{
		ID:        "CJOB-" + hex.EncodeToString(idBytes),
		ClusterID: clusterID,
		Kind:      kind,
		Status:    "queued",
		Total:     len(nodes),
		Items:     items,
		CreatedBy: actor,
		CreatedAt: fmtT(nowT()),
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO cluster_jobs
		(id, cluster_id, kind, status, total, done, failed, message, items, created_by, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.ClusterID, job.Kind, job.Status, job.Total, 0, 0, "", string(raw), job.CreatedBy, job.CreatedAt); err != nil {
		return clusterJobRecord{}, err
	}

	jobCtx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	a.clusterJobMu.Lock()
	if a.clusterJobCancels == nil {
		a.clusterJobCancels = make(map[string]context.CancelFunc)
	}
	a.clusterJobCancels[job.ID] = cancel
	a.clusterJobMu.Unlock()
	go a.runClusterJob(jobCtx, job, nodes)
	return job, nil
}

var errClusterJobEmpty = errors.New("集群还没有节点，无法执行检查或扫描")

func (a *App) finishClusterJobCancels(id string) {
	a.clusterJobMu.Lock()
	if cancel, ok := a.clusterJobCancels[id]; ok {
		cancel()
		delete(a.clusterJobCancels, id)
	}
	a.clusterJobMu.Unlock()
}

// runClusterJob 以 3 个并发执行节点任务，每完成一个节点立即落库进度
func (a *App) runClusterJob(ctx context.Context, job clusterJobRecord, nodes []clusterNodeRecord) {
	defer a.finishClusterJobCancels(job.ID)
	execCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	startedAt := fmtT(nowT())
	if _, err := a.db.Exec(`UPDATE cluster_jobs SET status='running', started_at=?, message=? WHERE id=?`,
		startedAt, "任务执行中", job.ID); err != nil {
		slog.Warn("更新集群任务状态失败", "job", job.ID, "err", err)
	}

	items := make([]clusterJobItem, len(nodes))
	for i, node := range nodes {
		items[i] = clusterJobItem{NodeID: node.ID, NodeName: node.Name, Status: "queued"}
	}
	var mu sync.Mutex
	done, failed := 0, 0
	persist := func() {
		mu.Lock()
		raw, _ := json.Marshal(items)
		_, err := a.db.Exec(`UPDATE cluster_jobs SET done=?, failed=?, items=? WHERE id=?`,
			done, failed, string(raw), job.ID)
		mu.Unlock()
		if err != nil {
			slog.Warn("写入集群任务进度失败", "job", job.ID, "err", err)
		}
	}
	persist()

	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for index := range nodes {
		if execCtx.Err() != nil {
			break
		}
		sem <- struct{}{}
		if execCtx.Err() != nil {
			<-sem
			break
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			node := nodes[idx]
			mu.Lock()
			items[idx].Status = "running"
			mu.Unlock()

			item := clusterJobItem{NodeID: node.ID, NodeName: node.Name}
			if job.Kind == "scan" {
				a.runClusterScanItem(execCtx, node, job.CreatedBy, &item)
			} else {
				updated := a.runClusterNodeCheck(execCtx, node)
				item.Status = updated.Status
				item.Message = updated.Detail
				item.LatencyMs = updated.LatencyMs
			}
			if execCtx.Err() != nil {
				item.Status = "canceled"
				item.Message = "任务已取消"
			}
			mu.Lock()
			items[idx] = item
			done++
			if item.Status == "failed" {
				failed++
			}
			mu.Unlock()
			persist()
		}(index)
	}
	wg.Wait()

	if execCtx.Err() != nil {
		mu.Lock()
		for i := range items {
			if items[i].Status == "queued" || items[i].Status == "running" {
				items[i].Status = "canceled"
				items[i].Message = "任务已取消"
			}
		}
		mu.Unlock()
	}
	persist()

	okCount, skipCount, failedCount := 0, 0, 0
	mu.Lock()
	for _, item := range items {
		switch item.Status {
		case "ok":
			okCount++
		case "skipped", "canceled":
			skipCount++
		case "failed":
			failedCount++
		}
	}
	mu.Unlock()

	status, message := "succeeded", ""
	if execCtx.Err() != nil {
		status = "canceled"
		message = fmt.Sprintf("任务已取消：完成 %d/%d，失败 %d", okCount, len(items), failedCount)
	} else if failedCount == len(items) {
		status = "failed"
		if job.Kind == "scan" {
			message = fmt.Sprintf("扫描全部失败：%d 个节点", failedCount)
		} else {
			message = fmt.Sprintf("检查全部失败：%d 个节点", failedCount)
		}
	} else if failedCount > 0 {
		status = "partial"
		message = fmt.Sprintf("部分完成：成功 %d，失败 %d，跳过 %d", okCount, failedCount, skipCount)
	} else if job.Kind == "scan" {
		message = fmt.Sprintf("扫描完成：成功 %d，跳过 %d", okCount, skipCount)
	} else {
		message = fmt.Sprintf("检查完成：正常 %d，跳过 %d", okCount, skipCount)
	}
	finishedAt := fmtT(nowT())
	if _, err := a.db.Exec(`UPDATE cluster_jobs SET status=?, message=?, finished_at=? WHERE id=?`,
		status, message, finishedAt, job.ID); err != nil {
		slog.Warn("写入集群任务结果失败", "job", job.ID, "err", err)
	}
	a.auditAs(job.CreatedBy, "user", "", "", "cluster.job."+job.Kind, job.ID,
		fmt.Sprintf("集群 #%d %s，%s", job.ClusterID, job.Kind, message))
	slog.Info("集群任务完成", "job", job.ID, "cluster", job.ClusterID, "kind", job.Kind, "status", status)
}

func (a *App) runClusterScanItem(ctx context.Context, node clusterNodeRecord, actor string, item *clusterJobItem) {
	if node.SSHHostID <= 0 {
		item.Status, item.Message = "skipped", "未关联 SSH 主机"
		return
	}
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, err := a.scanClusterNode(scanCtx, node, actor)
	if err != nil {
		item.Status = "failed"
		if failure, ok := err.(*sshScanFailure); ok {
			item.Message = failure.Message
		} else {
			item.Message = truncateRunes(err.Error(), 200)
		}
		return
	}
	item.Status = "ok"
	item.AssetID = result.AssetID
	item.Components = result.Components
	item.Created = result.Created
	item.Updated = result.Updated
	item.Message = fmt.Sprintf("%d 个组件，新增 %d / 更新 %d 条漏洞", result.Components, result.Created, result.Updated)
}

// ---------- HTTP ----------

func (a *App) handleClusterJobCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	kind := in.Kind
	if kind != "check" && kind != "scan" {
		writeErr(w, http.StatusBadRequest, "bad_request", "kind 仅支持 check 或 scan")
		return
	}
	job, err := a.startClusterJob(r.Context(), clusterID, kind, u.Username)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	if errors.Is(err, errClusterJobEmpty) {
		writeErr(w, http.StatusBadRequest, "empty_cluster", err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建任务失败")
		return
	}
	a.audit(r, "cluster.job."+kind, job.ID, fmt.Sprintf("集群 #%d 创建%s任务（%d 个节点）",
		clusterID, map[string]string{"check": "检查", "scan": "扫描"}[kind], job.Total))
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (a *App) handleClusterJobs(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := a.clusterJobsByCluster(r.Context(), clusterID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取任务失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleClusterJobDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	job, err := a.clusterJobByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "任务不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取任务失败")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *App) handleClusterJobCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	job, err := a.clusterJobByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "任务不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取任务失败")
		return
	}
	switch job.Status {
	case "succeeded", "partial", "failed", "canceled":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": job.Status})
		return
	}
	a.finishClusterJobCancels(job.ID)
	if _, err := a.db.ExecContext(r.Context(), `UPDATE cluster_jobs SET status='canceled', finished_at=?, message=?
		WHERE id=? AND status IN ('queued','running')`, fmtT(nowT()), "任务已取消", job.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "取消任务失败")
		return
	}
	a.audit(r, "cluster.job.cancel", job.ID, "取消集群任务")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "canceled"})
}

// interruptClusterJobs 进程重启时把未完成任务标记为中断
func (a *App) interruptClusterJobs() {
	res, err := a.db.Exec(`UPDATE cluster_jobs SET status='canceled', message='服务重启，任务中断', finished_at=?
		WHERE status IN ('queued','running')`, fmtT(nowT()))
	if err != nil {
		slog.Warn("清理中断的集群任务失败", "err", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("已标记中断的集群任务", "count", n)
	}
}
