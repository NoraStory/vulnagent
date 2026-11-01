package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// DiscoveryRepo 网段发现任务与候选资产的 SQLite 仓储
type DiscoveryRepo struct {
	db *sql.DB
}

// NewDiscoveryRepo 构造发现仓储
func NewDiscoveryRepo(db *sql.DB) *DiscoveryRepo { return &DiscoveryRepo{db: db} }

var _ ports.DiscoveryRepository = (*DiscoveryRepo)(nil)

const discoveryJobSelect = `SELECT id, name, cidrs, ports, status, total, scanned, found, options,
	cancel_requested, created_by, created_at, started_at, finished_at, error FROM discovery_jobs`

func scanDiscoveryJob(sc interface{ Scan(...any) error }) (ports.DiscoveryJob, error) {
	var job ports.DiscoveryJob
	var cancel int
	err := sc.Scan(&job.ID, &job.Name, &job.CIDRs, &job.Ports, &job.Status, &job.Total, &job.Scanned,
		&job.Found, &job.Options, &cancel, &job.CreatedBy, &job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.Error)
	job.CancelRequested = cancel != 0
	return job, err
}

// CreateJob 写入一条待执行的发现任务
func (r *DiscoveryRepo) CreateJob(ctx context.Context, job ports.DiscoveryJob) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO discovery_jobs(name, cidrs, ports, status, total, scanned,
		found, options, cancel_requested, created_by, created_at, started_at, finished_at, error)
		VALUES(?,?,?,?,?,?,?,?,0,?,?,?,?,?)`,
		job.Name, job.CIDRs, job.Ports, job.Status, job.Total, job.Scanned, job.Found,
		job.Options, job.CreatedBy, job.CreatedAt, job.StartedAt, job.FinishedAt, job.Error)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetJob 按 ID 读取任务
func (r *DiscoveryRepo) GetJob(ctx context.Context, id int64) (ports.DiscoveryJob, error) {
	job, err := scanDiscoveryJob(r.db.QueryRowContext(ctx, discoveryJobSelect+" WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.DiscoveryJob{}, ports.ErrNotFound
	}
	return job, err
}

// ListJobs 返回任务列表与总数
func (r *DiscoveryRepo) ListJobs(ctx context.Context, status string, limit, offset int) ([]ports.DiscoveryJob, int, error) {
	where := "1=1"
	args := []any{}
	if status = strings.TrimSpace(status); status != "" {
		where = "status = ?"
		args = append(args, status)
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM discovery_jobs WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := r.db.QueryContext(ctx, discoveryJobSelect+" WHERE "+where+" ORDER BY id DESC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ports.DiscoveryJob, 0, limit)
	for rows.Next() {
		job, err := scanDiscoveryJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, job)
	}
	return out, total, rows.Err()
}

// CountRunningJobs 返回 pending/running 任务数，用于限制并发任务
func (r *DiscoveryRepo) CountRunningJobs(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_jobs WHERE status IN ('pending','running')`).Scan(&count)
	return count, err
}

// CountJobsSince 返回某时间之后创建的任务数，用于小时级限流
func (r *DiscoveryRepo) CountJobsSince(ctx context.Context, since string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_jobs WHERE created_at >= ?`, since).Scan(&count)
	return count, err
}

// UpdateJobProgress 更新扫描进度
func (r *DiscoveryRepo) UpdateJobProgress(ctx context.Context, id int64, scanned, found int) error {
	_, err := r.db.ExecContext(ctx, `UPDATE discovery_jobs SET scanned = ?, found = ? WHERE id = ?`, scanned, found, id)
	return err
}

// FinishJob 结束任务并写入状态与错误信息
func (r *DiscoveryRepo) FinishJob(ctx context.Context, id int64, status, errText, finishedAt string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE discovery_jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?`,
		status, errText, finishedAt, id)
	return err
}

// RequestCancel 标记取消请求；执行中的任务由 runner 轮询后终止
func (r *DiscoveryRepo) RequestCancel(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `UPDATE discovery_jobs SET cancel_requested = 1 WHERE id = ? AND status IN ('pending','running')`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// CancelRequested 查询任务是否已被请求取消
func (r *DiscoveryRepo) CancelRequested(ctx context.Context, id int64) (bool, error) {
	var flag int
	if err := r.db.QueryRowContext(ctx, `SELECT cancel_requested FROM discovery_jobs WHERE id = ?`, id).Scan(&flag); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ports.ErrNotFound
		}
		return false, err
	}
	return flag != 0, nil
}

// InterruptUnfinishedJobs 服务启动时把残留任务标记为失败
func (r *DiscoveryRepo) InterruptUnfinishedJobs(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE discovery_jobs SET status = 'failed', error = '服务重启中断', finished_at = ?
		WHERE status IN ('pending','running')`, nowString())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// InsertCandidate 写入候选资产，同一任务内按 IP 去重
func (r *DiscoveryRepo) InsertCandidate(ctx context.Context, c ports.DiscoveryCandidate) (int64, error) {
	_, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO discovery_candidates(job_id, ip, hostname, mac,
		open_ports, services, evidence, matched_asset_id, decision, confidence, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		c.JobID, c.IP, c.Hostname, c.MAC, c.OpenPorts, c.Services, c.Evidence,
		c.MatchedAssetID, c.Decision, c.Confidence, c.CreatedAt)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM discovery_candidates WHERE job_id = ? AND ip = ?`,
		c.JobID, c.IP).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

const discoveryCandidateSelect = `SELECT id, job_id, ip, hostname, mac, open_ports, services, evidence,
	matched_asset_id, decision, confidence, decided_by, decided_at, asset_id, created_at FROM discovery_candidates`

func scanDiscoveryCandidate(sc interface{ Scan(...any) error }) (ports.DiscoveryCandidate, error) {
	var c ports.DiscoveryCandidate
	err := sc.Scan(&c.ID, &c.JobID, &c.IP, &c.Hostname, &c.MAC, &c.OpenPorts, &c.Services, &c.Evidence,
		&c.MatchedAssetID, &c.Decision, &c.Confidence, &c.DecidedBy, &c.DecidedAt, &c.AssetID, &c.CreatedAt)
	return c, err
}

// GetCandidate 按 ID 读取候选
func (r *DiscoveryRepo) GetCandidate(ctx context.Context, id int64) (ports.DiscoveryCandidate, error) {
	c, err := scanDiscoveryCandidate(r.db.QueryRowContext(ctx, discoveryCandidateSelect+" WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.DiscoveryCandidate{}, ports.ErrNotFound
	}
	return c, err
}

// ListCandidates 返回候选资产列表与总数
func (r *DiscoveryRepo) ListCandidates(ctx context.Context, filter ports.DiscoveryCandidateFilter, limit, offset int) ([]ports.DiscoveryCandidate, int, error) {
	conds := []string{"1=1"}
	args := []any{}
	if filter.JobID > 0 {
		conds = append(conds, "job_id = ?")
		args = append(args, filter.JobID)
	}
	if decision := strings.TrimSpace(filter.Decision); decision != "" && decision != "all" {
		conds = append(conds, "decision = ?")
		args = append(args, decision)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(ip LIKE ? OR hostname LIKE ?)")
		args = append(args, like, like)
	}
	where := strings.Join(conds, " AND ")
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM discovery_candidates WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := r.db.QueryContext(ctx, discoveryCandidateSelect+" WHERE "+where+" ORDER BY id DESC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ports.DiscoveryCandidate, 0, limit)
	for rows.Next() {
		c, err := scanDiscoveryCandidate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// SetCandidateDecision 更新候选处置结果
func (r *DiscoveryRepo) SetCandidateDecision(ctx context.Context, id int64, decision string, assetID int64, actor, decidedAt string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE discovery_candidates SET decision = ?, asset_id = ?, decided_by = ?, decided_at = ?
		WHERE id = ?`, decision, assetID, actor, decidedAt, id)
	return err
}

// CountCandidates 按处置状态统计候选数量
func (r *DiscoveryRepo) CountCandidates(ctx context.Context, jobID int64) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT decision, COUNT(*) FROM discovery_candidates WHERE job_id = ? GROUP BY decision`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var decision string
		var count int
		if err := rows.Scan(&decision, &count); err != nil {
			return nil, err
		}
		out[decision] = count
	}
	return out, rows.Err()
}
