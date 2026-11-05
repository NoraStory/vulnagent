package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// JobRepo 主机作业的 SQLite 仓储
type JobRepo struct {
	db *sql.DB
}

// NewJobRepo 构造作业仓储
func NewJobRepo(db *sql.DB) *JobRepo { return &JobRepo{db: db} }

var _ ports.JobRepository = (*JobRepo)(nil)

const jobSelect = `SELECT host_jobs.id, host_jobs.asset_id, host_jobs.action, host_jobs.params,
	host_jobs.risk, host_jobs.status, host_jobs.requested_by, host_jobs.approval_id,
	host_jobs.attempts, host_jobs.max_attempts, host_jobs.next_run_at, host_jobs.output,
	host_jobs.error, host_jobs.exit_code, host_jobs.created_at, host_jobs.started_at,
	host_jobs.finished_at
	FROM host_jobs`

func scanJob(sc interface{ Scan(...any) error }) (ports.HostJob, error) {
	var j ports.HostJob
	err := sc.Scan(&j.ID, &j.AssetID, &j.Action, &j.Params, &j.Risk, &j.Status, &j.RequestedBy,
		&j.ApprovalID, &j.Attempts, &j.MaxAttempts, &j.NextRunAt, &j.Output, &j.Error,
		&j.ExitCode, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	return j, err
}

// Create 写入作业
func (r *JobRepo) Create(ctx context.Context, job ports.HostJob) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO host_jobs(id, asset_id, action, params, risk, status,
		requested_by, approval_id, idempotency_key, attempts, max_attempts, next_run_at, output, error,
		exit_code, created_at, started_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.AssetID, job.Action, job.Params, job.Risk, job.Status, job.RequestedBy,
		job.ApprovalID, job.IdempotencyKey, job.Attempts, job.MaxAttempts, job.NextRunAt, job.Output,
		job.Error, job.ExitCode, job.CreatedAt, job.StartedAt, job.FinishedAt)
	return err
}

// CreateIdempotent 在同一写事务内完成窗口去重与插入；失败、取消和过期记录不占用幂等键。
func (r *JobRepo) CreateIdempotent(ctx context.Context, job ports.HostJob, since string) (ports.HostJob, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.HostJob{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := scanJob(tx.QueryRowContext(ctx, jobSelect+`
		WHERE idempotency_key = ? AND created_at >= ? AND status IN ('pending','running','succeeded')
		ORDER BY created_at DESC LIMIT 1`, job.IdempotencyKey, since))
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ports.HostJob{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_jobs(id, asset_id, action, params, risk, status,
		requested_by, approval_id, idempotency_key, attempts, max_attempts, next_run_at, output, error,
		exit_code, created_at, started_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.AssetID, job.Action, job.Params, job.Risk, job.Status, job.RequestedBy,
		job.ApprovalID, job.IdempotencyKey, job.Attempts, job.MaxAttempts, job.NextRunAt, job.Output,
		job.Error, job.ExitCode, job.CreatedAt, job.StartedAt, job.FinishedAt); err != nil {
		return ports.HostJob{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ports.HostJob{}, false, err
	}
	return job, true, nil
}

// ByID 按 ID 读取作业
func (r *JobRepo) ByID(ctx context.Context, id string) (ports.HostJob, bool, error) {
	job, err := scanJob(r.db.QueryRowContext(ctx, jobSelect+` WHERE host_jobs.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.HostJob{}, false, nil
	}
	return job, err == nil, err
}

// DueForHost 返回指定主机到期的待执行作业
func (r *JobRepo) DueForHost(ctx context.Context, hostname, now string, limit int) ([]ports.HostJob, error) {
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	rows, err := r.db.QueryContext(ctx, jobSelect+`
		JOIN assets a ON a.id = host_jobs.asset_id
		WHERE a.hostname = ? AND host_jobs.status = 'pending'
		  AND (host_jobs.next_run_at = '' OR host_jobs.next_run_at <= ?)
		  AND NOT EXISTS (SELECT 1 FROM host_jobs running
		      WHERE running.asset_id = host_jobs.asset_id AND running.status = 'running')
		ORDER BY host_jobs.created_at ASC LIMIT ?`, hostname, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.HostJob, 0, limit)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// Claim 原子抢占作业并记录一次尝试
func (r *JobRepo) Claim(ctx context.Context, id, hostname, now string) (ports.HostJob, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.HostJob{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	job, err := scanJob(tx.QueryRowContext(ctx, jobSelect+`
		JOIN assets a ON a.id = host_jobs.asset_id
		WHERE host_jobs.id = ? AND a.hostname = ? AND host_jobs.status = 'pending'
		  AND (host_jobs.next_run_at = '' OR host_jobs.next_run_at <= ?)`, id, hostname, now))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.HostJob{}, false, nil
	}
	if err != nil {
		return ports.HostJob{}, false, err
	}
	job.Attempts++
	job.StartedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE host_jobs SET status = 'running', attempts = ?, started_at = ?
		WHERE id = ? AND status = 'pending'`, job.Attempts, now, id); err != nil {
		return ports.HostJob{}, false, err
	}
	job.Status = "running"
	if err := tx.Commit(); err != nil {
		return ports.HostJob{}, false, err
	}
	return job, true, nil
}

// Complete 写入执行结果；nextRunAt 非空表示进入重试。
func (r *JobRepo) Complete(ctx context.Context, id, status, output, errText string, exitCode int, now, nextRunAt string) error {
	job, found, err := r.ByID(ctx, id)
	if err != nil {
		return err
	}
	if !found {
		return ports.ErrNotFound
	}
	_, err = r.CompleteOnce(ctx, id, job.Attempts, status, output, errText, exitCode, now, nextRunAt)
	return err
}

// CompleteOnce 按尝试编号幂等完成运行中的作业；重复或迟到结果返回 applied=false。
func (r *JobRepo) CompleteOnce(ctx context.Context, id string, attempt int, status, output, errText string, exitCode int, now, nextRunAt string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	job, err := scanJob(tx.QueryRowContext(ctx, jobSelect+` WHERE host_jobs.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return false, ports.ErrNotFound
	}
	if err != nil {
		return false, err
	}
	var completed int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_job_attempts WHERE job_id=? AND attempt=?`, id, attempt).Scan(&completed); err != nil {
		return false, err
	}
	if completed > 0 || attempt <= 0 || job.Status != "running" || job.Attempts != attempt {
		return false, nil
	}

	finishedAt := now
	if nextRunAt != "" {
		finishedAt = ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE host_jobs SET status = ?, output = ?, error = ?,
		exit_code = ?, finished_at = ?, next_run_at = ? WHERE id = ? AND status = 'running' AND attempts = ?`,
		status, output, errText, exitCode, finishedAt, nextRunAt, id, attempt)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_job_attempts(job_id, attempt, status, output,
		error, started_at, finished_at) VALUES(?,?,?,?,?,?,?)`,
		id, attempt, status, output, errText, job.StartedAt, finishedAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RecoverExpired 回收超过租约的运行作业，并留下过期尝试记录以拒绝迟到结果。
func (r *JobRepo) RecoverExpired(ctx context.Context, now, cutoff string) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, jobSelect+`
		WHERE host_jobs.status='running' AND host_jobs.started_at<>'' AND host_jobs.started_at<=?`, cutoff)
	if err != nil {
		return 0, err
	}
	jobs := make([]ports.HostJob, 0, 4)
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			rows.Close()
			return 0, scanErr
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	recovered := 0
	for _, job := range jobs {
		status := "pending"
		errText := "Agent 执行租约超时，已重新排队"
		nextRunAt := now
		finishedAt := ""
		if job.Attempts >= job.MaxAttempts {
			status = "failed"
			errText = "Agent 执行租约超时，已超过最大尝试次数"
			nextRunAt = ""
			finishedAt = now
		}
		if _, err := tx.ExecContext(ctx, `UPDATE host_jobs SET status=?, next_run_at=?, error=?, finished_at=?
			WHERE id=? AND status='running'`, status, nextRunAt, errText, finishedAt, job.ID); err != nil {
			return recovered, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_job_attempts(job_id, attempt, status, output,
			error, started_at, finished_at) VALUES(?,?,?,?,?,?,?)`,
			job.ID, job.Attempts, "expired", "", errText, job.StartedAt, now); err != nil {
			return recovered, err
		}
		recovered++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return recovered, nil
}

// ListByAsset 返回资产最近作业
func (r *JobRepo) ListByAsset(ctx context.Context, assetID int64, limit int) ([]ports.HostJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, jobSelect+` WHERE host_jobs.asset_id = ? ORDER BY host_jobs.created_at DESC, host_jobs.id DESC LIMIT ?`,
		assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.HostJob, 0, limit)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// ExistingByIdempotency 查找未失效的幂等作业
func (r *JobRepo) ExistingByIdempotency(ctx context.Context, key, since string) (ports.HostJob, bool, error) {
	job, err := scanJob(r.db.QueryRowContext(ctx, jobSelect+`
		WHERE idempotency_key = ? AND created_at >= ? AND status IN ('pending','running','succeeded')
		ORDER BY created_at DESC LIMIT 1`, key, since))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.HostJob{}, false, nil
	}
	return job, err == nil, err
}
