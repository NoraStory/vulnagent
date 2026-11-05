-- 主机作业幂等只在应用事务的时间窗口内生效，历史失败、取消与过期记录不阻止新作业。
DROP INDEX IF EXISTS idx_host_jobs_idem;
CREATE INDEX IF NOT EXISTS idx_host_jobs_idem ON host_jobs(idempotency_key, created_at DESC);
