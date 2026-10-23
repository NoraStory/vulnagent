-- 0003 索引：补齐既有索引与列表/情报查询的高频过滤列
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_components_asset ON components(asset_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_poc_cve ON cve_poc(cve_id);
CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected(product);
CREATE INDEX IF NOT EXISTS idx_product_map_product ON product_map(product);

-- 新增：优先级筛选、CVE 关联、EPSS 排序与增量同步
CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_updated ON cves(updated_at);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss DESC);
