-- 0018 性能索引：覆盖列表排序、统计趋势与常见过滤列
CREATE INDEX IF NOT EXISTS idx_findings_risk_id ON findings(risk DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_findings_status_risk ON findings(status, risk DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_findings_priority_risk ON findings(priority, risk DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings(first_seen);
CREATE INDEX IF NOT EXISTS idx_findings_component ON findings(component_name, component_version, eco, risk DESC);
CREATE INDEX IF NOT EXISTS idx_findings_ticket ON findings(ticket_id);

CREATE INDEX IF NOT EXISTS idx_assets_merged ON assets(merged_into, id);
CREATE INDEX IF NOT EXISTS idx_assets_env_status ON assets(env, status, merged_into);
CREATE INDEX IF NOT EXISTS idx_assets_source_seen ON assets(source, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_serial ON assets(serial);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac);

CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_logs(actor, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tickets_asset ON tickets(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_finding_time ON finding_events(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_poc_cve_time ON cve_poc(cve_id, inserted_at DESC);
