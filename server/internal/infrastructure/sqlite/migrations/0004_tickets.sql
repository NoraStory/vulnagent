-- 0004 本地工单：记录由控制面创建的修复工单及其流转
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    finding_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    asset_id INTEGER NOT NULL,
    priority TEXT NOT NULL DEFAULT 'P3',
    status TEXT NOT NULL DEFAULT 'open',
    assignee TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tickets_finding ON tickets(finding_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status, updated_at DESC);

-- 历史库中 findings.ticket_id 已存在但缺少工单行，补齐为可查询的本地工单
INSERT OR IGNORE INTO tickets(id, finding_id, cve_id, asset_id, priority, status, assignee,
    created_by, note, created_at, updated_at)
SELECT f.ticket_id, f.id, f.cve_id, f.asset_id, f.priority, f.status, COALESCE(f.assignee, ''),
    '', '历史工单，迁移自 findings.ticket_id',
    COALESCE(f.first_seen, ''), COALESCE(f.last_seen, '')
FROM findings f
WHERE f.ticket_id IS NOT NULL AND f.ticket_id <> '';

