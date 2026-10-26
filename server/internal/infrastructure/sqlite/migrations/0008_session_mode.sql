-- 0008 会话审批模式：each（每次审批）/ smart（AI 判断）/ full（完全操作，留痕）
ALTER TABLE agent_sessions ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'each';
