-- 0024 数据库节点深度检查：只读连接配置（密码使用 AES-GCM 加密存储）
ALTER TABLE cluster_nodes ADD COLUMN db_engine TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_name TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_user TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_ssl_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_detail TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_nodes ADD COLUMN db_checked_at TEXT NOT NULL DEFAULT '';
