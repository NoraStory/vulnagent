-- 0009 遥测快照补充进程内存 Top N
ALTER TABLE asset_telemetry ADD COLUMN processes_json TEXT NOT NULL DEFAULT '[]';
