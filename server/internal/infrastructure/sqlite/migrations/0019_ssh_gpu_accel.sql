-- 主机级 GPU 推理加速开关（NVIDIA，OpenAI 兼容端点）
ALTER TABLE ssh_hosts ADD COLUMN gpu_accel INTEGER NOT NULL DEFAULT 0;
