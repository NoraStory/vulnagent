import type { Priority } from "./types";

export const priorityMeta: Record<Priority, { label: string; color: string; soft: string; text: string }> = {
  P0: { label: "严重", color: "#B42318", soft: "#FDECEA", text: "#B42318" },
  P1: { label: "高危", color: "#B54708", soft: "#FDF1E3", text: "#B54708" },
  P2: { label: "中危", color: "#A15C07", soft: "#FEF6E7", text: "#A15C07" },
  P3: { label: "低危", color: "#667085", soft: "#F2F4F7", text: "#475467" }
};

export const statusMeta: Record<string, { label: string; color: string }> = {
  open: { label: "待处理", color: "#B42318" },
  triaged: { label: "已定级", color: "#B54708" },
  fixing: { label: "修复中", color: "#2A5BD7" },
  fixed: { label: "已修复", color: "#12805C" },
  verified: { label: "已验证", color: "#12805C" },
  closed: { label: "已关闭", color: "#667085" },
  risk_accepted: { label: "风险接受", color: "#667085" },
  false_positive: { label: "误报", color: "#667085" }
};

export const roleMeta: Record<string, string> = {
  admin: "管理员",
  operator: "运维",
  viewer: "只读",
  system: "系统",
  agent: "Agent"
};

export const envMeta: Record<string, string> = {
  prod: "生产",
  staging: "预发",
  dev: "开发"
};

export const exposureMeta: Record<string, string> = {
  public: "公网",
  internal: "内网",
  isolated: "隔离"
};

export const sourceMeta: Record<string, string> = {
  agent: "Agent",
  ssh: "SSH 兜底",
  container: "容器",
  self: "自身"
};

export const agentMeta: Record<string, { label: string; color: string }> = {
  online: { label: "在线", color: "#34C759" },
  offline: { label: "离线", color: "#8E8E93" },
  stale: { label: "滞后", color: "#FF9F0A" },
  none: { label: "无 Agent", color: "#8E8E93" }
};

export const checkMeta: Record<string, { label: string; color: string; soft: string }> = {
  pass: { label: "通过", color: "#34C759", soft: "#E9F9EE" },
  warn: { label: "警告", color: "#FF9F0A", soft: "#FFF3E0" },
  fail: { label: "失败", color: "#FF3B30", soft: "#FFECEA" },
  skip: { label: "跳过", color: "#8E8E93", soft: "#F2F2F7" }
};

export function formatTime(iso: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}

export function formatDate(iso: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

export function timeAgo(iso: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const diff = Date.now() - date.getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.round(hours / 24);
  return `${days} 天前`;
}

export function compactNumber(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 10_000) return `${(value / 1000).toFixed(1)}k`;
  return value.toLocaleString("zh-CN");
}

export function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function initials(name: string): string {
  if (!name) return "?";
  return name.slice(0, 1).toUpperCase();
}
