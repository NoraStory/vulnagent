import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Copy, Link2, Loader2, Share2, ShieldCheck, Trash2, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { formatTime } from "../lib/format";
import { useToast } from "../lib/toast";
import type { SshShareCreated, SshShareLink, SshSharePermission } from "../lib/types";

type Props = {
  sessionId: string;
  hostName: string;
  onClose: () => void;
};

const ttlOptions = [
  { value: 30, label: "30 分钟" },
  { value: 60, label: "1 小时" },
  { value: 480, label: "8 小时" },
  { value: 1440, label: "24 小时" }
];

export function ShareDialog({ sessionId, hostName, onClose }: Props) {
  const toast = useToast();
  const [links, setLinks] = useState<SshShareLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [permission, setPermission] = useState<SshSharePermission>("read");
  const [ttl, setTtl] = useState(60);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<SshShareCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const linkRef = useRef<HTMLInputElement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.sshShares(sessionId);
      setLinks(result.items ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "读取分享链接失败");
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  async function create() {
    if (creating) return;
    setCreating(true);
    try {
      const result = await api.sshCreateShare(sessionId, permission, ttl);
      setCreated(result);
      setCopied(false);
      await load();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "创建分享链接失败", "error");
    } finally {
      setCreating(false);
    }
  }

  async function copy() {
    if (!created) return;
    const url = `${window.location.origin}${created.path}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      toast.push("链接已复制", "success");
    } catch {
      const input = linkRef.current;
      if (input) {
        input.focus();
        input.select();
        try {
          document.execCommand("copy");
          setCopied(true);
          toast.push("链接已复制", "success");
        } catch {
          toast.push("复制失败，请手动选择链接", "error");
        }
      } else {
        toast.push("复制失败，请手动选择链接", "error");
      }
    }
  }

  async function revoke(id: number) {
    try {
      await api.sshRevokeShare(id);
      setLinks((prev) => prev.filter((item) => item.id !== id));
      toast.push("分享链接已撤销", "success");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "撤销失败", "error");
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="w-full max-w-[420px] rounded-[12px] border border-line bg-surface p-4 shadow-float"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="分享会话"
      >
        <header className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-brand-soft text-brand">
            <Share2 size={14} />
          </span>
          <div className="min-w-0">
            <p className="text-[12.5px] font-semibold text-ink">分享会话</p>
            <p className="truncate text-[10px] text-ink3">{hostName} · 会话 {sessionId.slice(0, 8)}</p>
          </div>
          <button
            type="button"
            className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={onClose}
            aria-label="关闭分享"
          >
            <X size={15} />
          </button>
        </header>

        <div className="mt-3 grid grid-cols-2 gap-1.5">
          <label className="block">
            <span className="text-[10px] text-ink3">权限</span>
            <select
              value={permission}
              onChange={(event) => setPermission(event.target.value as SshSharePermission)}
              className="input mt-1 h-7 w-full text-[11px]"
            >
              <option value="read">只读</option>
              <option value="write">可写（operator+）</option>
            </select>
          </label>
          <label className="block">
            <span className="text-[10px] text-ink3">有效期</span>
            <select
              value={ttl}
              onChange={(event) => setTtl(Number(event.target.value))}
              className="input mt-1 h-7 w-full text-[11px]"
            >
              {ttlOptions.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <button
          type="button"
          className="btn btn-primary mt-2 h-7 w-full text-[11px]"
          onClick={() => void create()}
          disabled={creating}
        >
          {creating ? <Loader2 size={11} className="animate-spin" /> : <Link2 size={11} />}
          生成分享链接
        </button>

        {created && (
          <div className="mt-2 rounded-[8px] border border-line bg-subtle/60 px-2.5 py-2">
            <p className="text-[9.5px] text-warn">链接只显示一次，请立即复制并发送给协作者。</p>
            <div className="mt-1 flex items-center gap-1">
              <input
                ref={linkRef}
                readOnly
                value={`${window.location.origin}${created.path}`}
                className="input h-7 min-w-0 flex-1 font-mono text-[9.5px]"
                onFocus={(event) => event.target.select()}
              />
              <button type="button" className="btn btn-secondary h-7 px-2 text-[10.5px]" onClick={() => void copy()}>
                {copied ? <Check size={11} className="text-ok" /> : <Copy size={11} />}
                {copied ? "已复制" : "复制"}
              </button>
            </div>
            <p className="mt-1 text-[9.5px] text-ink3">
              {created.permission === "write" ? "可写" : "只读"} · {formatTime(created.expiresAt)} 过期
            </p>
          </div>
        )}

        <div className="mt-3">
          <p className="text-[10px] font-medium text-ink3">有效链接</p>
          {loading && (
            <div className="flex items-center gap-1.5 py-2 text-[10.5px] text-ink3">
              <Loader2 size={11} className="animate-spin" />
              读取中…
            </div>
          )}
          {!loading && links.length === 0 && !error && (
            <p className="py-2 text-[10.5px] text-ink3">暂无有效链接</p>
          )}
          {error && <p className="py-2 text-[10.5px] text-danger">{error}</p>}
          <div className="max-h-[140px] space-y-1 overflow-y-auto">
            {links.map((link) => (
              <div key={link.id} className="flex items-center gap-1.5 rounded-[7px] bg-subtle/50 px-2 py-1.5">
                <ShieldCheck size={11} className={link.permission === "write" ? "text-warn" : "text-ok"} />
                <span className="text-[10.5px] text-ink">{link.permission === "write" ? "可写" : "只读"}</span>
                <span className="truncate text-[9.5px] text-ink3">
                  {link.createdBy} · {formatTime(link.expiresAt)} 过期
                </span>
                <button
                  type="button"
                  className="ml-auto rounded p-1 text-ink3 hover:bg-surface hover:text-danger"
                  onClick={() => void revoke(link.id)}
                  title="撤销链接"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))}
          </div>
        </div>

        <p className="mt-2 text-[9.5px] leading-[14px] text-ink3">
          协作者需登录控制台才能打开链接；只读链接不会转发输入，可写链接仅对 operator 及以上角色生效。
        </p>
      </div>
    </div>
  );
}
