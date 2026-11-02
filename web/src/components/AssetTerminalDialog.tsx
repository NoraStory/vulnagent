import { useEffect, useState } from "react";
import { AlertCircle, KeyRound, Loader2, ShieldCheck, SquareTerminal, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { SshAuthType, SshHost } from "../lib/types";
import { useToast } from "../lib/toast";

// AssetTerminalDialog 把资产直接落成 SSH 主机，避免用户在终端里重复录入同一台机器。
export function AssetTerminalDialog({
  open,
  assetId,
  hostname,
  ip,
  onClose,
  onLinked
}: {
  open: boolean;
  assetId: number;
  hostname: string;
  ip: string;
  onClose: () => void;
  onLinked: (host: SshHost) => void;
}) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [username, setUsername] = useState("root");
  const [port, setPort] = useState("22");
  const [authMode, setAuthMode] = useState<SshAuthType>("password");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const target = ip || hostname;

  useEffect(() => {
    if (!open) return;
    setName(hostname || ip);
    setUsername("root");
    setPort("22");
    setAuthMode("password");
    setPassword("");
    setPrivateKey("");
    setPassphrase("");
    setError("");
  }, [open, hostname, ip]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, busy, onClose]);

  if (!open) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!username.trim()) {
      setError("用户名不能为空");
      return;
    }
    if (authMode === "password" && !password) {
      setError("请输入 SSH 口令");
      return;
    }
    if (authMode === "key" && !privateKey.trim()) {
      setError("请粘贴私钥内容");
      return;
    }
    setBusy(true);
    try {
      const result = await api.assetSshLink(assetId, {
        name: name.trim() || hostname || target,
        username: username.trim(),
        port: Number(port) || 22,
        authType: authMode,
        password: authMode === "password" ? password : undefined,
        privateKey: authMode === "key" ? privateKey : undefined,
        passphrase: authMode === "key" ? passphrase : undefined
      });
      toast.push(result.created ? "已创建 SSH 主机，可直接打开终端" : "已更新该资产对应的 SSH 凭据", "success");
      setPassword("");
      setPrivateKey("");
      setPassphrase("");
      onLinked(result.host);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "保存 SSH 主机失败，请检查网络与凭据");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="关闭"
        className="animate-fade absolute inset-0 bg-[#1D1D1F]/25 backdrop-blur-[2px]"
        onClick={() => !busy && onClose()}
      />
      <form
        onSubmit={submit}
        className="animate-rise relative flex max-h-[calc(100vh-48px)] w-full max-w-[460px] flex-col overflow-hidden rounded-card border border-line bg-surface shadow-float"
      >
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <SquareTerminal size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">连接资产终端</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">
                目标 {target} · 保存后终端、集群与漏洞扫描共用同一份凭据
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => !busy && onClose()}
            className="rounded-full p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
            aria-label="关闭"
          >
            <X size={16} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          <div className="grid grid-cols-[1fr_88px] gap-2.5">
            <label className="block">
              <span className="mb-1 block text-[11.5px] font-medium text-ink2">显示名称</span>
              <input
                className="input h-9"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={hostname || target}
                autoFocus
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11.5px] font-medium text-ink2">端口</span>
              <input
                className="input h-9 tabular-nums"
                value={port}
                onChange={(event) => setPort(event.target.value)}
                inputMode="numeric"
              />
            </label>
          </div>

          <label className="mt-3 block">
            <span className="mb-1 block text-[11.5px] font-medium text-ink2">用户名</span>
            <input
              className="input h-9"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="off"
            />
          </label>

          <div className="mt-3">
            <span className="mb-1 block text-[11.5px] font-medium text-ink2">认证方式</span>
            <div className="inline-flex items-center gap-1 rounded-[10px] bg-subtle p-1">
              {(
                [
                  { value: "password" as SshAuthType, label: "口令", icon: <KeyRound size={12} /> },
                  { value: "key" as SshAuthType, label: "私钥", icon: <ShieldCheck size={12} /> }
                ]
              ).map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setAuthMode(option.value)}
                  className={`inline-flex h-7 items-center gap-1.5 rounded-[8px] px-2.5 text-[12px] font-medium transition-colors ${
                    authMode === option.value ? "bg-surface text-ink shadow-card" : "text-ink2 hover:text-ink"
                  }`}
                >
                  {option.icon}
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          {authMode === "password" ? (
            <label className="mt-3 block">
              <span className="mb-1 block text-[11.5px] font-medium text-ink2">口令</span>
              <input
                className="input h-9"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                placeholder="AES-256-GCM 加密保存"
              />
            </label>
          ) : (
            <>
              <label className="mt-3 block">
                <span className="mb-1 block text-[11.5px] font-medium text-ink2">私钥（OpenSSH / PEM）</span>
                <textarea
                  className="input h-[92px] resize-none py-2 font-mono text-[11px] leading-[17px]"
                  value={privateKey}
                  onChange={(event) => setPrivateKey(event.target.value)}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                />
              </label>
              <label className="mt-2.5 block">
                <span className="mb-1 block text-[11.5px] font-medium text-ink2">私钥口令（可选）</span>
                <input
                  className="input h-9"
                  type="password"
                  value={passphrase}
                  onChange={(event) => setPassphrase(event.target.value)}
                  autoComplete="new-password"
                />
              </label>
            </>
          )}

          {error && (
            <div className="animate-fade mt-3 flex items-start gap-2 rounded-[10px] border border-[#FFD5D1] bg-[#FFECEA] px-3 py-2 text-[11.5px] leading-[17px] text-[#C4170E]">
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <p className="mt-3 text-[10.5px] leading-[16px] text-ink3">
            凭据使用 AES-256-GCM 加密保存，不在页面回显；已存在同一主机的凭据会直接复用并更新。
          </p>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3.5">
          <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button type="submit" className="btn btn-primary h-8" disabled={busy}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <SquareTerminal size={13} />}
            {busy ? "正在保存…" : "保存并打开终端"}
          </button>
        </footer>
      </form>
    </div>
  );
}
