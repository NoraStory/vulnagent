import { useEffect, useState } from "react";
import { AlertCircle, KeyRound, Loader2, ShieldCheck, Terminal, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useToast } from "../lib/toast";

type AuthMode = "password" | "key";

export function SshScanDialog({
  open,
  onClose,
  onSuccess
}: {
  open: boolean;
  onClose: () => void;
  onSuccess: (assetId: number, summary: string) => void;
}) {
  const toast = useToast();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("root");
  const [authMode, setAuthMode] = useState<AuthMode>("password");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

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

  useEffect(() => {
    if (open) setError("");
  }, [open]);

  if (!open) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!host.trim() || !username.trim()) {
      setError("主机与用户名不能为空");
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
      const result = await api.sshScan({
        host: host.trim(),
        port: Number(port) || 22,
        username: username.trim(),
        password: authMode === "password" ? password : undefined,
        privateKey: authMode === "key" ? privateKey : undefined,
        passphrase: authMode === "key" ? passphrase : undefined,
        hostKeyFingerprint: fingerprint.trim() || undefined
      });
      const summary = `采集 ${result.components} 个组件 · 新增 ${result.created} 条漏洞 · 耗时 ${result.elapsedMs} ms`;
      toast.push(`SSH 采集完成：${summary}`);
      setPassword("");
      setPrivateKey("");
      setPassphrase("");
      onSuccess(result.assetId, summary);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "SSH 采集失败，请检查网络与凭据");
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
              <Terminal size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">SSH 兜底采集</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">用于无法安装 Agent 的主机，只执行只读脚本</p>
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
              <span className="mb-1 block text-[11.5px] font-medium text-ink2">主机 / IP</span>
              <input
                className="input h-9"
                value={host}
                onChange={(event) => setHost(event.target.value)}
                placeholder="10.20.9.71"
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
                  { value: "password" as AuthMode, label: "口令", icon: <KeyRound size={12} /> },
                  { value: "key" as AuthMode, label: "私钥", icon: <ShieldCheck size={12} /> }
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
                placeholder="不会保存"
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

          <label className="mt-3 block">
            <span className="mb-1 block text-[11.5px] font-medium text-ink2">
              主机指纹（可选，首次可留空）
            </span>
            <input
              className="input h-9 font-mono text-[11.5px]"
              value={fingerprint}
              onChange={(event) => setFingerprint(event.target.value)}
              placeholder="SHA256:..."
            />
          </label>

          {error && (
            <div className="animate-fade mt-3 flex items-start gap-2 rounded-[10px] border border-[#FFD5D1] bg-[#FFECEA] px-3 py-2 text-[11.5px] leading-[17px] text-[#C4170E]">
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <p className="mt-3 text-[10.5px] leading-[16px] text-ink3">
            凭据仅用于本次连接，不写入数据库与日志；采集脚本只读取包清单，不修改目标主机。
          </p>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3.5">
          <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button type="submit" className="btn btn-primary h-8" disabled={busy}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Terminal size={13} />}
            {busy ? "正在采集…" : "开始采集"}
          </button>
        </footer>
      </form>
    </div>
  );
}
