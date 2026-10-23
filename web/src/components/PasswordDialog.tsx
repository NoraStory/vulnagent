import { useEffect, useState } from "react";
import { KeyRound, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useToast } from "../lib/toast";

export function PasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setOldPassword("");
    setNewPassword("");
    setConfirm("");
    setError("");
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (newPassword.length < 10) {
      setError("新口令至少 10 个字符");
      return;
    }
    if (!/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      setError("新口令需同时包含字母与数字");
      return;
    }
    if (newPassword !== confirm) {
      setError("两次输入的新口令不一致");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(oldPassword, newPassword);
      toast.push("口令已更新，其他设备上的会话已下线");
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "修改口令失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="关闭"
        className="animate-fade absolute inset-0 bg-[#1D1D1F]/25 backdrop-blur-[2px]"
        onClick={() => !busy && onClose()}
      />
      <form
        onSubmit={submit}
        className="animate-rise relative w-full max-w-[400px] overflow-hidden rounded-card border border-line bg-surface shadow-float"
      >
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <KeyRound size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">修改口令</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">至少 10 位，需包含字母与数字</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => !busy && onClose()}
            className="rounded-[8px] p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
            aria-label="关闭"
          >
            <X size={15} />
          </button>
        </header>

        <div className="flex flex-col gap-3 px-5 py-4">
          <label className="flex flex-col gap-1.5">
            <span className="text-[12px] text-ink2">当前口令</span>
            <input
              type="password"
              className="input h-9"
              value={oldPassword}
              onChange={(event) => setOldPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-[12px] text-ink2">新口令</span>
            <input
              type="password"
              className="input h-9"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-[12px] text-ink2">确认新口令</span>
            <input
              type="password"
              className="input h-9"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
          {error && <p className="text-[12px] text-danger">{error}</p>}
          <p className="text-[11px] text-ink3">修改成功后，当前账号在其他设备上的会话会立即失效。</p>
        </div>

        <footer className="flex justify-end gap-2 border-t border-line px-5 py-3.5">
          <button type="button" className="btn btn-secondary h-8" onClick={() => onClose()} disabled={busy}>
            取消
          </button>
          <button type="submit" className="btn btn-primary h-8" disabled={busy}>
            {busy ? "提交中" : "确认修改"}
          </button>
        </footer>
      </form>
    </div>
  );
}
