import { useEffect, useState } from "react";
import { AlertCircle, Loader2, LockKeyhole, ShieldCheck } from "lucide-react";
import { useAuth } from "../lib/auth";
import { api, ApiError } from "../lib/api";

const demoAccounts = [
  { username: "admin", password: "Admin@12345", role: "管理员" },
  { username: "operator", password: "Ops@12345", role: "运维" },
  { username: "viewer", password: "View@12345", role: "只读" }
];

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [demo, setDemo] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .health()
      .then((result) => {
        if (active) setDemo(result.demo);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "无法连接控制面，请确认后端服务已启动（:8787）";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-page px-5 py-10">
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-[420px] opacity-90"
        style={{
          background:
            "radial-gradient(900px 340px at 50% -140px, #FFFFFF 0%, rgba(255,255,255,0) 72%)"
        }}
      />

      <div className="relative w-full max-w-[392px]">
        <div className="mb-6 flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-[10px] bg-brand text-white shadow-[0_4px_12px_rgba(0,122,255,.28)]">
            <ShieldCheck size={19} />
          </span>
          <span className="leading-tight">
            <span className="block text-[15px] font-semibold tracking-[-0.01em] text-ink">VulnAgent</span>
            <span className="block text-[11px] text-ink3">安全漏洞运维 Agent</span>
          </span>
        </div>

        <div className="card overflow-hidden p-7">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-ink">登录控制面</h1>
          <p className="mt-1 text-[12.5px] leading-[19px] text-ink2">
            使用平台账号登录，所有写操作都会留痕审计。
          </p>

          <form className="mt-6 flex flex-col gap-3.5" onSubmit={handleSubmit}>
            <label className="block">
              <span className="mb-1.5 block text-[12px] font-medium text-ink2">账号</span>
              <input
                className="input h-10"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                placeholder="请输入账号"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-[12px] font-medium text-ink2">口令</span>
              <input
                className="input h-10"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                placeholder="请输入口令"
              />
            </label>

            {error && (
              <div className="animate-fade flex items-start gap-2 rounded-[10px] border border-[#FFD5D1] bg-[#FFECEA] px-3 py-2 text-[12px] leading-[18px] text-[#C4170E]">
                <AlertCircle size={14} className="mt-0.5 shrink-0" />
                {error}
              </div>
            )}

            <button type="submit" className="btn btn-primary mt-1 h-10" disabled={submitting}>
              {submitting ? <Loader2 size={15} className="animate-spin" /> : <LockKeyhole size={14} />}
              {submitting ? "正在登录…" : "登录"}
            </button>
          </form>

          {demo && (
            <div className="mt-6 border-t border-line pt-4">
              <p className="mb-2 text-[11px] text-ink3">演示账号（点击填入）</p>
              <div className="flex gap-1.5">
                {demoAccounts.map((account) => (
                  <button
                    key={account.username}
                    type="button"
                    onClick={() => {
                      setUsername(account.username);
                      setPassword(account.password);
                      setError("");
                    }}
                    className="flex-1 rounded-[9px] border border-line bg-subtle px-2 py-1.5 text-[11.5px] text-ink2 transition-colors hover:border-lineStrong hover:bg-surface hover:text-ink"
                  >
                    {account.role}
                    <span className="mt-0.5 block font-mono text-[10px] text-ink3">{account.username}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <p className="mt-5 text-center text-[11px] text-ink3">
          {demo ? "演示环境 · 漏洞与情报为示例数据，不对接真实外部源" : "VulnAgent 控制面 · 写操作留痕审计"}
        </p>
      </div>
    </div>
  );
}
