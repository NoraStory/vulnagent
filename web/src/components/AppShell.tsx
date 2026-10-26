import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import {
  Activity,
  ChevronRight,
  History,
  KeyRound,
  LayoutDashboard,
  LogOut,
  ScrollText,
  Server,
  ShieldAlert,
  Sparkles
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { initials, roleMeta } from "../lib/format";
import { PasswordDialog } from "./PasswordDialog";

const navGroups = [
  {
    label: "监控",
    items: [
      { to: "/", label: "概览", icon: LayoutDashboard },
      { to: "/findings", label: "漏洞", icon: ShieldAlert },
      { to: "/assets", label: "资产", icon: Server }
    ]
  },
  {
    label: "智能",
    items: [
      { to: "/assistant", label: "助手", icon: Sparkles },
      { to: "/trajectory", label: "轨迹", icon: History }
    ]
  },
  {
    label: "平台",
    items: [
      { to: "/selfcheck", label: "自检", icon: Activity },
      { to: "/settings", label: "审计与设置", icon: ScrollText }
    ]
  }
];

const pageMeta: Record<string, { title: string; subtitle: string; crumb: string }> = {
  "/": { title: "安全概览", subtitle: "漏洞态势、情报新鲜度与采集健康度", crumb: "概览" },
  "/findings": { title: "漏洞清单", subtitle: "按风险优先级排序，可解释、可闭环", crumb: "漏洞" },
  "/assets": { title: "资产与组件", subtitle: "主机清单、SBOM 与暴露面权重", crumb: "资产" },
  "/assistant": { title: "Agent 助手", subtitle: "只读工具直接执行，写操作需审批", crumb: "助手" },
  "/trajectory": { title: "操作轨迹", subtitle: "审计、主机作业与工具调用的统一时间线", crumb: "轨迹" },
  "/selfcheck": { title: "平台自检", subtitle: "数据库、情报同步、采集链路与平台自身", crumb: "自检" },
  "/settings": { title: "审计与设置", subtitle: "风险策略、账号权限与操作留痕", crumb: "审计与设置" }
};

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [selfCheck, setSelfCheck] = useState<{ status: string; warnings: number } | null>(null);
  const [pwdOpen, setPwdOpen] = useState(false);
  const [demo, setDemo] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .overview()
      .then((result) => {
        if (active) setDemo(result.demo);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    api
      .latestSelfCheck()
      .then((result) => {
        if (!active) return;
        setSelfCheck(result.run ? { status: result.run.status, warnings: result.run.warnings } : null);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [location.pathname]);

  const meta = pageMeta[location.pathname] ?? {
    title: "资产详情",
    subtitle: "组件清单与关联漏洞",
    crumb: "资产"
  };

  return (
    <div className="flex h-full min-h-screen bg-page">
      <aside className="sticky top-0 hidden h-screen w-[232px] shrink-0 flex-col border-r border-line bg-surface lg:flex">
        <Link to="/" className="flex h-16 items-center gap-2.5 px-5">
          <img src="/brand/mark.svg" alt="Signal" className="h-8 w-8 rounded-[9px]" />
          <span className="leading-tight">
            <span className="block text-[14px] font-semibold tracking-[-0.01em] text-ink">Signal</span>
            <span className="block text-[10.5px] text-ink3">漏洞信号台</span>
          </span>
        </Link>

        <nav className="flex flex-1 flex-col gap-5 px-3 pt-2">
          {navGroups.map((group) => (
            <div key={group.label}>
              <p className="px-2.5 pb-1.5 text-[10.5px] font-medium uppercase tracking-[0.06em] text-ink3">
                {group.label}
              </p>
              <div className="flex flex-col gap-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active =
                    item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      className={`nav-item ${active ? "nav-item-active" : ""}`}
                    >
                      <Icon size={15.5} strokeWidth={1.8} />
                      {item.label}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-line p-3">
          <div className="flex items-center gap-2.5 rounded-[10px] px-2 py-1.5">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-subtle text-[12px] font-semibold text-ink2">
              {initials(user?.name ?? "")}
            </span>
            <span className="min-w-0 flex-1 leading-tight">
              <span className="block truncate text-[12.5px] font-medium text-ink">{user?.name}</span>
              <span className="block text-[11px] text-ink3">{user ? roleMeta[user.role] : ""}</span>
            </span>
            <button
              type="button"
              onClick={() => setPwdOpen(true)}
              className="rounded-[8px] p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
              aria-label="修改口令"
              title="修改口令"
            >
              <KeyRound size={15} />
            </button>
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded-[8px] p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
              aria-label="退出登录"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-line bg-surface/85 backdrop-blur-xl">
          <div className="flex h-16 items-center justify-between gap-4 px-5 lg:px-8">
            <div className="flex min-w-0 items-center gap-2">
              <span className="hidden items-center gap-1 text-[12px] text-ink3 lg:flex">
                Signal
                <ChevronRight size={13} />
                <span className="text-ink2">{meta.crumb}</span>
              </span>
              <span className="hidden h-4 w-px bg-line lg:mx-1 lg:block" />
              <div className="min-w-0">
                <h1 className="truncate text-[16.5px] font-semibold leading-5 tracking-[-0.01em] text-ink">
                  {meta.title}
                </h1>
                <p className="hidden truncate text-[11.5px] text-ink3 sm:block">{meta.subtitle}</p>
              </div>
            </div>

            <div className="flex items-center gap-2.5">
              {demo && (
                <span className="hidden items-center gap-1.5 rounded-full border border-line bg-subtle px-2.5 py-1 text-[11px] text-ink2 sm:inline-flex">
                  <span className="h-1.5 w-1.5 rounded-full bg-warn" />
                  演示数据
                </span>
              )}
              <Link
                to="/selfcheck"
                className="hidden items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-[11px] text-ink2 transition-colors hover:bg-subtle md:inline-flex"
              >
                <Activity size={12} className={selfCheck?.status === "pass" ? "text-ok" : "text-warn"} />
                {selfCheck
                  ? selfCheck.status === "pass"
                    ? "自检通过"
                    : `自检 ${selfCheck.warnings} 项告警`
                  : "平台自检"}
              </Link>
              <span className="hidden h-6 w-px bg-line lg:block" />
              <span className="hidden items-center gap-2 lg:flex">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-subtle text-[11px] font-semibold text-ink2">
                  {initials(user?.name ?? "")}
                </span>
                <span className="text-[12.5px] font-medium text-ink">{user?.name}</span>
              </span>
            </div>
          </div>

          <div className="flex gap-1 overflow-x-auto border-t border-line/70 px-3 py-2 lg:hidden">
            {navGroups.flatMap((group) => group.items).map((item) => {
              const active =
                item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={`shrink-0 rounded-full px-3 py-1.5 text-[12.5px] font-medium ${
                    active ? "bg-brand-soft text-brand-strong" : "text-ink2 hover:bg-subtle"
                  }`}
                >
                  {item.label}
                </NavLink>
              );
            })}
          </div>
        </header>

        <main className="flex-1 px-5 py-6 lg:px-8">
          <div className="mx-auto w-full max-w-[1320px]">{children}</div>
        </main>
      </div>

      <PasswordDialog open={pwdOpen} onClose={() => setPwdOpen(false)} />
    </div>
  );
}
