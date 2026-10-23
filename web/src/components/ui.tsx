import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, CircleSlash2, Loader2 } from "lucide-react";
import { checkMeta, priorityMeta, statusMeta } from "../lib/format";
import type { CheckStatus, Priority } from "../lib/types";

export function Dot({ color, size = 6 }: { color: string; size?: number }) {
  return (
    <span
      className="inline-block shrink-0 rounded-full"
      style={{ width: size, height: size, backgroundColor: color }}
    />
  );
}

export function PriorityPill({ priority, emphasis = false }: { priority: Priority; emphasis?: boolean }) {
  const meta = priorityMeta[priority];
  return (
    <span
      className="pill"
      style={{
        backgroundColor: meta.soft,
        color: meta.text,
        boxShadow: emphasis ? `inset 0 0 0 1px ${meta.color}33` : undefined
      }}
    >
      <Dot color={meta.color} size={5} />
      {priority} {meta.label}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const meta = statusMeta[status] ?? { label: status, color: "#8E8E93" };
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12.5px] text-ink2">
      <Dot color={meta.color} />
      {meta.label}
    </span>
  );
}

export function CheckPill({ status }: { status: CheckStatus }) {
  const meta = checkMeta[status] ?? checkMeta.skip;
  return (
    <span className="pill" style={{ backgroundColor: meta.soft, color: meta.color }}>
      {meta.label}
    </span>
  );
}

export function SectionCard({
  title,
  subtitle,
  action,
  children,
  className = "",
  bodyClassName = "p-5"
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`card flex min-w-0 flex-col ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4">
          <div>
            {title && <h2 className="text-[14px] font-semibold leading-5 text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[12px] text-ink3">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function Spinner({ size = 16, className = "" }: { size?: number; className?: string }) {
  return <Loader2 size={size} className={`animate-spin ${className}`} />;
}

export function Empty({
  title,
  description,
  action
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <div className="mb-1 flex h-10 w-10 items-center justify-center rounded-full bg-subtle text-ink3">
        <CircleSlash2 size={18} />
      </div>
      <p className="text-[13.5px] font-medium text-ink">{title}</p>
      {description && <p className="max-w-[320px] text-[12.5px] leading-[19px] text-ink3">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-[8px] bg-line/70 ${className}`} />;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange
}: {
  options: Array<{ value: T; label: string; count?: number; color?: string }>;
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="inline-flex items-center gap-1 rounded-[11px] bg-subtle p-1">
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={`inline-flex h-7 items-center gap-1.5 rounded-[8px] px-2.5 text-[12.5px] font-medium transition-colors ${
              active ? "bg-surface text-ink shadow-card" : "text-ink2 hover:text-ink"
            }`}
          >
            {option.color && <Dot color={option.color} size={6} />}
            {option.label}
            {typeof option.count === "number" && (
              <span className={`text-[11px] ${active ? "text-ink3" : "text-ink3/80"}`}>{option.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onChange
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="flex items-center justify-between gap-3 px-5 py-3">
      <p className="text-[12px] text-ink3">
        共 {total} 条 · 第 {page} / {pages} 页
      </p>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          className="btn btn-secondary h-8 px-2"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          aria-label="上一页"
        >
          <ChevronLeft size={15} />
        </button>
        <button
          type="button"
          className="btn btn-secondary h-8 px-2"
          disabled={page >= pages}
          onClick={() => onChange(page + 1)}
          aria-label="下一页"
        >
          <ChevronRight size={15} />
        </button>
      </div>
    </div>
  );
}

export function RiskMeter({ value, width = 56 }: { value: number; width?: number }) {
  const color = value >= 85 ? "#FF3B30" : value >= 70 ? "#FF9F0A" : value >= 50 ? "#FFCC00" : "#8E8E93";
  return (
    <div className="flex items-center gap-2">
      <span className="w-6 text-right text-[12.5px] font-semibold tabular-nums text-ink">{value}</span>
      <span className="h-1.5 overflow-hidden rounded-full bg-line" style={{ width }}>
        <span
          className="block h-full rounded-full transition-[width] duration-500"
          style={{ width: `${Math.min(100, value)}%`, backgroundColor: color }}
        />
      </span>
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral"
}: {
  children: ReactNode;
  tone?: "neutral" | "brand" | "success" | "warn" | "danger";
}) {
  const tones: Record<string, string> = {
    neutral: "bg-subtle text-ink2",
    brand: "bg-brand-soft text-brand-strong",
    success: "bg-[#E9F9EE] text-[#1E7B3C]",
    warn: "bg-[#FFF3E0] text-[#9A5B00]",
    danger: "bg-[#FFECEA] text-[#C4170E]"
  };
  return <span className={`pill ${tones[tone]}`}>{children}</span>;
}
