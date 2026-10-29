import { Link } from "react-router-dom";
import { CheckCircle2, Clock3, ExternalLink, Server, ShieldAlert, X } from "lucide-react";
import type { SshHostScanResult } from "../lib/types";

type Props = {
  result: SshHostScanResult;
  onClose: () => void;
};

export function ScanResultDialog({ result, onClose }: Props) {
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
        aria-label="漏洞扫描结果"
      >
        <header className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-okSoft text-ok">
            <CheckCircle2 size={14} />
          </span>
          <div className="min-w-0">
            <p className="text-[12.5px] font-semibold text-ink">扫描完成</p>
            <p className="truncate text-[10px] text-ink3">
              {result.hostName} · {result.username}@{result.host}
            </p>
          </div>
          <button
            type="button"
            className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={onClose}
            aria-label="关闭扫描结果"
          >
            <X size={15} />
          </button>
        </header>

        <div className="mt-3 grid grid-cols-3 gap-1.5">
          <div className="rounded-[8px] bg-subtle/70 px-2 py-1.5">
            <p className="text-[9.5px] text-ink3">软件组件</p>
            <p className="text-[15px] font-semibold text-ink">{result.components}</p>
          </div>
          <div className="rounded-[8px] bg-dangerSoft px-2 py-1.5">
            <p className="text-[9.5px] text-danger">新增漏洞</p>
            <p className="text-[15px] font-semibold text-danger">{result.created}</p>
          </div>
          <div className="rounded-[8px] bg-warnSoft px-2 py-1.5">
            <p className="text-[9.5px] text-warn">更新漏洞</p>
            <p className="text-[15px] font-semibold text-warn">{result.updated}</p>
          </div>
        </div>

        <div className="mt-2 space-y-1 rounded-[8px] border border-line px-2.5 py-2 text-[10px] text-ink3">
          <p className="flex items-center gap-1.5">
            <Server size={11} />
            系统：{result.os}
            {result.osVersion ? ` ${result.osVersion}` : ""}
          </p>
          <p className="flex items-center gap-1.5">
            <Clock3 size={11} />
            耗时 {(result.elapsedMs / 1000).toFixed(1)}s · 已收敛 {result.verified} / 关闭 {result.closed} / 重开 {result.reopened}
          </p>
          {result.hostKeyFingerprint && (
            <p className="truncate font-mono" title={result.hostKeyFingerprint}>
              指纹 {result.hostKeyFingerprint}
            </p>
          )}
        </div>

        <p className="mt-2 text-[9.5px] leading-[14px] text-ink3">
          采集为只读操作，结果已写入资产与漏洞流水线，可在资产详情中查看组件与关联漏洞。
        </p>

        <div className="mt-3 flex items-center justify-end gap-1.5">
          <Link to="/findings" className="btn btn-secondary h-7 px-2.5 text-[11px]" onClick={onClose}>
            <ShieldAlert size={11} />
            查看漏洞
          </Link>
          <Link
            to={`/assets/${result.assetId}`}
            className="btn btn-primary h-7 px-2.5 text-[11px]"
            onClick={onClose}
          >
            <ExternalLink size={11} />
            查看资产
          </Link>
        </div>
      </div>
    </div>
  );
}
