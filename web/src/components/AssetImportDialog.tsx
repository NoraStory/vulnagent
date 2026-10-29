import { useEffect, useRef, useState } from "react";
import { AlertCircle, CheckCircle2, FileDown, Loader2, Upload, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { AssetImportReport, AssetImportRow } from "../lib/types";
import { useToast } from "../lib/toast";

const strategyOptions = [
  { value: "update" as const, label: "更新已有资产", hint: "按标识匹配，命中则更新字段" },
  { value: "skip" as const, label: "跳过已有资产", hint: "只新增未纳管的资产" },
  { value: "create" as const, label: "仅新增", hint: "命中已有资产时记为冲突并跳过" }
];

const actionMeta: Record<AssetImportRow["action"], { label: string; tone: string }> = {
  created: { label: "新增", tone: "bg-[#E8F7EE] text-[#1E7B3C]" },
  updated: { label: "更新", tone: "bg-[#EAF1FF] text-[#2A5BD7]" },
  skipped: { label: "跳过", tone: "bg-subtle text-ink2" },
  error: { label: "失败", tone: "bg-[#FFECEA] text-[#C4170E]" }
};

export function AssetImportDialog({
  open,
  onClose,
  onImported
}: {
  open: boolean;
  onClose: () => void;
  onImported: () => void;
}) {
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [strategy, setStrategy] = useState<"skip" | "update" | "create">("update");
  const [report, setReport] = useState<AssetImportReport | null>(null);
  const [busy, setBusy] = useState<"preview" | "apply" | "">("");
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
    if (open) {
      setFile(null);
      setReport(null);
      setError("");
      setBusy("");
    }
  }, [open]);

  if (!open) return null;

  const runPreview = async () => {
    if (!file) {
      setError("请先选择 CSV 文件");
      return;
    }
    setBusy("preview");
    setError("");
    try {
      const result = await api.importAssets(file, { strategy, dryRun: true });
      setReport(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "预览失败");
    } finally {
      setBusy("");
    }
  };

  const runImport = async () => {
    if (!file) return;
    setBusy("apply");
    setError("");
    try {
      const result = await api.importAssets(file, { strategy });
      setReport(result);
      toast.push(
        `导入完成：新增 ${result.created} · 更新 ${result.updated} · 跳过 ${result.skipped} · 失败 ${result.errors}`,
        result.errors > 0 ? "error" : "success"
      );
      onImported();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "导入失败");
    } finally {
      setBusy("");
    }
  };

  const downloadTemplate = async () => {
    try {
      const blob = await api.exportAssets({});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "vulnagent-assets-template.csv";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "下载模板失败", "error");
    }
  };

  const applied = Boolean(report && !report.dryRun);

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="关闭"
        className="animate-fade absolute inset-0 bg-[#1D1D1F]/25 backdrop-blur-[2px]"
        onClick={() => !busy && onClose()}
      />
      <div className="animate-rise relative flex max-h-[calc(100vh-48px)] w-full max-w-[720px] flex-col overflow-hidden rounded-card border border-line bg-surface shadow-float">
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <Upload size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">导入资产档案</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">
                支持 CSV（UTF-8，单次 5000 行 / 5MB），先预览再写入
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
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={inputRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={(event) => {
                const next = event.target.files?.[0] ?? null;
                setFile(next);
                setReport(null);
                setError("");
              }}
            />
            <button type="button" className="btn btn-secondary h-9" onClick={() => inputRef.current?.click()}>
              <Upload size={13.5} />
              选择 CSV 文件
            </button>
            <button type="button" className="btn btn-ghost h-9" onClick={() => void downloadTemplate()}>
              <FileDown size={13.5} />
              下载模板
            </button>
            <span className="text-[11.5px] text-ink3">{file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB` : "尚未选择文件"}</span>
          </div>

          <div className="mt-4">
            <span className="mb-1.5 block text-[11.5px] font-medium text-ink2">冲突策略</span>
            <div className="grid gap-2 sm:grid-cols-3">
              {strategyOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setStrategy(option.value)}
                  className={`rounded-[10px] border px-3 py-2 text-left transition-colors ${
                    strategy === option.value ? "border-brand bg-brand-soft/60" : "border-line hover:bg-subtle"
                  }`}
                >
                  <span className="block text-[12px] font-medium text-ink">{option.label}</span>
                  <span className="mt-0.5 block text-[10.5px] leading-[15px] text-ink3">{option.hint}</span>
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="animate-fade mt-3 flex items-start gap-2 rounded-[10px] border border-[#FFD5D1] bg-[#FFECEA] px-3 py-2 text-[11.5px] leading-[17px] text-[#C4170E]">
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          {report && (
            <div className="mt-4">
              <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
                <span className="pill bg-subtle text-ink2">{report.dryRun ? "预览结果" : "导入结果"}</span>
                <span className="pill bg-[#E8F7EE] text-[#1E7B3C]">新增 {report.created}</span>
                <span className="pill bg-[#EAF1FF] text-[#2A5BD7]">更新 {report.updated}</span>
                <span className="pill bg-subtle text-ink2">跳过 {report.skipped}</span>
                <span className={`pill ${report.errors > 0 ? "bg-[#FFECEA] text-[#C4170E]" : "bg-subtle text-ink3"}`}>
                  失败 {report.errors}
                </span>
                <span className="text-ink3">共 {report.total} 行</span>
              </div>
              <div className="mt-2 max-h-[260px] overflow-auto rounded-panel border border-line">
                <table className="w-full min-w-[560px] border-collapse">
                  <thead className="sticky top-0 bg-surface">
                    <tr className="border-b border-line">
                      <th className="th w-[64px] pl-3">行号</th>
                      <th className="th w-[70px]">结果</th>
                      <th className="th">主机名</th>
                      <th className="th">说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.items.map((item) => {
                      const meta = actionMeta[item.action];
                      return (
                        <tr key={item.row} className="border-b border-line/70 last:border-0">
                          <td className="td pl-3 tabular-nums text-ink3">{item.row}</td>
                          <td className="td">
                            <span className={`pill ${meta.tone}`}>{meta.label}</span>
                          </td>
                          <td className="td font-mono text-[11.5px] text-ink">{item.hostname || "—"}</td>
                          <td className="td text-[11.5px] text-ink2">
                            {item.message || "—"}
                            {item.changed && item.changed.length > 0 && (
                              <span className="ml-1 text-ink3">（{item.changed.join(", ")}）</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        <footer className="flex items-center justify-between gap-2 border-t border-line px-5 py-3.5">
          <span className="text-[10.5px] text-ink3">表头支持中文或英文，可先用「导出 CSV」生成模板</span>
          <div className="flex items-center gap-2">
            <button type="button" className="btn btn-secondary h-8" onClick={onClose} disabled={Boolean(busy)}>
              关闭
            </button>
            <button type="button" className="btn btn-secondary h-8" onClick={() => void runPreview()} disabled={!file || Boolean(busy)}>
              {busy === "preview" ? <Loader2 size={13} className="animate-spin" /> : null}
              预览变更
            </button>
            <button
              type="button"
              className="btn btn-primary h-8"
              onClick={() => void runImport()}
              disabled={!file || Boolean(busy) || applied}
            >
              {busy === "apply" ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
              {applied ? "已导入" : "确认导入"}
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}
