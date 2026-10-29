import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowUp,
  ChevronRight,
  Copy,
  Download,
  File as FileIcon,
  FileText,
  Folder,
  FolderPlus,
  HardDrive,
  Loader2,
  Pencil,
  RefreshCw,
  Save,
  Trash2,
  Upload,
  X
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import { formatTime } from "../lib/format";
import { useToast } from "../lib/toast";
import type { SftpEntry, SftpList, SftpPreview, SshHost } from "../lib/types";

type Props = {
  host: SshHost;
  onClose: () => void;
};

type DialogState =
  | { kind: "mkdir"; title: string }
  | { kind: "rename"; title: string; entry: SftpEntry }
  | { kind: "delete"; title: string; entry: SftpEntry };

function joinPath(dir: string, name: string): string {
  const base = dir.endsWith("/") ? dir : `${dir}/`;
  return `${base}${name}`.replace(/\/+/g, "/");
}

function formatSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  return `${(size / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function SftpPanel({ host, onClose }: Props) {
  const toast = useToast();
  const [path, setPath] = useState("/");
  const [pathInput, setPathInput] = useState("/");
  const [data, setData] = useState<SftpList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [preview, setPreview] = useState<SftpPreview | null>(null);
  const [editContent, setEditContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [dialogValue, setDialogValue] = useState("");
  const uploadRef = useRef<HTMLInputElement | null>(null);

  const load = useCallback(
    async (target: string) => {
      setLoading(true);
      try {
        const result = await api.sftpList(host.id, target);
        setData(result);
        setPath(result.path);
        setPathInput(result.path);
        setError("");
      } catch (err) {
        setError(err instanceof ApiError ? err.message : "读取目录失败");
      } finally {
        setLoading(false);
      }
    },
    [host.id]
  );

  useEffect(() => {
    void load(path);
    // 仅在主机变化时重新加载根目录，路径变化由用户操作触发
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host.id]);

  async function run(key: string, task: () => Promise<void>) {
    if (busy) return;
    setBusy(key);
    try {
      await task();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "操作失败", "error");
    } finally {
      setBusy("");
    }
  }

  function up() {
    if (data?.parent) void load(data.parent);
  }

  function enter(entry: SftpEntry) {
    if (entry.dir) {
      void load(entry.path);
      return;
    }
    void openPreview(entry);
  }

  async function openPreview(entry: SftpEntry) {
    await run("preview", async () => {
      const result = await api.sftpPreview(host.id, entry.path);
      setPreview(result);
      setEditContent(result.content);
    });
  }

  async function copyPath(target: string) {
    try {
      await navigator.clipboard.writeText(target);
      toast.push("路径已复制", "success");
      return;
    } catch {
      /* 回退到 execCommand，兼容非安全上下文与自动化环境 */
    }
    try {
      const helper = document.createElement("textarea");
      helper.value = target;
      helper.style.position = "fixed";
      helper.style.opacity = "0";
      document.body.appendChild(helper);
      helper.select();
      document.execCommand("copy");
      helper.remove();
      toast.push("路径已复制", "success");
    } catch {
      toast.push("复制失败，请手动选择路径", "error");
    }
  }

  async function savePreview() {
    if (!preview || preview.binary || preview.truncated) return;
    setSaving(true);
    try {
      const result = await api.sftpSave(host.id, preview.path, editContent);
      toast.push("文件已保存", "success");
      setPreview({
        ...preview,
        content: editContent,
        size: result.size,
        truncated: false,
        modified: new Date().toISOString()
      });
      void load(path);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  }

  async function upload(file: File) {
    await run("upload", async () => {
      const result = await api.sftpUpload(host.id, path, file);
      toast.push(`已上传 ${result.path.split("/").pop()}`, "success");
      await load(path);
    });
  }

  function openMkdir() {
    setDialogValue("");
    setDialog({ kind: "mkdir", title: "新建目录" });
  }

  function openRename(entry: SftpEntry) {
    setDialogValue(entry.name);
    setDialog({ kind: "rename", title: "重命名", entry });
  }

  function openDelete(entry: SftpEntry) {
    setDialog({ kind: "delete", title: entry.dir ? "删除目录" : "删除文件", entry });
  }

  async function submitDialog() {
    if (!dialog) return;
    if (dialog.kind === "delete") {
      const entry = dialog.entry;
      setDialog(null);
      await run("delete", async () => {
        await api.sftpDelete(host.id, entry.path, entry.dir);
        await load(path);
        toast.push("已删除", "success");
      });
      return;
    }
    const name = dialogValue.trim();
    if (!name) {
      toast.push("名称不能为空", "error");
      return;
    }
    if (name.includes("/")) {
      toast.push("名称不能包含 /", "error");
      return;
    }
    if (dialog.kind === "rename" && name === dialog.entry.name) {
      setDialog(null);
      return;
    }
    const target = joinPath(path, name);
    setDialog(null);
    await run(dialog.kind, async () => {
      if (dialog.kind === "mkdir") {
        await api.sftpMkdir(host.id, target);
        toast.push("目录已创建", "success");
      } else {
        await api.sftpRename(host.id, dialog.entry.path, target);
        toast.push("已重命名", "success");
      }
      await load(path);
    });
  }

  const segments = path.split("/").filter(Boolean);
  const breadcrumb: Array<{ label: string; path: string }> = [{ label: "根目录", path: "/" }];
  let accumulated = "";
  for (const segment of segments) {
    accumulated += `/${segment}`;
    breadcrumb.push({ label: segment, path: accumulated });
  }

  return (
    <div className="relative flex h-full min-h-0 flex-col bg-surface">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-brand-soft text-brand">
          <HardDrive size={14} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-[12.5px] font-semibold text-ink">文件管理</p>
          <p className="truncate text-[10px] text-ink3">{host.name} · {host.username}@{host.host}</p>
        </div>
        <button
          type="button"
          className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
          onClick={onClose}
          aria-label="关闭文件管理"
        >
          <X size={15} />
        </button>
      </header>

      <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-3 py-2">
        <button
          type="button"
          className="rounded p-1.5 text-ink3 hover:bg-subtle hover:text-ink disabled:opacity-40"
          onClick={up}
          disabled={!data?.parent || loading}
          title="上一级"
        >
          <ArrowUp size={14} />
        </button>
        <button
          type="button"
          className="rounded p-1.5 text-ink3 hover:bg-subtle hover:text-ink"
          onClick={() => void load(path)}
          title="刷新"
        >
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
        </button>
        <button
          type="button"
          className="rounded p-1.5 text-ink3 hover:bg-subtle hover:text-ink"
          onClick={() => uploadRef.current?.click()}
          title="上传文件"
        >
          <Upload size={13} />
        </button>
        <button
          type="button"
          className="rounded p-1.5 text-ink3 hover:bg-subtle hover:text-ink"
          onClick={openMkdir}
          title="新建目录"
        >
          <FolderPlus size={13} />
        </button>
        <span className="ml-auto text-[10px] text-ink3">{data?.items.length ?? 0} 项</span>
        <input
          ref={uploadRef}
          type="file"
          className="sr-only"
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = "";
            if (file) void upload(file);
          }}
        />
      </div>

      <form
        className="flex items-center gap-1.5 border-b border-line px-3 py-1.5"
        onSubmit={(event) => {
          event.preventDefault();
          void load(pathInput);
        }}
      >
        <input
          value={pathInput}
          onChange={(event) => setPathInput(event.target.value)}
          onFocus={(event) => event.target.select()}
          onKeyDown={(event) => {
            if (event.nativeEvent.isComposing || event.keyCode === 229) return;
            if (event.key === "Enter") {
              event.preventDefault();
              void load(pathInput);
            }
          }}
          spellCheck={false}
          placeholder="/var/log"
          aria-label="路径"
          className="input h-7 flex-1 font-mono text-[10.5px]"
        />
        <button
          type="button"
          className="btn btn-secondary h-7 w-7 shrink-0 px-0"
          onClick={() => void copyPath(pathInput || path)}
          title="复制当前路径"
          aria-label="复制当前路径"
        >
          <Copy size={11} />
        </button>
        <button type="submit" className="btn btn-secondary h-7 px-2 text-[10.5px]">
          跳转
        </button>
      </form>

      <div className="flex flex-wrap items-center gap-0.5 border-b border-line px-3 py-1.5 text-[10.5px] text-ink3">
        {breadcrumb.map((item, index) => (
          <span key={item.path} className="flex items-center gap-0.5">
            {index > 0 && <ChevronRight size={10} className="text-ink3" />}
            <button
              type="button"
              className="rounded px-1 py-0.5 hover:bg-subtle hover:text-ink"
              onClick={() => void load(item.path)}
            >
              {item.label}
            </button>
          </span>
        ))}
      </div>

      {error && (
        <div className="mx-3 mt-2 rounded-[8px] bg-dangerSoft px-2.5 py-1.5 text-[10.5px] text-danger">{error}</div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center gap-2 px-4 py-6 text-[11px] text-ink3">
            <Loader2 size={13} className="animate-spin" />
            正在读取目录…
          </div>
        )}
        {!loading && data?.items.length === 0 && (
          <p className="px-4 py-10 text-center text-[11px] text-ink3">目录为空</p>
        )}
        {!loading &&
          data?.items.map((entry) => (
            <div
              key={entry.path}
              className="group flex items-center gap-2 border-b border-line/60 px-3 py-2 transition-colors hover:bg-subtle/60"
            >
              <span className={`shrink-0 ${entry.dir ? "text-brand" : "text-ink3"}`}>
                {entry.dir ? <Folder size={15} /> : <FileIcon size={15} />}
              </span>
              <button type="button" className="min-w-0 flex-1 text-left" onClick={() => enter(entry)}>
                <span className="block truncate text-[11.5px] text-ink">{entry.name}</span>
                <span className="mt-0.5 block truncate text-[9.5px] text-ink3">
                  {entry.dir ? "目录" : formatSize(entry.size)} · {formatTime(entry.modified)}
                  {entry.symlink ? " · 链接" : ""}
                </span>
              </button>
              <span className="flex shrink-0 items-center gap-0.5 opacity-70 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                {!entry.dir && (
                  <>
                    <button
                      type="button"
                      className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                      onClick={() => void openPreview(entry)}
                      title="预览"
                    >
                      <FileText size={12} />
                    </button>
                    <a
                      className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                      href={api.sftpDownloadURL(host.id, entry.path)}
                      title="下载"
                    >
                      <Download size={12} />
                    </a>
                  </>
                )}
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                  onClick={() => void copyPath(entry.path)}
                  title="复制路径"
                  aria-label={`复制路径 ${entry.name}`}
                >
                  <Copy size={12} />
                </button>
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                  onClick={() => openRename(entry)}
                  title="重命名"
                >
                  <Pencil size={12} />
                </button>
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-danger"
                  onClick={() => openDelete(entry)}
                  title="删除"
                >
                  <Trash2 size={12} />
                </button>
              </span>
            </div>
          ))}
        {data?.truncated && (
          <p className="px-3 py-2 text-[10px] text-warn">目录条目过多，仅显示前 2000 项</p>
        )}
      </div>

      <footer className="shrink-0 border-t border-line px-3 py-1.5 text-[9.5px] text-ink3">
        上传上限 256MB · 在线编辑 256KB · 全部操作写入审计
      </footer>

      {preview && (
        <div className="absolute inset-0 z-10 flex flex-col bg-surface">
          <header className="flex items-center gap-2 border-b border-line px-3 py-2">
            <FileText size={14} className="text-brand" />
            <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink">{preview.path}</span>
            <button
              type="button"
              className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
              onClick={() => void copyPath(preview.path)}
              title="复制路径"
              aria-label="复制文件路径"
            >
              <Copy size={13} />
            </button>
            <button
              type="button"
              className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
              onClick={() => setPreview(null)}
              aria-label="关闭预览"
            >
              <X size={14} />
            </button>
          </header>
          {preview.binary ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-2 px-4 text-center">
              <FileIcon size={22} className="text-ink3" />
              <p className="text-[11.5px] text-ink2">二进制文件，无法在线预览</p>
              <a
                className="btn btn-secondary h-8 text-[11.5px]"
                href={api.sftpDownloadURL(host.id, preview.path)}
              >
                <Download size={12} />
                下载文件
              </a>
            </div>
          ) : (
            <>
              <textarea
                className="min-h-0 flex-1 resize-none bg-[#0B1220] px-3 py-2 font-mono text-[11px] leading-[17px] text-[#D7DEEA] outline-none"
                value={editContent}
                onChange={(event) => setEditContent(event.target.value)}
                spellCheck={false}
              />
              <div className="flex items-center gap-2 border-t border-line px-3 py-2">
                {preview.truncated && <span className="text-[9.5px] text-warn">文件较大，仅展示前 256KB</span>}
                <span className="ml-auto text-[9.5px] text-ink3">{formatSize(preview.size)}</span>
                <button
                  type="button"
                  className="btn btn-primary h-7 px-2.5 text-[11px]"
                  onClick={() => void savePreview()}
                  disabled={saving || preview.truncated}
                >
                  {saving ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />}
                  保存
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {dialog && (
        <div
          className="absolute inset-0 z-20 flex items-center justify-center bg-black/45 px-4"
          onClick={() => setDialog(null)}
          onKeyDown={(event) => {
            if (event.key === "Escape") setDialog(null);
          }}
          role="presentation"
        >
          <div
            className="w-full max-w-[300px] rounded-[10px] border border-line bg-surface p-3 shadow-[0_16px_40px_rgba(0,0,0,0.35)]"
            onClick={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={dialog.title}
          >
            <p className="text-[12px] font-semibold text-ink">{dialog.title}</p>
            {dialog.kind === "delete" ? (
              <p className="mt-1.5 text-[11px] leading-[17px] text-ink2">
                确认删除{dialog.entry.dir ? "目录" : "文件"}「{dialog.entry.name}」
                {dialog.entry.dir ? "及其全部内容" : ""}？此操作不可撤销。
              </p>
            ) : (
              <input
                autoFocus
                value={dialogValue}
                onChange={(event) => setDialogValue(event.target.value)}
                onKeyDown={(event) => {
                  if (event.nativeEvent.isComposing || event.keyCode === 229) return;
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void submitDialog();
                  }
                  if (event.key === "Escape") {
                    event.preventDefault();
                    setDialog(null);
                  }
                }}
                spellCheck={false}
                aria-label="名称"
                className="input mt-2 h-8 w-full font-mono text-[11px]"
              />
            )}
            <div className="mt-3 flex items-center justify-end gap-1.5">
              <button
                type="button"
                className="btn btn-secondary h-7 px-2.5 text-[11px]"
                onClick={() => setDialog(null)}
              >
                取消
              </button>
              <button
                type="button"
                className={`btn h-7 px-2.5 text-[11px] ${dialog.kind === "delete" ? "btn-danger" : "btn-primary"}`}
                onClick={() => void submitDialog()}
              >
                {dialog.kind === "delete" ? "删除" : "确定"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
