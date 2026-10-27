import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BookOpen,
  Loader2,
  Pencil,
  Play,
  Plus,
  Radio,
  Search,
  Send,
  Trash2,
  X
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useToast } from "../lib/toast";
import type { SshSnippet, SshSnippetInput } from "../lib/types";

type Props = {
  connected: Array<{ hostId: number; name: string }>;
  activeHostId?: number;
  onClose: () => void;
  onInsert: (command: string) => void;
  onRun: (command: string, broadcast: boolean) => void;
};

type EditorState = { open: boolean; editing: SshSnippet | null };

const emptyForm: SshSnippetInput = { name: "", command: "", description: "", tags: "" };

export function SnippetPanel({ connected, activeHostId, onClose, onInsert, onRun }: Props) {
  const toast = useToast();
  const [snippets, setSnippets] = useState<SshSnippet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [editor, setEditor] = useState<EditorState>({ open: false, editing: null });
  const [form, setForm] = useState<SshSnippetInput>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<SshSnippet | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.sshSnippets(200);
      setSnippets(result.items ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "读取快捷命令失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const keyword = filter.trim().toLowerCase();
    if (!keyword) return snippets;
    return snippets.filter((item) =>
      `${item.name} ${item.command} ${item.description} ${item.tags}`.toLowerCase().includes(keyword)
    );
  }, [snippets, filter]);

  function openCreate() {
    setForm(emptyForm);
    setEditor({ open: true, editing: null });
  }

  function openEdit(snippet: SshSnippet) {
    setForm({
      name: snippet.name,
      command: snippet.command,
      description: snippet.description,
      tags: snippet.tags
    });
    setEditor({ open: true, editing: snippet });
  }

  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      const payload: SshSnippetInput = {
        name: form.name.trim(),
        command: form.command.trim(),
        description: form.description.trim(),
        tags: form.tags.trim()
      };
      if (editor.editing) {
        const result = await api.sshUpdateSnippet(editor.editing.id, payload);
        setSnippets((prev) => prev.map((item) => (item.id === result.snippet.id ? result.snippet : item)));
        toast.push("快捷命令已更新", "success");
      } else {
        const result = await api.sshCreateSnippet(payload);
        setSnippets((prev) => [result.snippet, ...prev]);
        toast.push("快捷命令已保存", "success");
      }
      setEditor({ open: false, editing: null });
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  }

  async function remove(snippet: SshSnippet) {
    setConfirmDelete(null);
    try {
      await api.sshDeleteSnippet(snippet.id);
      setSnippets((prev) => prev.filter((item) => item.id !== snippet.id));
      toast.push("快捷命令已删除", "success");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "删除失败", "error");
    }
  }

  function trackUse(snippet: SshSnippet, broadcast: boolean, executed: boolean) {
    const hostNames = broadcast ? connected.map((item) => item.name) : activeHostId
      ? connected.filter((item) => item.hostId === activeHostId).map((item) => item.name)
      : [];
    setSnippets((prev) =>
      prev.map((item) => (item.id === snippet.id ? { ...item, usageCount: item.usageCount + 1 } : item))
    );
    void api.sshUseSnippet(snippet.id, hostNames, broadcast).catch(() => {
      /* 统计失败不影响命令发送 */
    });
    if (!executed) {
      toast.push("命令已插入终端", "info");
    }
  }

  function run(snippet: SshSnippet, broadcast: boolean) {
    if (!activeHostId) {
      toast.push("请先连接一台主机", "error");
      return;
    }
    if (broadcast && connected.length === 0) {
      toast.push("没有已连接的会话", "error");
      return;
    }
    onRun(snippet.command, broadcast);
    trackUse(snippet, broadcast, true);
  }

  function insert(snippet: SshSnippet) {
    if (!activeHostId) {
      toast.push("请先连接一台主机", "error");
      return;
    }
    onInsert(snippet.command);
    trackUse(snippet, false, false);
  }

  return (
    <div className="relative flex h-full min-h-0 flex-col bg-surface">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-brand-soft text-brand">
          <BookOpen size={14} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-[12.5px] font-semibold text-ink">快捷命令</p>
          <p className="truncate text-[10px] text-ink3">
            团队共享脚本库 · 可插入、执行或广播到 {connected.length} 个会话
          </p>
        </div>
        <button
          type="button"
          className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
          onClick={onClose}
          aria-label="关闭快捷命令"
        >
          <X size={15} />
        </button>
      </header>

      <div className="flex items-center gap-1.5 border-b border-line px-3 py-2">
        <div className="relative min-w-0 flex-1">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-ink3" />
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="搜索名称 / 命令 / 标签"
            className="input h-7 w-full pl-6 text-[11px]"
          />
        </div>
        <button type="button" className="btn btn-primary h-7 px-2 text-[11px]" onClick={openCreate}>
          <Plus size={12} />
          新建
        </button>
      </div>

      {error && (
        <div className="mx-3 mt-2 rounded-[8px] bg-dangerSoft px-2.5 py-1.5 text-[10.5px] text-danger">{error}</div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center gap-2 px-4 py-6 text-[11px] text-ink3">
            <Loader2 size={13} className="animate-spin" />
            正在读取脚本库…
          </div>
        )}
        {!loading && filtered.length === 0 && (
          <p className="px-4 py-10 text-center text-[11px] text-ink3">
            {snippets.length === 0 ? "还没有快捷命令，点击「新建」沉淀常用操作。" : "没有匹配的命令"}
          </p>
        )}
        {!loading &&
          filtered.map((snippet) => (
            <div key={snippet.id} className="border-b border-line/60 px-3 py-2 hover:bg-subtle/40">
              <div className="flex items-center gap-1.5">
                <span className="truncate text-[11.5px] font-medium text-ink">{snippet.name}</span>
                <span className="ml-auto shrink-0 text-[9.5px] text-ink3">使用 {snippet.usageCount} 次</span>
              </div>
              <pre className="mt-1 overflow-x-auto rounded-[6px] bg-[#0B1220] px-2 py-1.5 font-mono text-[10.5px] leading-[15px] text-[#D7DEEA]">
                {snippet.command}
              </pre>
              {(snippet.description || snippet.tags) && (
                <p className="mt-1 truncate text-[9.5px] text-ink3">
                  {snippet.description}
                  {snippet.description && snippet.tags ? " · " : ""}
                  {snippet.tags}
                </p>
              )}
              <div className="mt-1.5 flex items-center gap-1">
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                  title="插入当前终端"
                  onClick={() => insert(snippet)}
                >
                  <Send size={12} />
                </button>
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                  title="在当前终端执行"
                  onClick={() => run(snippet, false)}
                >
                  <Play size={12} />
                </button>
                <button
                  type="button"
                  className="rounded p-1 text-ink3 hover:bg-surface hover:text-brand disabled:opacity-40"
                  title="广播到全部已连接会话"
                  onClick={() => run(snippet, true)}
                  disabled={connected.length === 0}
                >
                  <Radio size={12} />
                </button>
                <span className="ml-auto flex items-center gap-0.5">
                  <button
                    type="button"
                    className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                    title="编辑"
                    onClick={() => openEdit(snippet)}
                  >
                    <Pencil size={12} />
                  </button>
                  <button
                    type="button"
                    className="rounded p-1 text-ink3 hover:bg-surface hover:text-danger"
                    title="删除"
                    onClick={() => setConfirmDelete(snippet)}
                  >
                    <Trash2 size={12} />
                  </button>
                </span>
              </div>
            </div>
          ))}
      </div>

      <footer className="shrink-0 border-t border-line px-3 py-1.5 text-[9.5px] text-ink3">
        命令必须为单行 · 广播会发送到全部已连接会话 · 使用与变更写入审计
      </footer>

      {editor.open && (
        <div
          className="absolute inset-0 z-20 flex items-center justify-center bg-black/45 px-4"
          onClick={() => setEditor({ open: false, editing: null })}
          role="presentation"
        >
          <div
            className="w-full max-w-[360px] rounded-[10px] border border-line bg-surface p-3 shadow-[0_16px_40px_rgba(0,0,0,0.35)]"
            onClick={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={editor.editing ? "编辑快捷命令" : "新建快捷命令"}
          >
            <p className="text-[12px] font-semibold text-ink">{editor.editing ? "编辑快捷命令" : "新建快捷命令"}</p>
            <div className="mt-2 space-y-1.5">
              <input
                autoFocus
                value={form.name}
                onChange={(event) => setForm((prev) => ({ ...prev, name: event.target.value }))}
                placeholder="名称，例如：磁盘巡检"
                className="input h-7 w-full text-[11px]"
              />
              <textarea
                value={form.command}
                onChange={(event) => setForm((prev) => ({ ...prev, command: event.target.value }))}
                onKeyDown={(event) => {
                  if (event.nativeEvent.isComposing || event.keyCode === 229) return;
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void save();
                  }
                }}
                rows={3}
                placeholder="单行命令，例如：df -hT"
                className="input min-h-[64px] w-full resize-none py-1.5 font-mono text-[11px] leading-[16px]"
              />
              <input
                value={form.description}
                onChange={(event) => setForm((prev) => ({ ...prev, description: event.target.value }))}
                placeholder="说明（可选）"
                className="input h-7 w-full text-[11px]"
              />
              <input
                value={form.tags}
                onChange={(event) => setForm((prev) => ({ ...prev, tags: event.target.value }))}
                placeholder="标签，空格分隔（可选）"
                className="input h-7 w-full text-[11px]"
              />
            </div>
            <div className="mt-3 flex items-center justify-end gap-1.5">
              <button
                type="button"
                className="btn btn-secondary h-7 px-2.5 text-[11px]"
                onClick={() => setEditor({ open: false, editing: null })}
              >
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary h-7 px-2.5 text-[11px]"
                onClick={() => void save()}
                disabled={saving || !form.name.trim() || !form.command.trim()}
              >
                {saving ? <Loader2 size={11} className="animate-spin" /> : null}
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmDelete && (
        <div
          className="absolute inset-0 z-20 flex items-center justify-center bg-black/45 px-4"
          onClick={() => setConfirmDelete(null)}
          role="presentation"
        >
          <div
            className="w-full max-w-[300px] rounded-[10px] border border-line bg-surface p-3 shadow-[0_16px_40px_rgba(0,0,0,0.35)]"
            onClick={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label="删除快捷命令"
          >
            <p className="text-[12px] font-semibold text-ink">删除快捷命令</p>
            <p className="mt-1.5 text-[11px] leading-[17px] text-ink2">
              确认删除「{confirmDelete.name}」？此操作不可撤销。
            </p>
            <div className="mt-3 flex items-center justify-end gap-1.5">
              <button
                type="button"
                className="btn btn-secondary h-7 px-2.5 text-[11px]"
                onClick={() => setConfirmDelete(null)}
              >
                取消
              </button>
              <button
                type="button"
                className="btn btn-danger h-7 px-2.5 text-[11px]"
                onClick={() => void remove(confirmDelete)}
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
