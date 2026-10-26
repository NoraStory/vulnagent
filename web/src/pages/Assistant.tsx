import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  ArrowDown,
  Bot,
  Check,
  ChevronDown,
  Loader2,
  PanelLeft,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  Sparkles,
  X
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import { formatTime, timeAgo } from "../lib/format";
import { Markdown } from "../components/Markdown";
import type {
  HarnessApproval,
  HarnessApprovalMode,
  HarnessEvent,
  HarnessMessage,
  HarnessSession,
  HarnessSkill,
  HarnessToolCall,
  HarnessToolSpec
} from "../lib/types";

type ToolItem = {
  key: string;
  kind: "tool";
  tool: string;
  ok: boolean;
  running?: boolean;
  args?: string;
  result?: unknown;
};

type Item =
  | { key: string; kind: "user" | "assistant"; content: string; at?: string }
  | ToolItem
  | {
      key: string;
      kind: "approval";
      approval: HarnessApproval;
      status: "pending" | "approved" | "rejected" | "expired";
      error?: string;
    }
  | { key: string; kind: "error"; content: string };

const suggestions = [
  "总结当前最紧急的 3 个漏洞，并说明依据",
  "看看情报同步是否滞后，需要处理吗",
  "列出公网暴露且含 P0/P1 漏洞的资产"
];

const riskLabel: Record<string, string> = { low: "只读", medium: "需审批", high: "需审批 + 口令" };
const riskClass: Record<string, string> = {
  low: "bg-signal-soft text-signal",
  medium: "bg-warnSoft text-warn",
  high: "bg-dangerSoft text-danger"
};

// 会话权限：每次审批 / AI 判断 / 完全操作
const approvalModes: { value: HarnessApprovalMode; label: string; hint: string }[] = [
  { value: "each", label: "每次审批", hint: "所有写操作都需要你点确认" },
  { value: "smart", label: "智能审批", hint: "由 AI 判断是否需要你确认，拿不准就转人工" },
  { value: "full", label: "完全操作", hint: "写操作自动执行，全部留痕" }
];

function parseResult(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function parseArgs(value?: string): string {
  if (!value) return "";
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function toItems(messages: HarnessMessage[]): Item[] {
  const items: Item[] = [];
  const calls = new Map<string, HarnessToolCall>();
  messages.forEach((message) => {
    if (message.role === "assistant") {
      if (message.toolCalls) {
        try {
          const parsed = JSON.parse(message.toolCalls);
          if (Array.isArray(parsed)) {
            parsed.forEach((call: HarnessToolCall) => {
              if (call?.id) calls.set(call.id, call);
            });
          }
        } catch {
          /* 历史工具调用解析失败时忽略 */
        }
      }
      if (!message.content.trim()) return;
      items.push({
        key: `m-${message.id}`,
        kind: message.role,
        content: message.content,
        at: message.createdAt
      });
      return;
    }
    if (message.role === "tool") {
      const call = message.toolCallId ? calls.get(message.toolCallId) : undefined;
      let result: unknown = message.content;
      try {
        result = JSON.parse(message.content);
      } catch {
        /* 保留原始文本 */
      }
      items.push({
        key: `m-${message.id}`,
        kind: "tool",
        tool: call?.name || "工具结果",
        args: call?.arguments,
        ok: !message.content.startsWith("工具执行失败"),
        result
      });
    }
  });
  return items;
}

type Block =
  | { kind: "tools"; key: string; items: ToolItem[] }
  | { kind: "item"; key: string; item: Exclude<Item, ToolItem> };

// groupItems 把连续的工具调用聚合为一组，其余消息保持独立
function groupItems(items: Item[]): Block[] {
  const blocks: Block[] = [];
  let group: ToolItem[] = [];
  const flush = () => {
    if (group.length === 0) return;
    blocks.push({ kind: "tools", key: `g-${group[0].key}`, items: group });
    group = [];
  };
  items.forEach((item) => {
    if (item.kind === "tool") {
      group.push(item);
      return;
    }
    flush();
    blocks.push({ kind: "item", key: item.key, item });
  });
  flush();
  return blocks;
}

function ToolStatusIcon({ item }: { item: ToolItem }) {
  if (item.running) return <Loader2 size={12} className="animate-spin text-brand" />;
  if (item.ok) return <Check size={12} className="text-ok" />;
  return <X size={12} className="text-danger" />;
}

const ToolGroup = memo(function ToolGroup({ group }: { group: ToolItem[] }) {
  const running = group.some((item) => item.running);
  const finished = group.filter((item) => !item.running);
  const failed = finished.filter((item) => !item.ok).length;
  return (
    <details className="animate-fade group rounded-[10px] border border-line bg-subtle/70 px-3 py-2">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-[11.5px] text-ink2">
        {running ? (
          <Loader2 size={12} className="animate-spin text-brand" />
        ) : failed > 0 ? (
          <X size={12} className="text-danger" />
        ) : (
          <Check size={12} className="text-ok" />
        )}
        <span>工具调用 {group.length} 次</span>
        <span className="text-ink3">
          {running
            ? "执行中"
            : `成功 ${finished.length - failed} · 失败 ${failed}`}
        </span>
        <ChevronDown size={12} className="ml-auto text-ink3 transition-transform group-open:rotate-180" />
      </summary>
      <div className="mt-2 space-y-1.5">
        {group.map((item) => (
          <details key={item.key} className="group/tool rounded-[8px] border border-line/70 bg-surface">
            <summary className="flex cursor-pointer list-none items-center gap-2 px-2.5 py-1.5 text-[11px] text-ink2">
              <ToolStatusIcon item={item} />
              <span className="mono">{item.tool}</span>
              <span className="text-ink3">
                {item.running ? "执行中" : item.ok ? "完成" : "失败"}
              </span>
              <ChevronDown size={11} className="ml-auto text-ink3 transition-transform group-open/tool:rotate-180" />
            </summary>
            <div className="space-y-1.5 border-t border-line/70 px-2.5 py-2">
              {item.args && (
                <div>
                  <p className="text-[10.5px] text-ink3">参数</p>
                  <pre className="mono mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-[6px] bg-subtle/70 p-2 text-[11px] text-ink2">
                    {parseArgs(item.args)}
                  </pre>
                </div>
              )}
              <div>
                <p className="text-[10.5px] text-ink3">结果</p>
                {item.running ? (
                  <p className="mt-1 text-[11px] text-ink3">执行中…</p>
                ) : (
                  <pre className="mono mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-[6px] bg-subtle/70 p-2 text-[11px] text-ink2">
                    {parseResult(item.result)}
                  </pre>
                )}
              </div>
            </div>
          </details>
        ))}
      </div>
    </details>
  );
});

// 单条消息组件：用 memo 固定历史消息，切换权限或输入文字时不重复渲染、不重解析 Markdown
type PlainItem = Exclude<Item, ToolItem>;

const MessageItem = memo(function MessageItem({ item }: { item: PlainItem }) {
  if (item.kind === "user") {
    return (
      <div className="animate-rise flex justify-end">
        <div className="bubble-user whitespace-pre-wrap">{item.content}</div>
      </div>
    );
  }
  if (item.kind === "assistant") {
    return (
      <div className="animate-rise flex items-start gap-2">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-ink text-white">
          <Sparkles size={12} />
        </span>
        <div className="bubble-assistant">
          <Markdown content={item.content} />
        </div>
      </div>
    );
  }
  if (item.kind === "approval") {
    return (
      <div className="animate-rise rounded-[12px] border border-[#F5D9B8] bg-warnSoft/60 px-3.5 py-3">
        <div className="flex items-center gap-2">
          <ShieldAlert size={14} className="text-warn" />
          <span className="text-[12.5px] font-semibold text-ink">需要人工审批</span>
          <span className={`pill ${riskClass[item.approval.risk] ?? ""}`}>
            {riskLabel[item.approval.risk] ?? item.approval.risk}
          </span>
        </div>
        <p className="mt-1 text-[12px] text-ink2">{item.approval.reason}</p>
        <p className="mt-0.5 text-[10.5px] text-ink3">
          有效期至 {formatTime(item.approval.expiresAt)} · 一次性生效，参数变更即失效
        </p>
        <pre className="mono mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-[8px] bg-surface/80 p-2 text-[11px] text-ink2">
          {item.approval.tool} {item.approval.args}
        </pre>
        {item.status === "pending" ? (
          <p className="mt-2 text-[11.5px] text-warn">等待你在输入框上方点击「批准并执行」或「拒绝」</p>
        ) : item.status === "expired" ? (
          <p className="mt-2 text-[11.5px] text-ink3">
            审批已过期{item.error ? `：${item.error}` : "，请重新发起操作"}
          </p>
        ) : (
          <p className="mt-2 text-[11.5px] text-ink2">
            已{item.status === "approved" ? "批准并执行" : "拒绝"} · 审批一次性生效
          </p>
        )}
        {item.error && item.status !== "expired" && (
          <p className="mt-1.5 flex items-center gap-1 text-[11.5px] text-danger">
            <AlertCircle size={12} />
            {item.error}
          </p>
        )}
      </div>
    );
  }
  return (
    <div className="rounded-[10px] border border-[#F5C6C2] bg-dangerSoft px-3 py-2 text-[12px] text-danger">
      {item.content}
    </div>
  );
});

export function AssistantPage() {
  const [tools, setTools] = useState<HarnessToolSpec[]>([]);
  const [model, setModel] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [sessions, setSessions] = useState<HarnessSession[]>([]);
  const [activeId, setActiveId] = useState("");
  const [items, setItems] = useState<Item[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [pendingMode, setPendingMode] = useState<HarnessApprovalMode>("each");
  const [modeSaving, setModeSaving] = useState(false);
  const [decidingId, setDecidingId] = useState("");
  const [skills, setSkills] = useState<HarnessSkill[]>([]);
  const [activeSkillId, setActiveSkillId] = useState("");
  const [slashOpen, setSlashOpen] = useState(false);
  const [slashIndex, setSlashIndex] = useState(0);
  const [slashQuery, setSlashQuery] = useState("");
  const [atBottom, setAtBottom] = useState(true);
  const [mobileSessionsOpen, setMobileSessionsOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  // stickRef 记录用户是否停留在底部：在底部时新消息自动跟随，上翻阅读时不打断
  const stickRef = useRef(true);

  const active = sessions.find((session) => session.id === activeId);
  const mode = active?.approvalMode ?? pendingMode;
  const modeHint = approvalModes.find((item) => item.value === mode)?.hint ?? "";
  const activeSkill = skills.find((item) => item.id === activeSkillId);
  const slashMatches = slashOpen
    ? skills
        .filter((item) => `${item.id} ${item.displayName}`.toLowerCase().includes(slashQuery))
        .sort(
          (a, b) =>
            Number(b.id.toLowerCase().startsWith(slashQuery)) -
            Number(a.id.toLowerCase().startsWith(slashQuery))
        )
    : [];
  const pendingApproval = items.find(
    (item): item is Extract<Item, { kind: "approval" }> =>
      item.kind === "approval" && item.status === "pending"
  );
  const hasPendingApproval = Boolean(pendingApproval);
  const expiredApproval = items.find(
    (item): item is Extract<Item, { kind: "approval" }> =>
      item.kind === "approval" && item.status === "expired"
  );
  // 仅在消息变化时重新分组，保证 Block 引用稳定，配合 memo 让历史消息跳过渲染
  const blocks = useMemo(() => groupItems(items), [items]);

  useEffect(() => {
    let mounted = true;
    api
      .harnessTools()
      .then((result) => {
        if (!mounted) return;
        setEnabled(result.enabled);
        setModel(result.model);
        setTools(result.tools ?? []);
      })
      .catch(() => undefined);
    api
      .harnessSkills()
      .then((result) => {
        if (mounted) setSkills(result.skills ?? []);
      })
      .catch(() => undefined);
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    api
      .harnessSessions()
      .then((result) => {
        if (!mounted) return;
        setSessions(result.sessions ?? []);
        if ((result.sessions ?? []).length > 0) {
          setActiveId((current) => current || result.sessions[0].id);
        }
      })
      .catch(() => undefined);
    return () => {
      mounted = false;
    };
  }, []);

  const loadMessages = useCallback(async (sessionId: string) => {
    const result = await api.harnessMessages(sessionId);
    const restored: Item[] = (result.pendingApprovals ?? []).map((approval) => ({
      key: `ap-${approval.id}`,
      kind: "approval",
      approval,
      status: "pending"
    }));
    setItems([...toItems(result.messages ?? []), ...restored]);
    setActiveSkillId(result.activeSkillId ?? "");
  }, []);

  useEffect(() => {
    // 切换会话时回到干净状态：清空技能菜单、错误与滚动位置
    setSlashOpen(false);
    setSlashQuery("");
    setError("");
    setAtBottom(true);
    stickRef.current = true;
    if (!activeId) {
      setItems([]);
      return;
    }
    let mounted = true;
    loadMessages(activeId).catch((err) => {
      if (mounted) setError(err instanceof ApiError ? err.message : "读取会话失败");
    });
    return () => {
      mounted = false;
    };
  }, [activeId, loadMessages]);

  // 审批 TTL 到点后在本地标记为过期，避免工具栏长期卡在「待确认」而无法继续提问
  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now();
      setItems((prev) => {
        let changed = false;
        const next = prev.map((item) => {
          if (
            item.kind === "approval" &&
            item.status === "pending" &&
            Date.parse(item.approval.expiresAt) <= now
          ) {
            changed = true;
            return { ...item, status: "expired" as const };
          }
          return item;
        });
        return changed ? next : prev;
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !stickRef.current) return;
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [items, busy]);

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    stickRef.current = bottom;
    setAtBottom(bottom);
  }

  function scrollToBottom() {
    const el = scrollRef.current;
    if (!el) return;
    stickRef.current = true;
    setAtBottom(true);
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }

  // refreshMessages 主动与后端对齐，用于处理过期审批或其它窗口已处理的情况
  async function refreshMessages() {
    if (!activeId || busy) return;
    try {
      await loadMessages(activeId);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "刷新会话失败");
    }
  }

  const handleEvent = useCallback((event: HarnessEvent) => {
    const stamp = Date.now();
    if (event.type === "message") {
      const data = event.data ?? {};
      if (data.role !== "assistant" || !String(data.content ?? "").trim()) return;
      setItems((prev) => [
        ...prev,
        { key: `a-${stamp}`, kind: "assistant", content: String(data.content) }
      ]);
      return;
    }
    if (event.type === "tool_call") {
      const data = event.data ?? {};
      const name = data.tool ?? "tool";
      setItems((prev) => [
        ...prev,
        {
          key: `t-${stamp}-${name}`,
          kind: "tool",
          tool: name,
          args:
            data.args === undefined || data.args === null
              ? undefined
              : typeof data.args === "string"
                ? data.args
                : JSON.stringify(data.args),
          ok: true,
          running: true
        }
      ]);
      return;
    }
    if (event.type === "tool_result") {
      const data = event.data ?? {};
      setItems((prev) => {
        const next = [...prev];
        for (let i = next.length - 1; i >= 0; i -= 1) {
          const item = next[i];
          if (item.kind === "tool" && item.running) {
            next[i] = { ...item, running: false, ok: Boolean(data.ok), result: data.result };
            return next;
          }
        }
        return [
          ...next,
          {
            key: `tr-${stamp}`,
            kind: "tool",
            tool: String(data.tool ?? "tool"),
            ok: Boolean(data.ok),
            result: data.result
          }
        ];
      });
      return;
    }
    if (event.type === "approval_required") {
      const approval = event.data as HarnessApproval;
      setItems((prev) => [
        ...prev,
        { key: `ap-${approval.id}`, kind: "approval", approval, status: "pending" }
      ]);
      return;
    }
    if (event.type === "error") {
      const message = String(event.data?.message ?? "助手执行失败");
      setItems((prev) => [...prev, { key: `e-${stamp}`, kind: "error", content: message }]);
      setError(message);
    }
  }, []);

  async function ensureSession(text: string): Promise<string> {
    if (activeId) return activeId;
    const title = text.length > 18 ? `${text.slice(0, 18)}…` : text;
    const { session } = await api.harnessCreateSession(title, pendingMode);
    setSessions((prev) => [session, ...prev]);
    setActiveId(session.id);
    return session.id;
  }

  async function send(text: string) {
    const raw = text.trim();
    if ((!raw && !activeSkillId) || busy || !enabled || hasPendingApproval) return;
    let content = raw;
    let skillId = activeSkillId;
    if (raw.startsWith("/")) {
      const [head, ...rest] = raw.split(/\s+/);
      const id = head.slice(1);
      if (skills.some((item) => item.id === id)) {
        skillId = id;
        content = rest.join(" ").trim();
      }
    }
    if (!content) {
      content = "请按技能指引开始：先说明你能做的诊断项，然后等待我描述具体问题。";
    }
    if (skillId && skillId !== activeSkillId) setActiveSkillId(skillId);
    setError("");
    setBusy(true);
    setInput("");
    setSlashOpen(false);
    try {
      const sessionId = await ensureSession(content);
      setItems((prev) => [...prev, { key: `u-${Date.now()}`, kind: "user", content }]);
      await api.harnessChat(sessionId, content, skillId || undefined, handleEvent);
      const refreshed = await api.harnessSessions();
      setSessions(refreshed.sessions ?? []);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "无法连接助手服务";
      setError(message);
      setItems((prev) => [...prev, { key: `e-${Date.now()}`, kind: "error", content: message }]);
    } finally {
      setBusy(false);
    }
  }

  async function resume() {
    if (!activeId) return;
    setBusy(true);
    setError("");
    try {
      await api.harnessResume(activeId, handleEvent);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "继续对话失败";
      setError(message);
    } finally {
      setBusy(false);
    }
  }

  async function decide(approval: HarnessApproval, decision: "approve" | "reject", key: string) {
    if (decidingId) return;
    setDecidingId(approval.id);
    setError("");
    try {
      await api.harnessDecision(approval.id, decision, passwords[approval.id] ?? "");
      setItems((prev) =>
        prev.map((item) =>
          item.key === key && item.kind === "approval"
            ? { ...item, status: decision === "approve" ? "approved" : "rejected", error: undefined }
            : item
        )
      );
      // 无论批准还是拒绝，都让模型基于工具结果收尾
      await resume();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "审批失败";
      // 409 表示审批已被处理或过期：标记为过期并及时同步，避免一直卡在待确认
      const expired =
        err instanceof ApiError && (err.code === "approval_expired" || err.status === 409);
      setItems((prev) =>
        prev.map((item) =>
          item.key === key && item.kind === "approval"
            ? { ...item, status: expired ? "expired" : item.status, error: message }
            : item
        )
      );
      if (expired && activeId) {
        try {
          await loadMessages(activeId);
          setError("审批已失效或已在其他窗口处理，已同步最新会话状态");
        } catch {
          setError(message);
        }
      }
    } finally {
      setDecidingId("");
    }
  }

  async function createSession() {
    try {
      const { session } = await api.harnessCreateSession("排查会话", pendingMode);
      setSessions((prev) => [session, ...prev]);
      setActiveId(session.id);
      setItems([]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "创建会话失败");
    }
  }

  async function changeMode(next: HarnessApprovalMode) {
    if (next === mode || modeSaving) return;
    const previous = mode;
    // 先本地生效，避免等待接口返回期间点击像“没反应”
    setPendingMode(next);
    setModeSaving(true);
    setError("");
    if (activeId) {
      setSessions((prev) =>
        prev.map((item) => (item.id === activeId ? { ...item, approvalMode: next } : item))
      );
      try {
        const { session } = await api.harnessUpdateSession(activeId, next);
        setSessions((prev) => prev.map((item) => (item.id === session.id ? session : item)));
      } catch (err) {
        setSessions((prev) =>
          prev.map((item) => (item.id === activeId ? { ...item, approvalMode: previous } : item))
        );
        setError(err instanceof ApiError ? err.message : "切换权限失败");
      }
    }
    setModeSaving(false);
  }

  function sessionList(onPick?: () => void) {
    return sessions.map((session) => (
      <button
        key={session.id}
        type="button"
        onClick={() => {
          setActiveId(session.id);
          onPick?.();
        }}
        className={`mb-1 flex w-full flex-col items-start gap-0.5 rounded-[10px] px-2.5 py-2 text-left transition-colors ${
          session.id === activeId ? "bg-brand-soft text-brand-strong" : "text-ink2 hover:bg-subtle"
        }`}
      >
        <span className="w-full truncate text-[12.5px] font-medium">{session.title}</span>
        <span className="text-[10.5px] text-ink3">{timeAgo(session.updatedAt)}</span>
      </button>
    ));
  }

  function selectSkill(skill: HarnessSkill) {
    setActiveSkillId(skill.id);
    setInput("");
    setSlashOpen(false);
    setSlashQuery("");
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  if (!enabled) {
    return (
      <div className="card card-pad flex flex-col items-start gap-3">
        <div className="flex items-center gap-2 text-ink">
          <Sparkles size={16} className="text-brand" />
          <h2 className="text-[15px] font-semibold">Agent 助手未启用</h2>
        </div>
        <p className="max-w-[640px] text-[13px] leading-[21px] text-ink2">
          配置通用 OpenAI 兼容模型凭据后重启服务即可启用：<code className="mono">VA_LLM_BASE_URL</code>、
          <code className="mono">VA_LLM_API_KEY</code>、<code className="mono">VA_LLM_MODEL</code>。
          助手只通过静态注册的只读工具取数，写操作必须人工审批。
        </p>
      </div>
    );
  }

  return (
    <div className="grid h-[calc(100dvh-160px)] min-h-[420px] grid-cols-1 gap-4 md:grid-cols-[248px_minmax(0,1fr)]">
      <aside className="card hidden min-h-0 flex-col overflow-hidden md:flex">
        <div className="flex items-center justify-between border-b border-line px-3.5 py-3">
          <span className="text-[12px] font-medium text-ink2">会话</span>
          <button type="button" className="btn btn-secondary h-7 px-2 text-[12px]" onClick={() => void createSession()}>
            <Plus size={13} />
            新建
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          {sessions.length === 0 && (
            <p className="px-2 py-6 text-center text-[12px] text-ink3">还没有会话，直接提问即可创建</p>
          )}
          {sessionList()}
        </div>
        <div className="border-t border-line">
          <details className="group">
            <summary className="flex cursor-pointer list-none items-center gap-1 px-3.5 py-2.5 text-[11px] text-ink2">
              可用工具 {tools.length}
              <ChevronDown size={12} className="ml-auto text-ink3 transition-transform group-open:rotate-180" />
            </summary>
            <div className="max-h-64 overflow-y-auto px-2 pb-2">
              {tools.map((tool) => (
                <div key={tool.name} className="mb-1 rounded-[8px] border border-line/70 bg-subtle/60 px-2 py-1.5">
                  <div className="flex items-center gap-1.5">
                    <span className="mono truncate text-[11px] text-ink">{tool.name}</span>
                    <span className={`pill ml-auto ${riskClass[tool.risk] ?? ""}`}>
                      {riskLabel[tool.risk] ?? tool.risk}
                    </span>
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[10.5px] leading-[15px] text-ink3">{tool.description}</p>
                </div>
              ))}
            </div>
          </details>
        </div>
        <div className="border-t border-line px-3.5 py-2.5 text-[10.5px] text-ink3">
          模型 {model || "—"} · 工具 {tools.length} 个
        </div>
      </aside>

      <section className="card flex min-h-0 flex-col overflow-hidden">
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="flex min-w-0 items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-[9px] bg-ink text-white">
              <Bot size={15} />
            </span>
            <div className="min-w-0">
              <p className="truncate text-[13px] font-semibold text-ink">{active?.title ?? "新会话"}</p>
              <p className="truncate text-[10.5px] text-ink3">
                只读工具直接执行 · {modeHint || "写操作按权限模式处理"}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span className="pill hidden bg-signal-soft text-signal sm:inline-flex">{model || "模型"}</span>
            <button
              type="button"
              onClick={() => void refreshMessages()}
              disabled={!activeId || busy}
              className="btn btn-secondary h-8 w-8 shrink-0 px-0"
              aria-label="刷新会话"
              title="刷新会话消息"
            >
              <RefreshCw size={13} />
            </button>
            <button
              type="button"
              onClick={() => setMobileSessionsOpen(true)}
              className="btn btn-secondary h-8 shrink-0 px-2 text-[12px] md:hidden"
              aria-label="切换会话"
            >
              <PanelLeft size={13} />
              会话
            </button>
          </div>
        </header>

        <div className="relative min-h-0 flex-1">
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            className="h-full space-y-3 overflow-y-auto px-4 py-4"
          >
          {items.length === 0 && (
            <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
              <span className="flex h-11 w-11 items-center justify-center rounded-[14px] bg-brand-soft text-brand">
                <Sparkles size={20} />
              </span>
              <p className="text-[13px] text-ink2">从信号到结论，问点什么吧</p>
              <div className="flex max-w-[560px] flex-wrap justify-center gap-2">
                {suggestions.map((text) => (
                  <button
                    key={text}
                    type="button"
                    onClick={() => void send(text)}
                    className="rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] text-ink2 transition-colors hover:border-lineStrong hover:text-ink"
                  >
                    {text}
                  </button>
                ))}
              </div>
            </div>
          )}

          {blocks.map((block) =>
            block.kind === "tools" ? (
              <ToolGroup key={block.key} group={block.items} />
            ) : (
              <MessageItem key={block.key} item={block.item} />
            )
          )}
          </div>
          {!atBottom && items.length > 0 && (
            <button
              type="button"
              onClick={scrollToBottom}
              className="absolute bottom-3 left-1/2 z-10 flex -translate-x-1/2 items-center gap-1 rounded-full border border-line bg-surface px-3 py-1.5 text-[11.5px] text-ink2 shadow-[0_6px_18px_rgba(16,24,40,0.14)] transition-colors hover:text-ink"
            >
              <ArrowDown size={12} />
              回到底部
            </button>
          )}
        </div>

        {error && (
          <div className="mx-4 mb-2 flex shrink-0 items-start gap-1.5 rounded-[8px] bg-dangerSoft px-2.5 py-1.5 text-[11.5px] text-danger">
            <AlertCircle size={12} className="mt-0.5 shrink-0" />
            {error}
          </div>
        )}

        <footer className="shrink-0 border-t border-line px-4 py-3">
          {activeSkill && (
            <div className="mb-2 flex items-center gap-2 rounded-[8px] border border-line bg-subtle/60 px-2.5 py-1.5 text-[11.5px] text-ink2">
              <Sparkles size={12} className="text-brand" />
              <span>技能</span>
              <span className="mono text-ink">/{activeSkill.id}</span>
              <span className="min-w-0 flex-1 truncate text-ink3">{activeSkill.displayName}</span>
              <button
                type="button"
                className="rounded p-0.5 text-ink3 transition-colors hover:text-ink"
                onClick={() => setActiveSkillId("")}
                aria-label="退出技能"
              >
                <X size={12} />
              </button>
            </div>
          )}

          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-ink3">权限</span>
            <div className="flex rounded-[8px] border border-line bg-subtle/70 p-0.5">
              {approvalModes.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  title={option.hint}
                  onClick={() => void changeMode(option.value)}
                  disabled={modeSaving}
                  className={`rounded-[6px] px-2.5 py-1 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                    mode === option.value
                      ? option.value === "full"
                        ? "bg-dangerSoft font-medium text-danger"
                        : option.value === "smart"
                          ? "bg-warnSoft font-medium text-warn"
                          : "bg-surface font-medium text-ink shadow-sm"
                      : "text-ink2 hover:text-ink"
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
            <span className="text-[10.5px] text-ink3">{modeHint}</span>
          </div>

          {mode === "full" && (
            <p className="mb-2 flex items-start gap-1.5 rounded-[8px] bg-dangerSoft px-2.5 py-1.5 text-[11px] text-danger">
              <ShieldAlert size={12} className="mt-0.5 shrink-0" />
              完全操作：写操作不再弹审批，直接执行；全部记录在工具调用与操作轨迹中，请确认你了解风险。
            </p>
          )}

          {pendingApproval && (
            <div className="mb-2 rounded-[10px] border border-[#F5D9B8] bg-warnSoft/70 px-3 py-2">
              <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-ink2">
                <ShieldAlert size={13} className="text-warn" />
                <span className="font-medium text-ink">待确认</span>
                <span className="mono">{pendingApproval.approval.tool}</span>
                <span className={`pill ${riskClass[pendingApproval.approval.risk] ?? ""}`}>
                  {riskLabel[pendingApproval.approval.risk] ?? pendingApproval.approval.risk}
                </span>
                <span className="min-w-0 flex-1 truncate text-ink3">{pendingApproval.approval.reason}</span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {pendingApproval.approval.risk === "high" && (
                  <input
                    className="input h-8 w-[220px]"
                    type="password"
                    placeholder="输入当前账号口令再认证"
                    value={passwords[pendingApproval.approval.id] ?? ""}
                    onChange={(event) =>
                      setPasswords((prev) => ({ ...prev, [pendingApproval.approval.id]: event.target.value }))
                    }
                  />
                )}
                <button
                  type="button"
                  className="btn btn-primary h-8 px-3 text-[12px]"
                  onClick={() => void decide(pendingApproval.approval, "approve", pendingApproval.key)}
                  disabled={Boolean(decidingId)}
                >
                  {decidingId === pendingApproval.approval.id ? (
                    <Loader2 size={13} className="animate-spin" />
                  ) : (
                    <Check size={13} />
                  )}
                  批准并执行
                </button>
                <button
                  type="button"
                  className="btn btn-secondary h-8 px-3 text-[12px]"
                  onClick={() => void decide(pendingApproval.approval, "reject", pendingApproval.key)}
                  disabled={Boolean(decidingId)}
                >
                  <X size={13} />
                  拒绝
                </button>
                <span className="text-[10.5px] text-ink3">
                  有效期至 {formatTime(pendingApproval.approval.expiresAt)}
                </span>
                {pendingApproval.error && (
                  <span className="flex items-center gap-1 text-[11px] text-danger">
                    <AlertCircle size={12} />
                    {pendingApproval.error}
                  </span>
                )}
              </div>
            </div>
          )}

          {!pendingApproval && expiredApproval && (
            <div className="mb-2 flex flex-wrap items-center gap-2 rounded-[10px] border border-line bg-subtle/70 px-3 py-2 text-[11.5px] text-ink2">
              <AlertCircle size={13} className="text-ink3" />
              <span className="font-medium text-ink">审批已过期</span>
              <span className="mono">{expiredApproval.approval.tool}</span>
              <span className="min-w-0 flex-1 truncate text-ink3">
                {expiredApproval.error || "超过有效期未确认，该操作已失效，可重新发起"}
              </span>
              <button
                type="button"
                className="btn btn-secondary h-8 px-2.5 text-[12px]"
                onClick={() => void refreshMessages()}
                disabled={!activeId || busy}
              >
                <RefreshCw size={13} />
                同步状态
              </button>
            </div>
          )}

          <div className="relative">
            {slashOpen && slashMatches.length > 0 && (
              <div className="absolute bottom-full left-0 right-0 z-20 mb-2 max-h-[240px] overflow-y-auto rounded-[10px] border border-line bg-surface p-1 shadow-[0_12px_32px_rgba(16,24,40,0.16)]">
                <p className="px-2.5 pb-1 pt-1.5 text-[10.5px] text-ink3">
                  选择运维技能 · ↑↓ 切换 · Enter 确认 · Esc 关闭
                </p>
                {slashMatches.map((skill, index) => (
                  <button
                    key={skill.id}
                    type="button"
                    onMouseEnter={() => setSlashIndex(index)}
                    onClick={() => selectSkill(skill)}
                    className={`flex w-full flex-col items-start gap-0.5 rounded-[8px] px-2.5 py-2 text-left ${
                      index === slashIndex ? "bg-brand-soft" : "hover:bg-subtle"
                    }`}
                  >
                    <span className="flex w-full items-center gap-2">
                      <span className="mono text-[11.5px] text-brand-strong">/{skill.id}</span>
                      <span className="truncate text-[11.5px] text-ink2">{skill.displayName}</span>
                      {skill.platforms?.length > 0 && (
                        <span className="ml-auto shrink-0 text-[10px] text-ink3">{skill.platforms.join("/")}</span>
                      )}
                    </span>
                    <span className="line-clamp-2 text-[10.5px] leading-[15px] text-ink3">{skill.description}</span>
                  </button>
                ))}
              </div>
            )}

            {slashOpen && slashMatches.length === 0 && (
              <div className="absolute bottom-full left-0 right-0 z-20 mb-2 rounded-[10px] border border-line bg-surface px-3 py-2 text-[11.5px] text-ink3 shadow-[0_12px_32px_rgba(16,24,40,0.16)]">
                没有匹配的技能，输入 <span className="mono">/</span> 查看全部
              </div>
            )}

            <div className="flex items-end gap-2">
              <textarea
                ref={inputRef}
                className="input min-h-[42px] flex-1 resize-none py-2.5 leading-[19px]"
                rows={2}
                placeholder={
                  hasPendingApproval
                    ? "请先处理待审批操作，再继续提问"
                    : skills.length > 0
                      ? "输入 / 调用运维技能，Enter 发送，Shift + Enter 换行"
                      : "描述你的问题，Enter 发送，Shift + Enter 换行"
                }
                value={input}
                onChange={(event) => {
                  const value = event.target.value;
                  setInput(value);
                  if (value.startsWith("/") && !value.includes(" ")) {
                    setSlashQuery(value.slice(1).toLowerCase());
                    setSlashOpen(true);
                    setSlashIndex(0);
                  } else {
                    setSlashOpen(false);
                  }
                }}
                onKeyDown={(event) => {
                  // 中文/日文输入法组词时按 Enter 是上屏，不应触发发送或技能选择
                  if (event.nativeEvent.isComposing || event.keyCode === 229) return;
                  if (slashOpen && slashMatches.length > 0) {
                    if (event.key === "ArrowDown") {
                      event.preventDefault();
                      setSlashIndex((index) => (index + 1) % slashMatches.length);
                      return;
                    }
                    if (event.key === "ArrowUp") {
                      event.preventDefault();
                      setSlashIndex((index) => (index - 1 + slashMatches.length) % slashMatches.length);
                      return;
                    }
                    if (event.key === "Enter") {
                      event.preventDefault();
                      selectSkill(slashMatches[Math.min(slashIndex, slashMatches.length - 1)]);
                      return;
                    }
                    if (event.key === "Escape") {
                      event.preventDefault();
                      setSlashOpen(false);
                      return;
                    }
                  }
                  if (event.key === "Escape" && slashOpen) {
                    event.preventDefault();
                    setSlashOpen(false);
                    return;
                  }
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void send(input);
                  }
                }}
                disabled={busy || hasPendingApproval}
              />
              <button
                type="button"
                className="btn btn-primary h-[42px] w-[42px] shrink-0 px-0"
                onClick={() => void send(input)}
                disabled={busy || hasPendingApproval || (!input.trim() && !activeSkillId)}
                aria-label="发送"
              >
                {busy ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
              </button>
            </div>
          </div>
        </footer>
      </section>

      {mobileSessionsOpen && (
        <div
          className="fixed inset-0 z-40 flex items-end bg-black/30 md:hidden"
          onClick={() => setMobileSessionsOpen(false)}
        >
          <div
            className="max-h-[70vh] w-full overflow-y-auto rounded-t-[16px] border-t border-line bg-surface p-3 shadow-float"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="mb-2 flex items-center justify-between px-1">
              <span className="text-[13px] font-semibold text-ink">会话</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-secondary h-8 px-2.5 text-[12px]"
                  onClick={() => {
                    setMobileSessionsOpen(false);
                    void createSession();
                  }}
                >
                  <Plus size={13} />
                  新建
                </button>
                <button
                  type="button"
                  className="rounded-[8px] p-1.5 text-ink3 transition-colors hover:bg-subtle hover:text-ink"
                  onClick={() => setMobileSessionsOpen(false)}
                  aria-label="关闭会话列表"
                >
                  <X size={15} />
                </button>
              </div>
            </div>
            {sessions.length === 0 && (
              <p className="px-2 py-6 text-center text-[12px] text-ink3">还没有会话，直接提问即可创建</p>
            )}
            {sessionList(() => setMobileSessionsOpen(false))}
          </div>
        </div>
      )}
    </div>
  );
}
