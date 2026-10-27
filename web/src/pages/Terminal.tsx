import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState
} from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import {
  ArrowRight,
  Bot,
  Check,
  ChevronDown,
  CircleAlert,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Send,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  SquareTerminal,
  Trash2,
  Wand2,
  X
} from "lucide-react";
import { api, ApiError, sshTerminalURL } from "../lib/api";
import { timeAgo } from "../lib/format";
import { useToast } from "../lib/toast";
import { Markdown } from "../components/Markdown";
import { Skeleton } from "../components/ui";
import type {
  SshAgentEvent,
  SshAgentMode,
  SshAssistantReply,
  SshHost,
  SshHostInput,
  SshSessionItem
} from "../lib/types";

type ConnStatus = "connecting" | "connected" | "closed" | "failed";

interface OpenTab {
  key: string;
  host: SshHost;
  status: ConnStatus;
  sessionId: string;
  fingerprint: string;
  serverVersion: string;
  error: string;
  reconnectToken: number;
}

interface AiMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  commands?: string[];
}

type AgentStepView = {
  index: number;
  thought: string;
  command: string;
  risk: string;
  approval: string;
  approved?: boolean;
  output?: string;
  exitCode?: number;
};

type AgentPending = {
  id: string;
  index: number;
  command: string;
  risk: string;
  reason: string;
};

type AgentRunView = {
  runId: string;
  status: "running" | "done" | "error";
  goal: string;
  mode: SshAgentMode;
  steps: AgentStepView[];
  summary: string;
  error: string;
  pending?: AgentPending;
};

const agentRiskMeta: Record<string, { label: string; className: string }> = {
  normal: { label: "只读", className: "bg-signal-soft text-signal" },
  high: { label: "需确认", className: "bg-warnSoft text-warn" },
  critical: { label: "高风险", className: "bg-dangerSoft text-danger" }
};

const quickPrompts = [
  { label: "解释最近输出", prompt: "解释最近一段终端输出的含义，并指出是否存在异常。" },
  { label: "下一步排查", prompt: "基于当前终端现场，给出下一步排查步骤与命令。" },
  { label: "安全基线检查", prompt: "检查当前主机的安全基线，给出只读检查命令。" }
];

const statusMeta: Record<ConnStatus, { label: string; dot: string; text: string }> = {
  connecting: { label: "连接中", dot: "#B54708", text: "text-warn" },
  connected: { label: "已连接", dot: "#0E9F8A", text: "text-ok" },
  closed: { label: "已断开", dot: "#667085", text: "text-ink3" },
  failed: { label: "失败", dot: "#B42318", text: "text-danger" }
};

const terminalTheme = {
  background: "#0B1220",
  foreground: "#D7DEEA",
  cursor: "#5B8CFF",
  cursorAccent: "#0B1220",
  selectionBackground: "rgba(91,140,255,0.28)",
  black: "#0B1220",
  red: "#FF6B6B",
  green: "#3DDC97",
  yellow: "#FFC857",
  blue: "#5B8CFF",
  magenta: "#C792EA",
  cyan: "#5AD4E6",
  white: "#D7DEEA",
  brightBlack: "#5A6B85",
  brightRed: "#FF8A8A",
  brightGreen: "#62E8AE",
  brightYellow: "#FFD98A",
  brightBlue: "#84A9FF",
  brightMagenta: "#D7A8F5",
  brightCyan: "#7FE3F0",
  brightWhite: "#FFFFFF"
};

type PaneHandle = {
  send: (text: string) => void;
  focus: () => void;
  recent: () => string;
  fit: () => void;
};

const TerminalPane = forwardRef<
  PaneHandle,
  {
    host: SshHost;
    active: boolean;
    reconnectToken: number;
    onStatus: (state: Partial<Pick<OpenTab, "status" | "sessionId" | "fingerprint" | "serverVersion" | "error">>) => void;
  }
>(function TerminalPane({ host, active, reconnectToken, onStatus }, ref) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const statusRef = useRef<ConnStatus>("connecting");

  useImperativeHandle(ref, () => ({
    send(text: string) {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data: text }));
      }
    },
    focus() {
      termRef.current?.focus();
    },
    recent() {
      const term = termRef.current;
      if (!term) return "";
      const buffer = term.buffer.active;
      const end = buffer.baseY + buffer.cursorY;
      const start = Math.max(0, end - 120);
      const lines: string[] = [];
      for (let i = start; i <= end; i += 1) {
        lines.push(buffer.getLine(i)?.translateToString(true) ?? "");
      }
      return lines.join("\n").slice(-8000);
    },
    fit() {
      fitRef.current?.fit();
    }
  }));

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    statusRef.current = "connecting";
    onStatus({ status: "connecting", error: "", sessionId: "", fingerprint: "" });

    const fontFamily =
      getComputedStyle(document.documentElement).getPropertyValue("--font-mono").trim() ||
      "Consolas, monospace";
    const term = new XTerm({
      fontFamily,
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: true,
      scrollback: 8000,
      theme: terminalTheme,
      allowTransparency: true
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    termRef.current = term;
    fitRef.current = fit;
    try {
      fit.fit();
    } catch {
      /* 容器尚未布局时忽略 */
    }

    const ws = new WebSocket(sshTerminalURL(host.id, term.cols, term.rows));
    wsRef.current = ws;

    ws.onmessage = (event) => {
      let frame: { type?: string; data?: string; status?: string; message?: string; sessionId?: string; fingerprint?: string; serverVersion?: string; code?: number };
      try {
        frame = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (frame.type === "output" && frame.data) {
        const binary = atob(frame.data);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
        term.write(bytes);
        return;
      }
      if (frame.type === "status" && frame.status === "connected") {
        statusRef.current = "connected";
        onStatus({
          status: "connected",
          sessionId: frame.sessionId ?? "",
          fingerprint: frame.fingerprint ?? "",
          serverVersion: frame.serverVersion ?? ""
        });
        return;
      }
      if (frame.type === "exit") {
        statusRef.current = "closed";
        term.write("\r\n\x1b[38;5;245m[会话已结束]\x1b[0m\r\n");
        onStatus({ status: "closed" });
        return;
      }
      if (frame.type === "error") {
        statusRef.current = "failed";
        term.write(`\r\n\x1b[31m[连接失败] ${frame.message ?? ""}\x1b[0m\r\n`);
        onStatus({ status: "failed", error: frame.message ?? "连接失败" });
      }
    };
    ws.onclose = () => {
      if (statusRef.current !== "failed") {
        statusRef.current = "closed";
        onStatus({ status: "closed" });
      }
    };
    ws.onerror = () => {
      if (statusRef.current !== "failed") {
        statusRef.current = "failed";
        term.write("\r\n\x1b[31m[WebSocket 连接异常]\x1b[0m\r\n");
        onStatus({ status: "failed", error: "WebSocket 连接异常" });
      }
    };

    const dataDisposable = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    });

    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        return;
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    });
    observer.observe(container);
    term.focus();

    return () => {
      observer.disconnect();
      dataDisposable.dispose();
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host.id, reconnectToken]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(() => {
      try {
        fitRef.current?.fit();
      } catch {
        /* 忽略隐藏容器 */
      }
      termRef.current?.focus();
    }, 80);
    return () => window.clearTimeout(timer);
  }, [active]);

  return <div ref={containerRef} className="h-full w-full overflow-hidden bg-[#0B1220] px-2 py-2" />;
});

export function TerminalPage() {
  const toast = useToast();
  const [hosts, setHosts] = useState<SshHost[]>([]);
  const [sessions, setSessions] = useState<SshSessionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<SshHost | null>(null);
  const [tabs, setTabs] = useState<OpenTab[]>([]);
  const [activeKey, setActiveKey] = useState("");
  const [aiOpen, setAiOpen] = useState(false);
  const [aiMode, setAiMode] = useState<"chat" | "agent">("chat");
  const [aiByTab, setAiByTab] = useState<Record<string, AiMessage[]>>({});
  const [aiInput, setAiInput] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [agentByTab, setAgentByTab] = useState<Record<string, AgentRunView>>({});
  const [agentGoal, setAgentGoal] = useState("");
  const [agentMode, setAgentMode] = useState<SshAgentMode>("safe");
  const [agentDeciding, setAgentDeciding] = useState(false);
  const [pendingRun, setPendingRun] = useState<{ key: string; id: string; command: string } | null>(null);
  const [showSessions, setShowSessions] = useState(false);

  const paneRefs = useRef(new Map<string, PaneHandle>());
  const aiScrollRef = useRef<HTMLDivElement | null>(null);
  const agentScrollRef = useRef<HTMLDivElement | null>(null);
  const agentAbort = useRef(new Map<string, AbortController>());
  const activeTab = tabs.find((tab) => tab.key === activeKey) ?? null;
  const activeAi = activeTab ? aiByTab[activeTab.key] ?? [] : [];
  const agentState = activeTab ? agentByTab[activeTab.key] : undefined;

  const loadHosts = useCallback(async () => {
    try {
      const result = await api.sshHosts();
      setHosts(result.items ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "读取 SSH 主机失败");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    try {
      const result = await api.sshSessions(20);
      setSessions(result.items ?? []);
    } catch {
      /* 会话记录失败不影响主流程 */
    }
  }, []);

  useEffect(() => {
    void loadHosts();
    void loadSessions();
  }, [loadHosts, loadSessions]);

  useEffect(() => {
    const el = aiScrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [activeAi, aiBusy]);

  useEffect(() => {
    const el = agentScrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [agentState]);

  const filteredHosts = useMemo(() => {
    const keyword = filter.trim().toLowerCase();
    if (!keyword) return hosts;
    return hosts.filter((host) =>
      `${host.name} ${host.host} ${host.username} ${host.tags}`.toLowerCase().includes(keyword)
    );
  }, [hosts, filter]);

  function openHost(host: SshHost) {
    const key = `${host.id}-${Date.now()}`;
    const tab: OpenTab = {
      key,
      host,
      status: "connecting",
      sessionId: "",
      fingerprint: host.hostKey,
      serverVersion: "",
      error: "",
      reconnectToken: 0
    };
    setTabs((prev) => [...prev, tab]);
    setActiveKey(key);
    setPendingRun(null);
  }

  function closeTab(key: string) {
    const remaining = tabs.filter((tab) => tab.key !== key);
    setTabs(remaining);
    if (key === activeKey) {
      setActiveKey(remaining.length > 0 ? remaining[remaining.length - 1].key : "");
    }
    paneRefs.current.delete(key);
    setAiByTab((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
    setPendingRun(null);
  }

  function reconnect(key: string) {
    setTabs((prev) =>
      prev.map((tab) =>
        tab.key === key
          ? {
              ...tab,
              status: "connecting",
              error: "",
              sessionId: "",
              reconnectToken: tab.reconnectToken + 1
            }
          : tab
      )
    );
    toast.push("已重新发起连接", "info");
  }

  function updateTab(key: string, patch: Partial<OpenTab>) {
    setTabs((prev) => prev.map((tab) => (tab.key === key ? { ...tab, ...patch } : tab)));
    if (patch.status === "connected") void loadSessions();
  }

  function pushAi(key: string, message: AiMessage) {
    setAiByTab((prev) => ({ ...prev, [key]: [...(prev[key] ?? []), message] }));
  }

  async function ask(question: string) {
    if (!activeTab || aiBusy) return;
    const text = question.trim();
    if (!text) return;
    const key = activeTab.key;
    const pane = paneRefs.current.get(key);
    pushAi(key, { id: `u-${Date.now()}`, role: "user", content: text });
    setAiInput("");
    setAiBusy(true);
    try {
      const reply: SshAssistantReply = await api.sshAssistant({
        hostId: activeTab.host.id,
        question: text,
        context: pane?.recent() ?? "",
        sessionId: activeTab.sessionId
      });
      pushAi(key, {
        id: `a-${Date.now()}`,
        role: "assistant",
        content: reply.answer,
        commands: reply.commands
      });
    } catch (err) {
      pushAi(key, {
        id: `a-${Date.now()}`,
        role: "assistant",
        content: err instanceof ApiError ? `请求失败：${err.message}` : "AI 助手请求失败，请稍后重试。"
      });
    } finally {
      setAiBusy(false);
    }
  }

  function insertCommand(command: string) {
    if (!activeTab) return;
    paneRefs.current.get(activeTab.key)?.send(command);
    paneRefs.current.get(activeTab.key)?.focus();
    toast.push("命令已插入终端，确认后再回车执行", "info");
  }

  function runCommand(messageId: string, command: string) {
    if (!activeTab) return;
    if (!pendingRun || pendingRun.id !== messageId || pendingRun.command !== command) {
      setPendingRun({ key: activeTab.key, id: messageId, command });
      return;
    }
    const pane = paneRefs.current.get(activeTab.key);
    pane?.send(`${command}\r`);
    pane?.focus();
    setPendingRun(null);
    toast.push("已在终端执行命令", "success");
  }

  function updateAgentState(key: string, patch: (prev: AgentRunView) => AgentRunView) {
    setAgentByTab((prev) => (prev[key] ? { ...prev, [key]: patch(prev[key]) } : prev));
  }

  async function startAgent() {
    if (!activeTab || agentState?.status === "running") return;
    const goal = agentGoal.trim();
    if (!goal) return;
    const key = activeTab.key;
    const controller = new AbortController();
    agentAbort.current.set(key, controller);
    setAgentByTab((prev) => ({
      ...prev,
      [key]: {
        runId: "",
        status: "running",
        goal,
        mode: agentMode,
        steps: [],
        summary: "",
        error: ""
      }
    }));

    const handle = (event: SshAgentEvent) => {
      updateAgentState(key, (current) => {
        const data = event.data ?? {};
        const next: AgentRunView = { ...current, steps: [...current.steps] };
        switch (event.type) {
          case "status":
            next.runId = String(data.runId ?? "");
            break;
          case "step": {
            const index = Number(data.index ?? next.steps.length);
            const step: AgentStepView = {
              index,
              thought: String(data.thought ?? ""),
              command: String(data.command ?? ""),
              risk: String(data.risk ?? "normal"),
              approval: String(data.approval ?? "")
            };
            next.steps = [...next.steps.filter((item) => item.index !== index), step].sort(
              (a, b) => a.index - b.index
            );
            break;
          }
          case "await_approval":
            next.pending = {
              id: String(data.approvalId ?? ""),
              index: Number(data.index ?? 0),
              command: String(data.command ?? ""),
              risk: String(data.risk ?? ""),
              reason: String(data.reason ?? "")
            };
            break;
          case "approval_result": {
            const index = Number(data.index ?? 0);
            next.pending = undefined;
            next.steps = next.steps.map((item) =>
              item.index === index ? { ...item, approved: Boolean(data.approved) } : item
            );
            break;
          }
          case "output": {
            const index = Number(data.index ?? 0);
            next.steps = next.steps.map((item) =>
              item.index === index
                ? { ...item, output: String(data.output ?? ""), exitCode: Number(data.exitCode ?? 0) }
                : item
            );
            break;
          }
          case "done":
            next.status = "done";
            next.summary = String(data.summary ?? "");
            next.pending = undefined;
            break;
          case "error":
            next.status = "error";
            next.error = String(data.message ?? "运行失败");
            next.pending = undefined;
            break;
          default:
            break;
        }
        return next;
      });
    };

    try {
      await api.sshAgentRun(activeTab.host.id, goal, agentMode, handle, controller.signal);
      void loadSessions();
    } catch (err) {
      if (!controller.signal.aborted) {
        updateAgentState(key, (current) => ({
          ...current,
          status: "error",
          error: err instanceof ApiError ? err.message : "Agent 运行失败"
        }));
      }
    } finally {
      agentAbort.current.delete(key);
      updateAgentState(key, (current) =>
        current.status === "running"
          ? { ...current, status: "error", error: current.error || "运行中断" }
          : current
      );
    }
  }

  function stopAgent() {
    if (!activeTab) return;
    const key = activeTab.key;
    agentAbort.current.get(key)?.abort();
    agentAbort.current.delete(key);
    updateAgentState(key, (current) => ({ ...current, status: "error", error: "已手动停止", pending: undefined }));
  }

  async function decideAgent(decision: "approve" | "reject") {
    if (!activeTab || !agentState?.pending || agentDeciding) return;
    const key = activeTab.key;
    const pending = agentState.pending;
    setAgentDeciding(true);
    try {
      await api.sshAgentDecision(pending.id, decision);
      updateAgentState(key, (current) => ({ ...current, pending: undefined }));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "审批失败", "error");
    } finally {
      setAgentDeciding(false);
    }
  }

  async function removeHost(host: SshHost) {
    if (!window.confirm(`确认删除主机「${host.name}」？已保存的凭据会一并删除。`)) return;
    try {
      await api.sshDeleteHost(host.id);
      setHosts((prev) => prev.filter((item) => item.id !== host.id));
      toast.push("主机已删除", "success");
      void loadSessions();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "删除失败", "error");
    }
  }

  const dialog = dialogOpen ? (
    <HostDialog
      host={editing}
      onClose={() => {
        setDialogOpen(false);
        setEditing(null);
      }}
      onSaved={(saved) => {
        setDialogOpen(false);
        setEditing(null);
        setHosts((prev) => {
          const exists = prev.some((item) => item.id === saved.id);
          return exists ? prev.map((item) => (item.id === saved.id ? saved : item)) : [...prev, saved];
        });
        toast.push(editing ? "主机已更新" : "主机已添加", "success");
      }}
    />
  ) : null;

  const aiPanel = (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <Sparkles size={14} className="text-brand" />
        <span className="text-[12.5px] font-semibold text-ink">AI 终端助手</span>
        {activeTab && (
          <span className="ml-auto truncate text-[10.5px] text-ink3">{activeTab.host.name}</span>
        )}
        <button
          type="button"
          className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink xl:hidden"
          onClick={() => setAiOpen(false)}
          aria-label="关闭 AI 面板"
        >
          <X size={14} />
        </button>
      </div>

      <div className="flex items-center gap-1 border-b border-line px-2 py-1.5">
        {[
          { key: "chat" as const, label: "问答", icon: <Sparkles size={11} /> },
          { key: "agent" as const, label: "Agent 自动执行", icon: <Bot size={11} /> }
        ].map((item) => (
          <button
            key={item.key}
            type="button"
            onClick={() => setAiMode(item.key)}
            className={`inline-flex items-center gap-1 rounded-[6px] px-2 py-1 text-[10.5px] transition-colors ${
              aiMode === item.key ? "bg-brand-soft font-medium text-brand-strong" : "text-ink3 hover:text-ink"
            }`}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
        <span className="ml-auto text-[9px] text-ink3">逐步留痕</span>
      </div>

      {aiMode === "chat" ? (
        <>
      <div ref={aiScrollRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto px-3.5 py-3">
        {!activeTab && (
          <p className="rounded-[10px] border border-dashed border-line px-3 py-6 text-center text-[11.5px] text-ink3">
            先在左侧连接一台主机，AI 会读取最近的终端输出并结合现场回答。
          </p>
        )}
        {activeTab && activeAi.length === 0 && (
          <div className="space-y-2">
            <p className="text-[11.5px] leading-[18px] text-ink3">
              直接提问，或选择一个快捷动作。AI 生成的命令不会自动执行，需你确认。
            </p>
            {quickPrompts.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => void ask(item.prompt)}
                className="flex w-full items-center gap-2 rounded-[9px] border border-line bg-surface px-2.5 py-2 text-left text-[11.5px] text-ink2 transition-colors hover:border-lineStrong hover:text-ink"
              >
                <Wand2 size={12} className="shrink-0 text-brand" />
                {item.label}
                <ArrowRight size={12} className="ml-auto text-ink3" />
              </button>
            ))}
          </div>
        )}

        {activeAi.map((message) =>
          message.role === "user" ? (
            <div key={message.id} className="flex justify-end">
              <div className="max-w-[92%] rounded-[10px] rounded-br-[4px] bg-brand px-3 py-2 text-[11.5px] leading-[18px] text-white">
                {message.content}
              </div>
            </div>
          ) : (
            <div key={message.id} className="rounded-[10px] border border-line bg-surface px-3 py-2.5">
              <Markdown content={message.content} />
              {message.commands && message.commands.length > 0 && (
                <div className="mt-2 space-y-1.5">
                  {message.commands.map((command) => {
                    const confirming =
                      pendingRun?.id === message.id && pendingRun.command === command && pendingRun.key === activeTab?.key;
                    return (
                      <div key={command} className="rounded-[8px] border border-line bg-[#0B1220] px-2 py-1.5">
                        <code className="block break-all font-mono text-[11px] leading-[16px] text-[#D7DEEA]">
                          {command}
                        </code>
                        <div className="mt-1.5 flex items-center gap-1.5">
                          <button
                            type="button"
                            className="inline-flex items-center gap-1 rounded-[6px] px-1.5 py-0.5 text-[10.5px] text-ink3 hover:bg-white/10 hover:text-white"
                            onClick={() => insertCommand(command)}
                          >
                            <Plus size={11} />
                            插入
                          </button>
                          <button
                            type="button"
                            className={`inline-flex items-center gap-1 rounded-[6px] px-1.5 py-0.5 text-[10.5px] ${
                              confirming ? "bg-dangerSoft text-danger" : "text-ink3 hover:bg-white/10 hover:text-white"
                            }`}
                            onClick={() => runCommand(message.id, command)}
                          >
                            {confirming ? <Check size={11} /> : <Play size={11} />}
                            {confirming ? "确认执行" : "执行"}
                          </button>
                          {confirming && (
                            <button
                              type="button"
                              className="rounded-[6px] px-1.5 py-0.5 text-[10.5px] text-ink3 hover:text-white"
                              onClick={() => setPendingRun(null)}
                            >
                              取消
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )
        )}
        {aiBusy && (
          <div className="flex items-center gap-2 text-[11.5px] text-ink3">
            <Loader2 size={13} className="animate-spin" />
            正在结合终端现场分析…
          </div>
        )}
      </div>

      <div className="border-t border-line px-3 py-2.5">
        <div className="flex items-end gap-2">
          <textarea
            value={aiInput}
            onChange={(event) => setAiInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.nativeEvent.isComposing || event.keyCode === 229) return;
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void ask(aiInput);
              }
            }}
            rows={2}
            disabled={!activeTab || aiBusy}
            placeholder={activeTab ? "描述问题，Enter 发送，Shift + Enter 换行" : "连接主机后可提问"}
            className="input min-h-[38px] flex-1 resize-none py-2 text-[12px] leading-[18px]"
          />
          <button
            type="button"
            className="btn btn-primary h-[38px] w-[38px] shrink-0 px-0"
            onClick={() => void ask(aiInput)}
            disabled={!activeTab || aiBusy || !aiInput.trim()}
            aria-label="发送"
          >
            {aiBusy ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
          </button>
        </div>
        <p className="mt-1.5 text-[10px] text-ink3">只读取最近终端输出；命令执行前需要二次确认，操作写入审计。</p>
      </div>
        </>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="space-y-2 border-b border-line px-3 py-2.5">
            <div className="flex items-center gap-1.5 text-[10px] text-ink3">
              <Bot size={11} className="text-brand" />
              目标由 AI 拆解为命令并自动执行，危险操作按模式确认
            </div>
            <textarea
              rows={2}
              value={agentGoal}
              onChange={(event) => setAgentGoal(event.target.value)}
              disabled={!activeTab || agentState?.status === "running"}
              placeholder="例如：检查磁盘使用率并找出占用最大的目录"
              className="input min-h-[52px] resize-none py-2 text-[11.5px] leading-[17px]"
            />
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={agentMode}
                onChange={(event) => setAgentMode(event.target.value as SshAgentMode)}
                disabled={agentState?.status === "running"}
                className="input h-7 w-[128px] text-[10.5px]"
              >
                <option value="safe">仅危险确认</option>
                <option value="confirm">逐条确认</option>
                <option value="auto">全自动执行</option>
              </select>
              {agentState?.status === "running" ? (
                <button type="button" className="btn btn-secondary h-7 px-2.5 text-[11px]" onClick={stopAgent}>
                  <Square size={11} />
                  停止
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-primary h-7 px-2.5 text-[11px]"
                  onClick={() => void startAgent()}
                  disabled={!activeTab || !agentGoal.trim()}
                >
                  <Play size={11} />
                  开始执行
                </button>
              )}
              {agentState?.runId && (
                <span className="ml-auto font-mono text-[9px] text-ink3">运行 {agentState.runId.slice(0, 8)}</span>
              )}
            </div>
            {agentMode === "auto" && (
              <p className="rounded-[6px] bg-dangerSoft px-2 py-1 text-[9.5px] leading-[14px] text-danger">
                全自动模式仅 critical 命令需要确认，其余命令会直接执行；所有命令与输出均留痕。
              </p>
            )}
          </div>

          <div ref={agentScrollRef} className="min-h-0 flex-1 space-y-2 overflow-y-auto px-3 py-2.5">
            {!activeTab && (
              <p className="rounded-[10px] border border-dashed border-line px-3 py-6 text-center text-[10.5px] text-ink3">
                先连接一台主机，再启动 Agent。
              </p>
            )}
            {activeTab && !agentState && (
              <div className="space-y-2">
                <p className="text-[10.5px] leading-[17px] text-ink3">
                  Agent 会先做只读侦察，再根据输出决定下一步；每个命令、输出与审批都会留痕。
                </p>
                {[
                  "检查磁盘使用率并找出占用最大的目录",
                  "排查最近异常登录与失败的系统服务",
                  "检查系统安全基线并给出修复建议"
                ].map((goal) => (
                  <button
                    key={goal}
                    type="button"
                    onClick={() => setAgentGoal(goal)}
                    className="flex w-full items-center gap-2 rounded-[8px] border border-line bg-surface px-2.5 py-2 text-left text-[10.5px] text-ink2 transition-colors hover:border-lineStrong hover:text-ink"
                  >
                    <Wand2 size={11} className="shrink-0 text-brand" />
                    {goal}
                    <ArrowRight size={11} className="ml-auto text-ink3" />
                  </button>
                ))}
              </div>
            )}

            {agentState?.steps.map((step) => (
              <div key={step.index} className="rounded-[9px] border border-line bg-surface px-2.5 py-2">
                <div className="flex items-center gap-1.5 text-[9.5px] text-ink3">
                  <span className="font-mono">#{step.index + 1}</span>
                  <span className={`pill h-[18px] px-1.5 text-[9px] ${agentRiskMeta[step.risk]?.className ?? ""}`}>
                    {agentRiskMeta[step.risk]?.label ?? step.risk}
                  </span>
                  {step.approved === false && <span className="text-danger">已拒绝</span>}
                  {step.approved === true && <span className="text-ok">已确认</span>}
                  {step.exitCode !== undefined && (
                    <span className="ml-auto font-mono">exit {step.exitCode}</span>
                  )}
                </div>
                {step.thought && (
                  <p className="mt-1 text-[10.5px] leading-[16px] text-ink2">{step.thought}</p>
                )}
                <pre className="mt-1.5 overflow-x-auto rounded-[6px] bg-[#0B1220] px-2 py-1.5 font-mono text-[10.5px] leading-[15px] text-[#D7DEEA]">
                  {step.command}
                </pre>
                {step.output !== undefined && (
                  <details className="mt-1.5">
                    <summary className="cursor-pointer text-[10px] text-ink3">查看输出</summary>
                    <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-[6px] bg-subtle px-2 py-1.5 font-mono text-[10px] leading-[15px] text-ink2">
                      {step.output || "（无输出）"}
                    </pre>
                  </details>
                )}
              </div>
            ))}

            {agentState?.status === "running" && !agentState.pending && (
              <div className="flex items-center gap-2 text-[10.5px] text-ink3">
                <Loader2 size={12} className="animate-spin" />
                {agentState.steps.length === 0 ? "正在读取主机现场并规划下一步…" : "Agent 执行中，等待命令输出…"}
              </div>
            )}

            {agentState?.pending && (
              <div className="rounded-[9px] border border-[#F5D9B8] bg-warnSoft/70 px-2.5 py-2">
                <div className="flex items-center gap-1.5 text-[10.5px] font-medium text-ink">
                  <ShieldAlert size={12} className="text-warn" />
                  等待你确认执行
                </div>
                <p className="mt-1 text-[9.5px] leading-[14px] text-ink3">{agentState.pending.reason}</p>
                <pre className="mt-1.5 whitespace-pre-wrap break-all rounded-[6px] bg-surface px-2 py-1.5 font-mono text-[10px] text-ink2">
                  {agentState.pending.command}
                </pre>
                <div className="mt-1.5 flex items-center gap-1.5">
                  <button
                    type="button"
                    className="btn btn-primary h-7 px-2.5 text-[10.5px]"
                    onClick={() => void decideAgent("approve")}
                    disabled={agentDeciding}
                  >
                    <Check size={11} />
                    批准执行
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary h-7 px-2.5 text-[10.5px]"
                    onClick={() => void decideAgent("reject")}
                    disabled={agentDeciding}
                  >
                    <X size={11} />
                    拒绝
                  </button>
                </div>
              </div>
            )}

            {agentState?.status === "done" && (
              <div className="rounded-[9px] border border-line bg-subtle/70 px-2.5 py-2">
                <div className="flex items-center gap-1.5 text-[10.5px] font-medium text-ink">
                  <Check size={12} className="text-ok" />
                  执行完成
                </div>
                <p className="mt-1 text-[10.5px] leading-[17px] text-ink2">
                  {agentState.summary || "目标已完成"}
                </p>
              </div>
            )}
            {agentState?.status === "error" && (
              <div className="rounded-[9px] bg-dangerSoft px-2.5 py-2 text-[10.5px] leading-[16px] text-danger">
                {agentState.error}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="flex h-[calc(100dvh-170px)] min-h-[520px] flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-ink text-white">
            <SquareTerminal size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold leading-5 text-ink">SSH 智能终端</h2>
            <p className="truncate text-[11px] text-ink3">
              多主机并发 · AI 现场解读 · 命令确认执行 · 会话全量审计
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn btn-secondary h-8 px-2.5 text-[12px] xl:hidden"
            onClick={() => setAiOpen(true)}
          >
            <Sparkles size={13} />
            AI
          </button>
          <button
            type="button"
            className="btn btn-secondary h-8 px-2.5 text-[12px]"
            onClick={() => {
              setEditing(null);
              setDialogOpen(true);
            }}
          >
            <Plus size={13} />
            新建主机
          </button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 md:grid-cols-[236px_minmax(0,1fr)] xl:grid-cols-[236px_minmax(0,1fr)_340px]">
        <aside className="card hidden min-h-0 flex-col overflow-hidden md:flex">
          <div className="border-b border-line px-3 py-2.5">
            <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-ink2">
              <Server size={12} />
              主机
              <span className="ml-auto text-[10.5px] text-ink3">{hosts.length}</span>
            </div>
            <input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="搜索名称 / 地址 / 标签"
              className="input mt-2 h-7 text-[11.5px]"
            />
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
            {loading && (
              <div className="space-y-2 p-2">
                {[0, 1, 2].map((key) => (
                  <Skeleton key={key} className="h-12 w-full" />
                ))}
              </div>
            )}
            {!loading && error && (
              <div className="p-3 text-[11.5px] text-danger">
                {error}
                <button type="button" className="ml-2 underline" onClick={() => void loadHosts()}>
                  重试
                </button>
              </div>
            )}
            {!loading && !error && filteredHosts.length === 0 && (
              <p className="px-2 py-8 text-center text-[11.5px] text-ink3">
                还没有主机，点击右上角「新建主机」添加。
              </p>
            )}
            {filteredHosts.map((host) => {
              const open = tabs.some((tab) => tab.host.id === host.id);
              return (
                <div
                  key={host.id}
                  className="group mb-1 rounded-[9px] border border-transparent px-2 py-1.5 transition-colors hover:border-line hover:bg-subtle/70"
                >
                  <button type="button" className="w-full text-left" onClick={() => openHost(host)}>
                    <span className="flex items-center gap-1.5">
                      <span className="truncate text-[12px] font-medium text-ink">{host.name}</span>
                      {open && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-signal" />}
                    </span>
                    <span className="mt-0.5 block truncate font-mono text-[10.5px] text-ink3">
                      {host.username}@{host.host}:{host.port}
                    </span>
                    {host.tags && (
                      <span className="mt-1 flex flex-wrap gap-1">
                        {host.tags.split(/[,，\s]+/).filter(Boolean).slice(0, 3).map((tag) => (
                          <span key={tag} className="rounded bg-subtle px-1 py-0.5 text-[9.5px] text-ink3">
                            {tag}
                          </span>
                        ))}
                      </span>
                    )}
                  </button>
                  <div className="mt-1 flex items-center gap-1">
                    <span className="text-[9.5px] text-ink3">
                      {host.lastConnectedAt ? `最近 ${timeAgo(host.lastConnectedAt)}` : "未连接"}
                    </span>
                    <span className="ml-auto flex opacity-0 transition-opacity group-hover:opacity-100">
                      <button
                        type="button"
                        className="rounded p-0.5 text-ink3 hover:bg-surface hover:text-ink"
                        onClick={() => {
                          setEditing(host);
                          setDialogOpen(true);
                        }}
                        aria-label="编辑主机"
                      >
                        <Pencil size={11} />
                      </button>
                      <button
                        type="button"
                        className="rounded p-0.5 text-ink3 hover:bg-surface hover:text-danger"
                        onClick={() => void removeHost(host)}
                        aria-label="删除主机"
                      >
                        <Trash2 size={11} />
                      </button>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="border-t border-line">
            <button
              type="button"
              className="flex w-full items-center gap-1 px-3 py-2 text-[10.5px] text-ink2 hover:bg-subtle"
              onClick={() => {
                setShowSessions((value) => !value);
                if (!showSessions) void loadSessions();
              }}
            >
              <ShieldCheck size={11} />
              最近会话
              <ChevronDown
                size={11}
                className={`ml-auto text-ink3 transition-transform ${showSessions ? "rotate-180" : ""}`}
              />
            </button>
            {showSessions && (
              <div className="max-h-40 overflow-y-auto px-2 pb-2">
                {sessions.length === 0 && <p className="px-1 py-3 text-[10.5px] text-ink3">暂无会话记录</p>}
                {sessions.slice(0, 8).map((item) => (
                  <div key={item.id} className="mb-1 rounded-[7px] bg-subtle/60 px-2 py-1.5">
                    <div className="flex items-center gap-1">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          item.status === "connected"
                            ? "bg-signal"
                            : item.status === "failed"
                              ? "bg-danger"
                              : "bg-ink3"
                        }`}
                      />
                      <span className="truncate text-[10.5px] text-ink">{item.hostName}</span>
                      <span className="ml-auto shrink-0 text-[9.5px] text-ink3">{timeAgo(item.startedAt)}</span>
                    </div>
                    <p className="mt-0.5 truncate text-[9.5px] text-ink3">
                      {item.actor} · {item.addr}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </aside>

        <section className="card flex min-h-0 flex-col overflow-hidden">
          <div className="flex shrink-0 items-stretch overflow-x-auto border-b border-line bg-subtle/40">
            {tabs.map((tab) => {
              const meta = statusMeta[tab.status];
              const active = tab.key === activeKey;
              return (
                <div
                  key={tab.key}
                  role="button"
                  tabIndex={0}
                  onClick={() => setActiveKey(tab.key)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setActiveKey(tab.key);
                    }
                  }}
                  className={`group flex min-w-[150px] max-w-[220px] cursor-pointer items-center gap-1.5 border-r border-line px-2.5 py-2 text-left transition-colors ${
                    active ? "bg-surface" : "hover:bg-subtle"
                  }`}
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: meta.dot }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[11.5px] font-medium text-ink">{tab.host.name}</span>
                    <span className={`block truncate text-[9.5px] ${meta.text}`}>{meta.label}</span>
                  </span>
                  <button
                    type="button"
                    className="rounded p-0.5 text-ink3 opacity-0 hover:bg-subtle hover:text-ink group-hover:opacity-100"
                    onClick={(event) => {
                      event.stopPropagation();
                      closeTab(tab.key);
                    }}
                    aria-label="关闭标签"
                  >
                    <X size={11} />
                  </button>
                </div>
              );
            })}
            <div className="flex flex-1 items-center justify-end gap-1 px-2">
              {activeTab && (
                <>
                  <button
                    type="button"
                    className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                    title="重新连接"
                    onClick={() => reconnect(activeTab.key)}
                  >
                    <RefreshCw size={12} />
                  </button>
                  <button
                    type="button"
                    className="rounded p-1 text-ink3 hover:bg-surface hover:text-ink"
                    title="会话记录"
                    onClick={() => {
                      setShowSessions(true);
                      void loadSessions();
                    }}
                  >
                    <ShieldCheck size={12} />
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="relative min-h-0 flex-1 bg-[#0B1220]">
            {tabs.length === 0 && (
              <div className="flex h-full flex-col items-center justify-center gap-3 px-6 text-center">
                <span className="flex h-11 w-11 items-center justify-center rounded-[13px] bg-white/5 text-[#7FA6FF]">
                  <SquareTerminal size={20} />
                </span>
                <p className="text-[13px] text-[#C7D2E4]">选择左侧主机，开启一个 SSH 会话</p>
                <p className="max-w-[420px] text-[11px] leading-[17px] text-[#6E7F99]">
                  终端通过控制面建立 SSH 连接，凭据使用 AES-256-GCM 加密存放；AI 助手可读取最近输出并生成命令，
                  执行前必须人工确认，连接与命令都会写入审计。
                </p>
              </div>
            )}
            {tabs.map((tab) => (
              <div key={tab.key} className={`absolute inset-0 ${tab.key === activeKey ? "block" : "hidden"}`}>
                <TerminalPane
                  ref={(handle) => {
                    if (handle) paneRefs.current.set(tab.key, handle);
                    else paneRefs.current.delete(tab.key);
                  }}
                  host={tab.host}
                  active={tab.key === activeKey}
                  reconnectToken={tab.reconnectToken}
                  onStatus={(state) => updateTab(tab.key, state)}
                />
              </div>
            ))}
          </div>

          <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-t border-line bg-surface px-3 py-1.5 text-[10px] text-ink3">
            {activeTab ? (
              <>
                <span className={`inline-flex items-center gap-1 ${statusMeta[activeTab.status].text}`}>
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ backgroundColor: statusMeta[activeTab.status].dot }}
                  />
                  {statusMeta[activeTab.status].label}
                </span>
                <span className="font-mono">{activeTab.host.username}@{activeTab.host.host}:{activeTab.host.port}</span>
                {activeTab.serverVersion && <span>SSH {activeTab.serverVersion}</span>}
                {activeTab.sessionId && <span className="font-mono">会话 {activeTab.sessionId.slice(0, 8)}</span>}
                {activeTab.fingerprint && (
                  <span className="font-mono" title={activeTab.fingerprint}>
                    指纹 {activeTab.fingerprint.slice(0, 14)}…
                  </span>
                )}
                {activeTab.error && (
                  <span className="inline-flex items-center gap-1 text-danger">
                    <CircleAlert size={10} />
                    {activeTab.error}
                  </span>
                )}
                {(activeTab.status === "closed" || activeTab.status === "failed") && (
                  <button
                    type="button"
                    className="ml-auto text-brand hover:underline"
                    onClick={() => reconnect(activeTab.key)}
                  >
                    重新连接
                  </button>
                )}
              </>
            ) : (
              <span>未连接主机</span>
            )}
          </div>
        </section>

        <aside className="card hidden min-h-0 flex-col overflow-hidden xl:flex">{aiPanel}</aside>
      </div>

      {aiOpen && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/30 xl:hidden" onClick={() => setAiOpen(false)}>
          <div
            className="h-full w-[360px] max-w-[92vw] border-l border-line bg-surface shadow-float"
            onClick={(event) => event.stopPropagation()}
          >
            {aiPanel}
          </div>
        </div>
      )}

      {dialog}
    </div>
  );
}

function HostDialog({
  host,
  onClose,
  onSaved
}: {
  host: SshHost | null;
  onClose: () => void;
  onSaved: (host: SshHost) => void;
}) {
  const toast = useToast();
  const [form, setForm] = useState({
    name: host?.name ?? "",
    host: host?.host ?? "",
    port: String(host?.port ?? 22),
    username: host?.username ?? "",
    authType: host?.authType ?? "password",
    password: "",
    privateKey: "",
    passphrase: "",
    note: host?.note ?? "",
    tags: host?.tags ?? ""
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState("");
  const [error, setError] = useState("");

  const isEdit = Boolean(host);

  async function save() {
    if (saving) return;
    setError("");
    const port = Number(form.port);
    if (!form.name.trim() || !form.host.trim() || !form.username.trim()) {
      setError("名称、主机地址与用户名不能为空");
      return;
    }
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      setError("端口必须为 1-65535 的整数");
      return;
    }
    if (!isEdit && form.authType === "password" && !form.password) {
      setError("请填写登录口令");
      return;
    }
    if (!isEdit && form.authType === "key" && !form.privateKey.trim()) {
      setError("请粘贴私钥内容");
      return;
    }
    if (isEdit && host && form.authType !== host.authType) {
      if (form.authType === "password" && !form.password) {
        setError("切换为口令认证时需要填写新口令");
        return;
      }
      if (form.authType === "key" && !form.privateKey.trim()) {
        setError("切换为私钥认证时需要粘贴私钥内容");
        return;
      }
    }
    const payload: SshHostInput = {
      name: form.name.trim(),
      host: form.host.trim(),
      port,
      username: form.username.trim(),
      authType: form.authType as "password" | "key",
      note: form.note.trim(),
      tags: form.tags.trim()
    };
    if (form.password) payload.password = form.password;
    if (form.privateKey.trim()) payload.privateKey = form.privateKey.trim();
    if (form.passphrase) payload.passphrase = form.passphrase;
    setSaving(true);
    try {
      const result = isEdit && host
        ? await api.sshUpdateHost(host.id, payload)
        : await api.sshCreateHost(payload);
      onSaved(result.host);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    if (!host || testing) return;
    setTesting(true);
    setTestResult("");
    try {
      const result = await api.sshTestHost(host.id);
      setTestResult(
        `连接成功 · ${result.serverVersion} · ${result.elapsedMs}ms · ${result.fingerprint}${result.trusted ? "" : "（指纹不匹配）"}`
      );
      if (!result.trusted) toast.push("主机指纹与已保存值不一致，请确认目标主机", "error");
    } catch (err) {
      setTestResult(err instanceof ApiError ? err.message : "连接测试失败");
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 px-4" onClick={onClose}>
      <div
        className="w-full max-w-[560px] overflow-hidden rounded-card border border-line bg-surface shadow-float"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center gap-2 border-b border-line px-5 py-3.5">
          <SquareTerminal size={16} className="text-brand" />
          <h3 className="text-[14px] font-semibold text-ink">{isEdit ? "编辑 SSH 主机" : "新建 SSH 主机"}</h3>
          <button
            type="button"
            className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={onClose}
            aria-label="关闭"
          >
            <X size={15} />
          </button>
        </header>

        <div className="max-h-[70vh] space-y-3 overflow-y-auto px-5 py-4">
          <div className="grid grid-cols-2 gap-3">
            <label className="col-span-2 block">
              <span className="mb-1 block text-[11px] text-ink2">名称</span>
              <input
                className="input h-9 text-[12.5px]"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                placeholder="例如 web-01 生产"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">主机地址</span>
              <input
                className="input h-9 font-mono text-[12.5px]"
                value={form.host}
                onChange={(event) => setForm({ ...form, host: event.target.value })}
                placeholder="10.0.0.12 或 host.example.com"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">端口</span>
              <input
                className="input h-9 font-mono text-[12.5px]"
                value={form.port}
                onChange={(event) => setForm({ ...form, port: event.target.value })}
                inputMode="numeric"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">用户名</span>
              <input
                className="input h-9 font-mono text-[12.5px]"
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
                placeholder="root"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">认证方式</span>
              <select
                className="input h-9 text-[12.5px]"
                value={form.authType}
                onChange={(event) => setForm({ ...form, authType: event.target.value as "password" | "key" })}
              >
                <option value="password">口令</option>
                <option value="key">私钥</option>
              </select>
            </label>
          </div>

          {form.authType === "password" ? (
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">
                登录口令{isEdit && host?.hasSecret ? "（留空保持不变）" : ""}
              </span>
              <input
                className="input h-9 text-[12.5px]"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                placeholder={isEdit ? "不修改请留空" : "输入 SSH 登录口令"}
              />
            </label>
          ) : (
            <>
              <label className="block">
                <span className="mb-1 block text-[11px] text-ink2">
                  私钥内容{isEdit && host?.hasSecret ? "（留空保持不变）" : ""}
                </span>
                <textarea
                  className="input min-h-[96px] resize-y font-mono text-[11.5px] leading-[17px]"
                  value={form.privateKey}
                  onChange={(event) => setForm({ ...form, privateKey: event.target.value })}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] text-ink2">私钥口令（可选）</span>
                <input
                  className="input h-9 text-[12.5px]"
                  type="password"
                  autoComplete="new-password"
                  value={form.passphrase}
                  onChange={(event) => setForm({ ...form, passphrase: event.target.value })}
                />
              </label>
            </>
          )}

          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">标签（逗号分隔）</span>
              <input
                className="input h-9 text-[12.5px]"
                value={form.tags}
                onChange={(event) => setForm({ ...form, tags: event.target.value })}
                placeholder="prod, web"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink2">备注</span>
              <input
                className="input h-9 text-[12.5px]"
                value={form.note}
                onChange={(event) => setForm({ ...form, note: event.target.value })}
                placeholder="用途或负责人"
              />
            </label>
          </div>

          {host?.hostKey && (
            <p className="rounded-[8px] bg-subtle px-2.5 py-1.5 font-mono text-[10.5px] text-ink3">
              已信任指纹：{host.hostKey}
            </p>
          )}
          {testResult && (
            <p className={`rounded-[8px] px-2.5 py-1.5 text-[11px] ${testResult.startsWith("连接成功") ? "bg-okSoft text-ok" : "bg-dangerSoft text-danger"}`}>
              {testResult}
            </p>
          )}
          {error && <p className="rounded-[8px] bg-dangerSoft px-2.5 py-1.5 text-[11px] text-danger">{error}</p>}
        </div>

        <footer className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3">
          {isEdit && (
            <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => void test()} disabled={testing}>
              {testing ? <Loader2 size={13} className="animate-spin" /> : <ShieldCheck size={13} />}
              测试连接
            </button>
          )}
          <span className="ml-auto flex items-center gap-2">
            <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
              取消
            </button>
            <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void save()} disabled={saving}>
              {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
              保存
            </button>
          </span>
        </footer>
      </div>
    </div>
  );
}
