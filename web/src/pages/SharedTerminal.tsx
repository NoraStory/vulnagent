import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ArrowLeft, CircleAlert, Eye, Loader2, PenLine, Share2, SquareTerminal } from "lucide-react";
import { api, ApiError, sshSharedTerminalURL } from "../lib/api";
import { formatTime } from "../lib/format";
import { terminalTheme } from "../lib/terminalTheme";
import type { SshShareInfo } from "../lib/types";

type ConnState = "loading" | "connecting" | "connected" | "ended" | "error";

export function SharedTerminalPage() {
  const { token = "" } = useParams();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const statusRef = useRef<ConnState>("loading");
  const [info, setInfo] = useState<SshShareInfo | null>(null);
  const [state, setState] = useState<ConnState>("loading");
  const [error, setError] = useState("");
  const [hasOutput, setHasOutput] = useState(false);

  const setConnState = useCallback((next: ConnState) => {
    statusRef.current = next;
    setState(next);
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .sshShareInfo(token)
      .then((data) => {
        if (cancelled) return;
        setInfo(data);
        setConnState("connecting");
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "分享链接不可用");
        setConnState("error");
      });
    return () => {
      cancelled = true;
    };
  }, [token, setConnState]);

  useEffect(() => {
    if (!info || !containerRef.current) return;
    const container = containerRef.current;
    const canWrite = info.canWrite;
    const term = new XTerm({
      fontFamily:
        getComputedStyle(document.documentElement).getPropertyValue("--font-mono").trim() || "Consolas, monospace",
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: canWrite,
      disableStdin: !canWrite,
      scrollback: 5000,
      theme: terminalTheme
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    termRef.current = term;
    fitRef.current = fit;
    try {
      fit.fit();
    } catch {
      /* 布局尚未完成 */
    }

    const ws = new WebSocket(sshSharedTerminalURL(token, term.cols, term.rows));
    wsRef.current = ws;

    ws.onmessage = (event) => {
      let frame: {
        type?: string;
        data?: string;
        status?: string;
        message?: string;
        code?: number;
        viewers?: number;
      };
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
        setHasOutput(true);
        return;
      }
      if (frame.type === "viewers") {
        setInfo((prev) => (prev ? { ...prev, viewers: frame.viewers ?? 0 } : prev));
        return;
      }
      if (frame.type === "status") {
        if (frame.viewers !== undefined) {
          const nextViewers = frame.viewers;
          setInfo((prev) => (prev ? { ...prev, viewers: nextViewers } : prev));
        }
        setConnState("connected");
        return;
      }
      if (frame.type === "exit") {
        term.write("\r\n\x1b[38;5;245m[会话已结束]\x1b[0m\r\n");
        setConnState("ended");
        return;
      }
      if (frame.type === "error") {
        setError(frame.message ?? "连接失败");
        setConnState("error");
      }
    };
    ws.onclose = () => {
      if (statusRef.current !== "error" && statusRef.current !== "ended") {
        setConnState("ended");
      }
    };
    ws.onerror = () => {
      if (statusRef.current !== "error" && statusRef.current !== "ended") {
        setError("协同连接异常");
        setConnState("error");
      }
    };

    const dataDisposable = term.onData((data) => {
      if (!canWrite) return;
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
    // 仅依赖稳定的会话标识与权限，避免协作者人数变化重建连接
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info?.sessionId, info?.canWrite, token, setConnState]);

  const stateMeta: Record<ConnState, { label: string; className: string }> = {
    loading: { label: "加载中", className: "text-ink3" },
    connecting: { label: "连接中", className: "text-warn" },
    connected: { label: "已连接", className: "text-ok" },
    ended: { label: "会话已结束", className: "text-ink3" },
    error: { label: "不可用", className: "text-danger" }
  };

  return (
    <div className="flex h-[calc(100dvh-170px)] min-h-[520px] flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-ink text-white">
            <Share2 size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold leading-5 text-ink">协同会话</h2>
            <p className="truncate text-[11px] text-ink3">
              {info ? `${info.hostName} · ${info.addr}` : "通过分享链接接入的实时终端"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {info && (
            <span
              className={`inline-flex items-center gap-1 rounded-[6px] px-2 py-1 text-[10.5px] ${
                info.canWrite ? "bg-warnSoft text-warn" : "bg-subtle text-ink2"
              }`}
            >
              {info.canWrite ? <PenLine size={11} /> : <Eye size={11} />}
              {info.canWrite ? "可写" : "只读"}
            </span>
          )}
          <Link to="/terminal" className="btn btn-secondary h-8 px-2.5 text-[12px]">
            <ArrowLeft size={13} />
            返回终端
          </Link>
        </div>
      </div>

      <section className="card flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-subtle/40 px-3 py-2 text-[10px] text-ink3">
          <span className="inline-flex items-center gap-1">
            <SquareTerminal size={11} />
            {info?.sessionId ? `会话 ${info.sessionId.slice(0, 8)}` : "会话"}
          </span>
          <span className={`inline-flex items-center gap-1 ${stateMeta[state].className}`}>
            {state === "connecting" || state === "loading" ? <Loader2 size={10} className="animate-spin" /> : null}
            {stateMeta[state].label}
          </span>
          {info && <span>发起人 {info.owner}</span>}
          {info && <span>{info.viewers} 位协作者</span>}
          {info && <span>{formatTime(info.expiresAt)} 过期</span>}
          {info?.serverVersion && <span>SSH {info.serverVersion}</span>}
        </div>

        {error && (
          <div className="mx-3 mt-3 flex items-center gap-2 rounded-[8px] bg-dangerSoft px-2.5 py-2 text-[11px] text-danger">
            <CircleAlert size={13} />
            {error}
          </div>
        )}

        <div className="relative min-h-0 flex-1 bg-[#0B1220]">
          {info ? (
            <>
              <div ref={containerRef} className="h-full w-full px-2 py-2" />
              {state === "connected" && !hasOutput && (
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-1 text-[11px] text-[#6E7F99]">
                  <Loader2 size={16} className="animate-spin" />
                  已加入协同会话，等待主会话输出…
                </div>
              )}
            </>
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-[11px] text-ink3">
              {state === "loading" ? <Loader2 size={16} className="animate-spin" /> : <CircleAlert size={16} />}
              {state === "loading" ? "正在校验分享链接…" : error || "分享链接不可用"}
            </div>
          )}
        </div>

        {info && (
          <div className="shrink-0 border-t border-line bg-surface px-3 py-1.5 text-[10px] text-ink3">
            {info.canWrite
              ? "可写模式：你的输入会直接发送到主会话并写入审计，请谨慎操作。"
              : "只读模式：你可以实时观看主会话输出，输入不会发送。"}
          </div>
        )}
      </section>
    </div>
  );
}
