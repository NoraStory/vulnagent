import { useCallback, useEffect, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import { CircleAlert, Loader2, Pause, Play, RotateCcw, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { formatTime } from "../lib/format";
import { terminalTheme } from "../lib/terminalTheme";
import type { SshRecording, SshSessionItem } from "../lib/types";

type Props = {
  session: SshSessionItem;
  onClose: () => void;
};

const speedOptions = [1, 2, 4] as const;

function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function formatDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

export function SessionReplay({ session, onClose }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [recording, setRecording] = useState<SshRecording | null>(null);
  const [error, setError] = useState("");
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<(typeof speedOptions)[number]>(1);

  const fit = useCallback(() => {
    try {
      fitRef.current?.fit();
    } catch {
      /* 布局尚未完成时忽略 */
    }
  }, []);

  useEffect(() => {
    const term = new XTerm({
      theme: terminalTheme,
      fontSize: 11.5,
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", "Courier New", monospace',
      lineHeight: 1.35,
      cursorBlink: false,
      disableStdin: true,
      scrollback: 5000,
      convertEol: false
    });
    termRef.current = term;
    term.open(containerRef.current as HTMLDivElement);
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    fitRef.current = fitAddon;
    fitAddon.fit();
    const observer = new ResizeObserver(() => fit());
    if (containerRef.current) observer.observe(containerRef.current);
    return () => {
      observer.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [fit]);

  useEffect(() => {
    let cancelled = false;
    setError("");
    api
      .sshRecording(session.id)
      .then((data) => {
        if (cancelled) return;
        setRecording(data);
        setIndex(0);
        setPlaying(true);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "读取会话录制失败");
      });
    return () => {
      cancelled = true;
    };
  }, [session.id]);

  useEffect(() => {
    if (!playing || !recording) return;
    if (index >= recording.chunks.length) {
      setPlaying(false);
      return;
    }
    const chunk = recording.chunks[index];
    const prevOffset = index === 0 ? 0 : recording.chunks[index - 1].offsetMs;
    const delay = Math.max(0, Math.min(chunk.offsetMs - prevOffset, 3000)) / speed;
    const timer = window.setTimeout(() => {
      try {
        termRef.current?.write(decodeBase64(chunk.data));
      } catch {
        /* 单个分片损坏不影响后续回放 */
      }
      setIndex((value) => value + 1);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [playing, recording, index, speed]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  function restart() {
    termRef.current?.reset();
    setIndex(0);
    setPlaying(true);
  }

  const total = recording?.chunks.length ?? 0;
  const progress = total > 0 ? Math.min(1, index / total) : 0;
  const simulatedMs =
    recording && total > 0
      ? index >= total
        ? recording.durationMs
        : recording.chunks[Math.min(index, total - 1)].offsetMs
      : 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="flex h-[78vh] max-h-[720px] w-[880px] max-w-[96vw] flex-col overflow-hidden rounded-[12px] border border-line bg-surface shadow-float"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="会话回放"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-brand-soft text-brand">
            <Play size={13} />
          </span>
          <div className="min-w-0">
            <p className="truncate text-[12.5px] font-semibold text-ink">会话回放 · {session.hostName}</p>
            <p className="truncate text-[10px] text-ink3">
              {session.actor} · {session.addr} · {formatTime(session.startedAt)} · 会话 {session.id.slice(0, 8)}
            </p>
          </div>
          {recording && (
            <span className="ml-auto shrink-0 text-[10px] text-ink3">
              {formatDuration(recording.durationMs)} · {(recording.bytes / 1024).toFixed(1)} KB
            </span>
          )}
          <button
            type="button"
            className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={onClose}
            aria-label="关闭回放"
          >
            <X size={15} />
          </button>
        </header>

        {error && (
          <div className="mx-4 mt-3 flex items-center gap-2 rounded-[8px] bg-dangerSoft px-2.5 py-2 text-[11px] text-danger">
            <CircleAlert size={13} />
            {error}
          </div>
        )}

        <div className="relative min-h-0 flex-1 bg-[#0B1220]">
          <div ref={containerRef} className="h-full w-full" />
          {!recording && !error && (
            <div className="absolute inset-0 flex items-center gap-2 bg-[#0B1220] px-4 text-[11px] text-ink3">
              <Loader2 size={13} className="animate-spin" />
              正在加载录制…
            </div>
          )}
        </div>

        <footer className="flex shrink-0 flex-wrap items-center gap-2 border-t border-line px-4 py-2">
          <button
            type="button"
            className="btn btn-secondary h-7 px-2.5 text-[11px]"
            onClick={() => {
              if (total > 0 && index >= total) {
                restart();
                return;
              }
              setPlaying((value) => !value);
            }}
            disabled={!recording || total === 0}
          >
            {playing ? (
              <Pause size={11} />
            ) : index >= total && total > 0 ? (
              <RotateCcw size={11} />
            ) : (
              <Play size={11} />
            )}
            {playing ? "暂停" : index >= total && total > 0 ? "重播" : "播放"}
          </button>
          <button
            type="button"
            className="rounded p-1.5 text-ink3 hover:bg-subtle hover:text-ink"
            onClick={restart}
            disabled={!recording || total === 0}
            title="重新播放"
          >
            <RotateCcw size={12} />
          </button>
          <div className="h-1.5 min-w-[120px] flex-1 overflow-hidden rounded-full bg-subtle">
            <div className="h-full rounded-full bg-brand transition-all" style={{ width: `${progress * 100}%` }} />
          </div>
          <span className="font-mono text-[10px] text-ink3">
            {formatDuration(simulatedMs)} / {formatDuration(recording?.durationMs ?? 0)}
          </span>
          <div className="flex items-center gap-0.5 rounded-[6px] bg-subtle p-0.5">
            {speedOptions.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setSpeed(item)}
                className={`rounded px-1.5 py-0.5 text-[10px] ${
                  speed === item ? "bg-surface font-medium text-ink shadow-sm" : "text-ink3 hover:text-ink"
                }`}
              >
                {item}x
              </button>
            ))}
          </div>
          {recording?.truncated && <span className="text-[10px] text-warn">录制达到 2MB 上限，仅保留前段输出</span>}
        </footer>
      </div>
    </div>
  );
}
