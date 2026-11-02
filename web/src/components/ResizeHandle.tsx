import { useCallback, useEffect, useRef } from "react";
import type { CSSProperties, KeyboardEvent, PointerEvent } from "react";

interface ResizeHandleProps {
  value: number;
  min: number;
  max: number;
  /** 拖动方向：面板在右侧传 1（右拖变宽），在左侧传 -1（右拖变窄） */
  direction?: 1 | -1;
  onChange: (value: number) => void;
  onReset: () => void;
  label: string;
  className?: string;
  style?: CSSProperties;
}

/**
 * 竖向拖拽条：支持鼠标/触摸拖拽、方向键微调、Home/End 与双击复位。
 * 需要放在 position: relative 的容器内，由调用方通过 style 定位到列间空隙。
 */
export function ResizeHandle({
  value,
  min,
  max,
  direction = 1,
  onChange,
  onReset,
  label,
  className = "",
  style
}: ResizeHandleProps) {
  const drag = useRef<{ startX: number; startValue: number } | null>(null);

  const clamp = useCallback((next: number) => Math.min(max, Math.max(min, next)), [min, max]);

  const stop = useCallback(() => {
    drag.current = null;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }, []);

  useEffect(() => stop, [stop]);

  const handlePointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { startX: event.clientX, startValue: value };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return;
    const delta = (event.clientX - drag.current.startX) * direction;
    onChange(clamp(drag.current.startValue + delta));
  };

  const handlePointerUp = (event: PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    stop();
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = 16;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      const delta = event.key === "ArrowRight" ? step : -step;
      onChange(clamp(value + delta * direction));
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      onChange(min);
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      onChange(max);
    }
  };

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={Math.round(value)}
      tabIndex={0}
      title={`${label}（拖动调整，双击复位，方向键微调）`}
      className={`group absolute top-0 bottom-0 z-20 w-3 cursor-col-resize touch-none select-none outline-none ${className}`}
      style={style}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerUp}
      onLostPointerCapture={stop}
      onDoubleClick={onReset}
      onKeyDown={handleKeyDown}
    >
      <span className="mx-auto block h-full w-[2px] rounded-full bg-line transition-colors group-hover:bg-brand/60 group-focus-visible:bg-brand/60 group-active:bg-brand" />
    </div>
  );
}
