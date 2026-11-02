import { useId } from "react";

export interface TrendSeries {
  label: string;
  values: number[];
  color: string;
  fill?: boolean;
}

interface MetricTrendProps {
  title: string;
  series: TrendSeries[];
  max?: number;
  unit?: string;
  height?: number;
  hint?: string;
  formatValue?: (value: number) => string;
}

const WIDTH = 100;
const HEIGHT = 40;
const PAD = 3;

function buildPoints(values: number[], max: number): string {
  if (values.length === 0) return "";
  if (values.length === 1) {
    const y = HEIGHT - PAD - Math.min(1, Math.max(0, values[0] / max)) * (HEIGHT - PAD * 2);
    return `0,${y} ${WIDTH},${y}`;
  }
  return values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * WIDTH;
      const y = HEIGHT - PAD - Math.min(1, Math.max(0, value / max)) * (HEIGHT - PAD * 2);
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

/** 轻量 SVG 趋势图：无第三方依赖，用于实时滚动展示 CPU/内存/负载/网络 */
export function MetricTrend({ title, series, max, unit = "", height = 120, hint, formatValue }: MetricTrendProps) {
  const gradientId = useId().replace(/[:]/g, "");
  const allValues = series.flatMap((item) => item.values);
  const autoMax = Math.max(...allValues, 1);
  const scaleMax = max ?? autoMax * 1.15;
  const format = formatValue ?? ((value: number) => `${value.toFixed(1)}${unit}`);
  const latest = (item: TrendSeries) => (item.values.length > 0 ? item.values[item.values.length - 1] : 0);

  return (
    <div className="card min-w-0 px-3 py-2.5">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[12px] font-medium text-ink">{title}</p>
          {hint && <p className="mt-0.5 truncate text-[10px] text-ink3">{hint}</p>}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-0.5">
          {series.map((item) => (
            <span key={item.label} className="flex items-center gap-1.5 font-mono text-[10.5px] text-ink2">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: item.color }} />
              {item.label}
              <span className="text-ink">{format(latest(item))}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="relative mt-2" style={{ height }}>
        {allValues.length === 0 ? (
          <div className="flex h-full items-center justify-center text-[10.5px] text-ink3">等待采样…</div>
        ) : (
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            preserveAspectRatio="none"
            className="h-full w-full overflow-visible"
            role="img"
            aria-label={title}
          >
            <defs>
              {series.map((item, index) => (
                <linearGradient key={item.label} id={`${gradientId}-${index}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={item.color} stopOpacity="0.22" />
                  <stop offset="100%" stopColor={item.color} stopOpacity="0" />
                </linearGradient>
              ))}
            </defs>
            {[0.25, 0.5, 0.75].map((ratio) => (
              <line
                key={ratio}
                x1="0"
                x2={WIDTH}
                y1={HEIGHT * ratio}
                y2={HEIGHT * ratio}
                stroke="var(--color-line)"
                strokeWidth="0.4"
                vectorEffect="non-scaling-stroke"
              />
            ))}
            {series.map((item, index) => {
              const points = buildPoints(item.values, scaleMax);
              if (!points) return null;
              return (
                <g key={item.label}>
                  {item.fill && (
                    <polygon
                      points={`0,${HEIGHT} ${points} ${WIDTH},${HEIGHT}`}
                      fill={`url(#${gradientId}-${index})`}
                      stroke="none"
                    />
                  )}
                  <polyline
                    points={points}
                    fill="none"
                    stroke={item.color}
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    vectorEffect="non-scaling-stroke"
                  />
                </g>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
}
