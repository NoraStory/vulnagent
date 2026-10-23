import { useMemo } from "react";

interface TrendPoint {
  date: string;
  p0: number;
  p1: number;
  p2: number;
  p3: number;
  total: number;
}

const series = [
  { key: "p3" as const, color: "#C7C7CC", label: "P3 低危" },
  { key: "p2" as const, color: "#FFCC00", label: "P2 中危" },
  { key: "p1" as const, color: "#FF9F0A", label: "P1 高危" },
  { key: "p0" as const, color: "#FF3B30", label: "P0 严重" }
];

export function TrendChart({ data }: { data: TrendPoint[] }) {
  const max = useMemo(() => {
    const peak = Math.max(1, ...data.map((point) => point.total));
    return Math.ceil(peak / 10) * 10;
  }, [data]);

  const ticks = [max, Math.round(max * 0.75), Math.round(max * 0.5), Math.round(max * 0.25), 0];

  return (
    <div className="flex flex-col gap-3 overflow-x-clip">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {series
            .slice()
            .reverse()
            .map((item) => (
              <span key={item.key} className="inline-flex items-center gap-1.5 text-[11.5px] text-ink2">
                <span className="h-2 w-2 rounded-[3px]" style={{ backgroundColor: item.color }} />
                {item.label}
              </span>
            ))}
        </div>
        <span className="text-[11.5px] text-ink3">近 14 天</span>
      </div>

      <div className="flex gap-3">
        <div className="flex h-[176px] w-7 flex-col justify-between pb-5 text-right text-[10.5px] tabular-nums text-ink3">
          {ticks.map((tick) => (
            <span key={tick}>{tick}</span>
          ))}
        </div>

        <div className="relative h-[176px] flex-1">
          <div className="absolute inset-x-0 top-0 bottom-5 flex flex-col justify-between">
            {ticks.map((tick) => (
              <div key={tick} className="h-px w-full bg-line/70" />
            ))}
          </div>

          <div className="relative flex h-full items-end gap-[6px]">
            {data.map((point, index) => {
              const lastIndex = data.length - 1;
              const hideOnMobile =
                (index % 2 === 1 && index !== lastIndex) ||
                (lastIndex % 2 === 1 && index === lastIndex - 1);
              return (
              <div key={point.date} className="group relative flex h-full flex-1 flex-col justify-end">
                <div className="mb-5 flex flex-col-reverse gap-[2px]">
                  {series.map((item) => {
                    const value = point[item.key];
                    if (!value) return null;
                    return (
                      <span
                        key={item.key}
                        className="block w-full rounded-[3px] transition-opacity group-hover:opacity-80"
                        style={{
                          height: `${(value / max) * 116}px`,
                          backgroundColor: item.color
                        }}
                      />
                    );
                  })}
                </div>
                <span
                  className={`absolute -bottom-5 text-[10px] tabular-nums text-ink3 ${
                    index === 0
                      ? "left-0"
                      : index === data.length - 1
                        ? "right-0"
                        : "left-1/2 -translate-x-1/2"
                  } ${hideOnMobile ? "hidden sm:block" : ""}`}
                >
                  {point.date.slice(5).replace("-", "/")}
                </span>

                <div
                  className={`pointer-events-none absolute top-0 z-10 w-[124px] rounded-[10px] border border-line bg-surface/95 px-2.5 py-2 opacity-0 shadow-float backdrop-blur transition-opacity group-hover:opacity-100 ${
                    index < 2
                      ? "left-0"
                      : index >= data.length - 2
                        ? "right-0"
                        : "left-1/2 -translate-x-1/2"
                  }`}
                >
                  <p className="mb-1 text-[10.5px] font-medium text-ink">{point.date}</p>
                  {series
                    .slice()
                    .reverse()
                    .map((item) => (
                      <p key={item.key} className="flex items-center justify-between text-[10.5px] text-ink2">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: item.color }} />
                          {item.label.slice(0, 2)}
                        </span>
                        <span className="tabular-nums text-ink">{point[item.key]}</span>
                      </p>
                    ))}
                </div>
              </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
