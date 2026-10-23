import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { CheckCircle2, Info, TriangleAlert } from "lucide-react";

type Tone = "success" | "error" | "info";

interface ToastItem {
  id: number;
  message: string;
  tone: Tone;
}

interface ToastState {
  push: (message: string, tone?: Tone) => void;
}

const ToastContext = createContext<ToastState | null>(null);

let counter = 0;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const push = useCallback((message: string, tone: Tone = "success") => {
    counter += 1;
    const id = counter;
    setItems((current) => [...current, { id, message, tone }]);
    window.setTimeout(() => {
      setItems((current) => current.filter((item) => item.id !== id));
    }, 3600);
  }, []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack pointer-events-none fixed bottom-6 right-6 z-[80] flex w-[320px] flex-col gap-2 transition-[bottom] duration-200">
        {items.map((item) => (
          <div
            key={item.id}
            className="animate-rise pointer-events-auto flex items-start gap-2.5 rounded-panel border border-line bg-surface px-3.5 py-3 text-[13px] text-ink shadow-float"
          >
            <span className="mt-0.5 shrink-0">
              {item.tone === "success" && <CheckCircle2 size={15} className="text-ok" />}
              {item.tone === "error" && <TriangleAlert size={15} className="text-danger" />}
              {item.tone === "info" && <Info size={15} className="text-brand" />}
            </span>
            <span className="leading-[19px]">{item.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastState {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast 必须在 ToastProvider 内使用");
  }
  return context;
}
