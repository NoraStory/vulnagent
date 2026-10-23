/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: "var(--color-page)",
        surface: "var(--color-surface)",
        subtle: "var(--color-subtle)",
        line: "var(--color-line)",
        lineStrong: "var(--color-line-strong)",
        ink: "var(--color-ink)",
        ink2: "var(--color-ink-2)",
        ink3: "var(--color-ink-3)",
        brand: {
          DEFAULT: "var(--color-brand)",
          strong: "var(--color-brand-strong)",
          soft: "var(--color-brand-soft)"
        },
        signal: {
          DEFAULT: "var(--color-signal)",
          soft: "var(--color-signal-soft)"
        },
        ok: "var(--color-ok)",
        okSoft: "var(--color-ok-soft)",
        warn: "var(--color-warn)",
        warnSoft: "var(--color-warn-soft)",
        danger: "var(--color-danger)",
        dangerSoft: "var(--color-danger-soft)",
        muted: "var(--color-ink-3)"
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"]
      },
      borderRadius: {
        card: "var(--radius-card)",
        panel: "var(--radius-panel)",
        control: "var(--radius-control)"
      },
      boxShadow: {
        card: "var(--shadow-card)",
        float: "var(--shadow-float)"
      },
      fontSize: {
        micro: ["11px", "16px"],
        label: ["12px", "16px"],
        caption: ["13px", "18px"],
        body: ["14px", "21px"],
        title: ["17px", "24px"],
        h2: ["22px", "28px"],
        h1: ["28px", "34px"],
        metric: ["34px", "40px"]
      }
    }
  },
  plugins: []
};
