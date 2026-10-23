/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: "#F2F2F7",
        surface: "#FFFFFF",
        subtle: "#F7F7FA",
        line: "#E5E5EA",
        lineStrong: "#D1D1D6",
        ink: "#1D1D1F",
        ink2: "#6E6E73",
        ink3: "#8E8E93",
        brand: {
          DEFAULT: "#007AFF",
          strong: "#0064D6",
          soft: "#E8F2FF"
        },
        ok: "#34C759",
        warn: "#FF9F0A",
        danger: "#FF3B30",
        muted: "#8E8E93"
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "\"SF Pro Text\"",
          "\"DM Sans\"",
          "\"PingFang SC\"",
          "\"Microsoft YaHei\"",
          "sans-serif"
        ],
        mono: ["\"JetBrains Mono\"", "ui-monospace", "Consolas", "monospace"]
      },
      borderRadius: {
        card: "18px",
        panel: "14px",
        control: "10px"
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,.04), 0 1px 3px rgba(0,0,0,.05)",
        float: "0 8px 24px -8px rgba(0,0,0,.10), 0 4px 8px -4px rgba(0,0,0,.05)",
        drawer: "-16px 0 48px -24px rgba(0,0,0,.16)"
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
