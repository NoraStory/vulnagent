import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
        ws: true
      }
    }
  },
  // vite preview 同样代理 API，避免预览构建产物时收到 index.html 当作 JSON
  preview: {
    port: 4173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
        ws: true
      }
    }
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        // 第三方依赖单独成块，应用代码更新时可复用浏览器缓存
        manualChunks: {
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-markdown": ["react-markdown", "remark-gfm"],
          "vendor-xterm": ["@xterm/xterm", "@xterm/addon-fit", "@xterm/addon-search"]
        }
      }
    }
  }
});
