import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { useAuth } from "./lib/auth";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { FindingsPage } from "./pages/Findings";
import { AssetsPage } from "./pages/Assets";
import { AssetDetailPage } from "./pages/AssetDetail";
import { SelfCheckPage } from "./pages/SelfCheck";
import { SettingsPage } from "./pages/Settings";
import { AssistantPage } from "./pages/Assistant";
import { TrajectoryPage } from "./pages/Trajectory";

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-page">
        <div className="flex items-center gap-2 text-[12.5px] text-ink3">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-lineStrong border-t-brand" />
          正在加载控制面…
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:id" element={<AssetDetailPage />} />
        <Route path="/assistant" element={<AssistantPage />} />
        <Route path="/trajectory" element={<TrajectoryPage />} />
        <Route path="/selfcheck" element={<SelfCheckPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
