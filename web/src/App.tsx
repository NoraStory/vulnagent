import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { useAuth } from "./lib/auth";
import { LoginPage } from "./pages/Login";

const OverviewPage = lazy(() => import("./pages/Overview").then((m) => ({ default: m.OverviewPage })));
const FindingsPage = lazy(() => import("./pages/Findings").then((m) => ({ default: m.FindingsPage })));
const AssetsPage = lazy(() => import("./pages/Assets").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage = lazy(() => import("./pages/AssetDetail").then((m) => ({ default: m.AssetDetailPage })));
const DiscoveryPage = lazy(() => import("./pages/Discovery").then((m) => ({ default: m.DiscoveryPage })));
const TopologyPage = lazy(() => import("./pages/Topology").then((m) => ({ default: m.TopologyPage })));
const GovernancePage = lazy(() => import("./pages/Governance").then((m) => ({ default: m.GovernancePage })));
const IntegrationsPage = lazy(() => import("./pages/Integrations").then((m) => ({ default: m.IntegrationsPage })));
const AssistantPage = lazy(() => import("./pages/Assistant").then((m) => ({ default: m.AssistantPage })));
const TerminalPage = lazy(() => import("./pages/Terminal").then((m) => ({ default: m.TerminalPage })));
const HostMonitorPage = lazy(() => import("./pages/HostMonitor").then((m) => ({ default: m.HostMonitorPage })));
const HostAccelPage = lazy(() => import("./pages/HostAccel").then((m) => ({ default: m.HostAccelPage })));
const ClustersPage = lazy(() => import("./pages/Clusters").then((m) => ({ default: m.ClustersPage })));
const AgentsPage = lazy(() => import("./pages/Agents").then((m) => ({ default: m.AgentsPage })));
const SharedTerminalPage = lazy(() =>
  import("./pages/SharedTerminal").then((m) => ({ default: m.SharedTerminalPage }))
);
const TrajectoryPage = lazy(() => import("./pages/Trajectory").then((m) => ({ default: m.TrajectoryPage })));
const SelfCheckPage = lazy(() => import("./pages/SelfCheck").then((m) => ({ default: m.SelfCheckPage })));
const SettingsPage = lazy(() => import("./pages/Settings").then((m) => ({ default: m.SettingsPage })));

function PageFallback() {
  return (
    <div className="flex h-[240px] items-center justify-center">
      <div className="flex items-center gap-2 text-[12.5px] text-ink3">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-lineStrong border-t-brand" />
        正在加载页面…
      </div>
    </div>
  );
}

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
      <Suspense fallback={<PageFallback />}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/assets/:id" element={<AssetDetailPage />} />
          <Route path="/discovery" element={<DiscoveryPage />} />
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/clusters" element={<ClustersPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/governance" element={<GovernancePage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="/assistant" element={<AssistantPage />} />
          <Route path="/terminal" element={<TerminalPage />} />
          <Route path="/terminal/monitor/:id" element={<HostMonitorPage />} />
          <Route path="/terminal/accel/:id" element={<HostAccelPage />} />
          <Route path="/share/:token" element={<SharedTerminalPage />} />
          <Route path="/trajectory" element={<TrajectoryPage />} />
          <Route path="/selfcheck" element={<SelfCheckPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}
