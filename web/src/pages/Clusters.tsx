import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Boxes,
  CheckCircle2,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  ScanLine,
  Trash2,
  TriangleAlert,
  X
} from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";
import type {
  AssetItem,
  ClusterDetailData,
  ClusterEnvironment,
  ClusterItem,
  ClusterJob,
  ClusterNodeItem,
  ClusterNodeRole,
  ProjectItem,
  SshHost
} from "../lib/types";
import { Empty } from "../components/ui";

const roleLabels: Record<ClusterNodeRole, string> = {
  backend: "后端服务",
  database: "数据库",
  cache: "缓存",
  proxy: "代理/网关",
  storage: "存储",
  scan_target: "扫描目标"
};

const envLabels: Record<ClusterEnvironment, string> = {
  prod: "生产",
  staging: "预发",
  dev: "开发",
  test: "测试",
  other: "其他"
};

const statusMeta: Record<string, { label: string; className: string }> = {
  ok: { label: "正常", className: "bg-okSoft text-ok" },
  failed: { label: "异常", className: "bg-dangerSoft text-danger" },
  unknown: { label: "未检查", className: "bg-subtle text-ink3" }
};

const jobStatusMeta: Record<string, { label: string; className: string }> = {
  queued: { label: "排队中", className: "bg-subtle text-ink3" },
  running: { label: "执行中", className: "bg-brand-soft text-brand" },
  succeeded: { label: "已完成", className: "bg-okSoft text-ok" },
  partial: { label: "部分完成", className: "bg-warnSoft text-warn" },
  failed: { label: "失败", className: "bg-dangerSoft text-danger" },
  canceled: { label: "已取消", className: "bg-subtle text-ink3" }
};

function endpointOf(node: ClusterNodeItem): string {
  if (node.url) return node.url;
  if (node.host) return `${node.host}${node.port ? `:${node.port}` : ""}`;
  if (node.sshHostId) return `SSH 主机 #${node.sshHostId}`;
  return "—";
}

function StatCard({
  label,
  value,
  sub,
  tone,
  onClick
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "normal" | "ok" | "warn" | "danger";
  onClick?: () => void;
}) {
  const toneClass = tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "text-ink";
  const body = (
    <>
      <p className="text-[10.5px] text-ink3">{label}</p>
      <p className={`mt-1 truncate font-mono text-[20px] font-semibold leading-6 ${toneClass}`}>{value}</p>
      {sub && <p className="mt-0.5 truncate text-[10px] text-ink3">{sub}</p>}
    </>
  );
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="card px-3 py-2.5 text-left transition-colors hover:border-brand/40 hover:bg-brand-soft/20"
      >
        {body}
      </button>
    );
  }
  return <div className="card px-3 py-2.5">{body}</div>;
}

export function ClustersPage() {
  const { user, isAdmin } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [clusters, setClusters] = useState<ClusterItem[]>([]);
  const [selectedProject, setSelectedProject] = useState<number>(0);
  const [selectedCluster, setSelectedCluster] = useState<number>(0);
  const [detail, setDetail] = useState<ClusterDetailData | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [projectOpen, setProjectOpen] = useState(false);
  const [clusterOpen, setClusterOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<ProjectItem | null>(null);
  const [editingCluster, setEditingCluster] = useState<ClusterItem | null>(null);
  const [nodeOpen, setNodeOpen] = useState(false);
  const [linkOpen, setLinkOpen] = useState(false);
  const [editingNode, setEditingNode] = useState<ClusterNodeItem | null>(null);
  const [sshHosts, setSshHosts] = useState<SshHost[]>([]);
  const [job, setJob] = useState<ClusterJob | null>(null);
  const [cancelBusy, setCancelBusy] = useState(false);

  const jobRunning = job?.status === "queued" || job?.status === "running";

  const loadProjects = useCallback(async () => {
    const result = await api.projects();
    setProjects(result.items);
    if (result.items.length > 0 && !result.items.some((item) => item.id === selectedProject)) {
      setSelectedProject(result.items[0].id);
    }
  }, [selectedProject]);

  const loadClusters = useCallback(async (projectId: number) => {
    if (!projectId) {
      setClusters([]);
      setSelectedCluster(0);
      return;
    }
    const result = await api.clusters(projectId);
    setClusters(result.items);
    if (result.items.length > 0 && !result.items.some((item) => item.id === selectedCluster)) {
      setSelectedCluster(result.items[0].id);
    }
    if (result.items.length === 0) {
      setSelectedCluster(0);
      setDetail(null);
    }
  }, [selectedCluster]);

  const loadDetail = useCallback(async (clusterId: number) => {
    if (!clusterId) {
      setDetail(null);
      return;
    }
    setLoading(true);
    try {
      setDetail(await api.clusterDetail(clusterId));
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "读取集群详情失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProjects().catch((err) => setError(err instanceof Error ? err.message : "读取项目失败"));
    void api.sshHosts().then((result) => setSshHosts(result.items)).catch(() => undefined);
  }, [loadProjects]);

  useEffect(() => {
    void loadClusters(selectedProject).catch((err) => setError(err instanceof Error ? err.message : "读取集群失败"));
  }, [selectedProject, loadClusters]);

  useEffect(() => {
    void loadDetail(selectedCluster);
  }, [selectedCluster, loadDetail]);

  useEffect(() => {
    setJob(null);
  }, [selectedCluster]);

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) return;
    const jobId = job.id;
    const timer = window.setInterval(() => {
      void api
        .clusterJob(jobId)
        .then(async (next) => {
          setJob(next);
          if (next.status !== "queued" && next.status !== "running") {
            await loadDetail(next.clusterId);
            await loadClusters(selectedProject);
            toast.push(next.message || "任务完成", next.status === "failed" ? "error" : "success");
          }
        })
        .catch(() => undefined);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [job?.id, job?.status, loadDetail, loadClusters, selectedProject, toast]);

  async function refreshAll() {
    await loadProjects();
    await loadClusters(selectedProject);
    await loadDetail(selectedCluster);
  }

  async function startJob(kind: "check" | "scan") {
    if (!selectedCluster || busy || jobRunning) return;
    setBusy(kind);
    try {
      const result = await api.createClusterJob(selectedCluster, kind);
      setJob(result.job);
      toast.push(kind === "check" ? "检查任务已创建" : "扫描任务已创建", "info");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "创建任务失败", "error");
    } finally {
      setBusy("");
    }
  }

  async function cancelJob() {
    if (!job || cancelBusy) return;
    setCancelBusy(true);
    try {
      await api.cancelClusterJob(job.id);
      setJob(await api.clusterJob(job.id));
      toast.push("已取消任务", "info");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "取消任务失败", "error");
    } finally {
      setCancelBusy(false);
    }
  }

  async function checkNode(node: ClusterNodeItem) {
    setBusy(`node-check-${node.id}`);
    try {
      const result = await api.checkClusterNode(node.id);
      toast.push(`${node.name}：${statusMeta[result.status]?.label ?? result.status}`, result.status === "ok" ? "success" : "error");
      await loadDetail(node.clusterId);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "节点检查失败", "error");
    } finally {
      setBusy("");
    }
  }

  async function scanNode(node: ClusterNodeItem) {
    setBusy(`node-scan-${node.id}`);
    try {
      await api.scanClusterNode(node.id);
      toast.push(`${node.name} 扫描完成`, "success");
      await loadDetail(node.clusterId);
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "节点扫描失败", "error");
    } finally {
      setBusy("");
    }
  }

  async function removeNode(node: ClusterNodeItem) {
    if (!window.confirm(`删除节点「${node.name}」？`)) return;
    try {
      await api.deleteClusterNode(node.id);
      await loadDetail(node.clusterId);
      toast.push("节点已删除", "success");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "删除节点失败", "error");
    }
  }

  async function removeCluster(cluster: ClusterItem) {
    if (!isAdmin || !window.confirm(`删除集群「${cluster.name}」及其节点？`)) return;
    try {
      await api.deleteCluster(cluster.id);
      setSelectedCluster(0);
      await refreshAll();
      toast.push("集群已删除", "success");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "删除集群失败", "error");
    }
  }

  async function removeProject(project: ProjectItem) {
    if (!isAdmin || !window.confirm(`删除项目「${project.name}」及其全部集群？`)) return;
    try {
      await api.deleteProject(project.id);
      setSelectedProject(0);
      setSelectedCluster(0);
      await refreshAll();
      toast.push("项目已删除", "success");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "删除项目失败", "error");
    }
  }

  async function unlinkAsset(assetId: number) {
    if (!currentCluster) return;
    try {
      await api.unlinkClusterAsset(currentCluster.id, assetId);
      await loadDetail(currentCluster.id);
      toast.push("已解除资产关联", "success");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "解除关联失败", "error");
    }
  }

  const currentProject = projects.find((item) => item.id === selectedProject) ?? null;
  const currentCluster = clusters.find((item) => item.id === selectedCluster) ?? null;
  const findings = detail?.findings ?? {};
  const canOperate = user?.role === "admin" || user?.role === "operator";
  const clusterQuery = currentCluster
    ? `clusterId=${currentCluster.id}&clusterName=${encodeURIComponent(currentCluster.name)}`
    : "";

  const nodeSummary = useMemo(() => {
    const nodes = detail?.nodes ?? [];
    return {
      total: nodes.length,
      healthy: nodes.filter((node) => node.status === "ok").length,
      failed: nodes.filter((node) => node.status === "failed").length,
      scannable: nodes.filter((node) => node.sshHostId > 0).length
    };
  }, [detail]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-ink text-white">
            <Boxes size={16} />
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-[15px] font-semibold leading-5 text-ink">项目与集群</h2>
            <p className="truncate text-[11px] text-ink3">跨主机后端、数据库与扫描目标的统一运维视图</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => { setEditingProject(null); setProjectOpen(true); }}>
              <Plus size={13} />
              新建项目
            </button>
          )}
          {isAdmin && (
            <button
              type="button"
              className="btn btn-secondary h-8 px-2.5 text-[12px]"
              onClick={() => {
                setEditingCluster(null);
                setClusterOpen(true);
              }}
              disabled={!currentProject}
            >
              <Plus size={13} />
              新建集群
            </button>
          )}
          <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => void refreshAll()} disabled={loading}>
            <RefreshCw size={13} />
            刷新
          </button>
          <button type="button" className="btn btn-secondary h-8 px-2.5 text-[12px]" onClick={() => void startJob("check")} disabled={!currentCluster || busy !== "" || jobRunning}>
            {busy === "check" ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
            检查全部
          </button>
          <button type="button" className="btn btn-primary h-8 px-2.5 text-[12px]" onClick={() => void startJob("scan")} disabled={!currentCluster || busy !== "" || jobRunning || !canOperate}>
            {busy === "scan" ? <Loader2 size={13} className="animate-spin" /> : <ScanLine size={13} />}
            扫描全部
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-card border border-line bg-dangerSoft px-3 py-2 text-[11.5px] text-danger">
          {error}
          <button type="button" className="ml-2 underline" onClick={() => void refreshAll()}>
            重试
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[280px_1fr]">
        <div className="space-y-3">
          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-3 py-2">
              <p className="text-[12px] font-medium text-ink">项目</p>
              <span className="text-[10px] text-ink3">{projects.length} 个</span>
            </div>
            {projects.length === 0 ? (
              <Empty title="暂无项目" description="管理员可创建项目并添加集群" />
            ) : (
              <div className="divide-y divide-line/60">
                {projects.map((project) => (
                  <div
                    key={project.id}
                    className={`flex items-center gap-2 px-3 py-2 ${project.id === selectedProject ? "bg-brand-soft/40" : ""}`}
                  >
                    <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setSelectedProject(project.id)}>
                      <span className="block truncate text-[12px] font-medium text-ink">{project.name}</span>
                      <span className="block truncate text-[10px] text-ink3">
                        {project.clusterCount} 集群 · {project.nodeCount} 节点 {project.owner ? `· ${project.owner}` : ""}
                      </span>
                    </button>
                    {isAdmin && (
                      <button
                        type="button"
                        className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                        onClick={() => {
                          setEditingProject(project);
                          setProjectOpen(true);
                        }}
                        title="编辑项目"
                        aria-label="编辑项目"
                      >
                        <Pencil size={11} />
                      </button>
                    )}
                    {isAdmin && (
                      <button
                        type="button"
                        className="rounded p-1 text-ink3 hover:bg-dangerSoft hover:text-danger"
                        onClick={() => void removeProject(project)}
                        title="删除项目"
                        aria-label="删除项目"
                      >
                        <Trash2 size={11} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-3 py-2">
              <p className="text-[12px] font-medium text-ink">集群</p>
              <span className="text-[10px] text-ink3">{clusters.length} 个</span>
            </div>
            {clusters.length === 0 ? (
              <Empty title="暂无集群" description={currentProject ? "为该项目创建第一个集群" : "先选择项目"} />
            ) : (
              <div className="divide-y divide-line/60">
                {clusters.map((cluster) => (
                  <div
                    key={cluster.id}
                    className={`flex items-center gap-2 px-3 py-2 ${cluster.id === selectedCluster ? "bg-brand-soft/40" : ""}`}
                  >
                    <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setSelectedCluster(cluster.id)}>
                      <span className="flex items-center gap-1.5">
                        <span className="truncate text-[12px] font-medium text-ink">{cluster.name}</span>
                        <span className="shrink-0 rounded-full bg-subtle px-1.5 py-0.5 text-[9px] text-ink3">
                          {envLabels[cluster.environment] ?? cluster.environment}
                        </span>
                      </span>
                      <span className="block truncate text-[10px] text-ink3">
                        {cluster.healthyNodes}/{cluster.nodeCount} 节点正常 · {cluster.assetCount} 资产 · {cluster.openFindings} 漏洞
                      </span>
                    </button>
                    {isAdmin && (
                      <button
                        type="button"
                        className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                        onClick={() => {
                          setEditingCluster(cluster);
                          setClusterOpen(true);
                        }}
                        title="编辑集群"
                        aria-label="编辑集群"
                      >
                        <Pencil size={11} />
                      </button>
                    )}
                    {isAdmin && (
                      <button
                        type="button"
                        className="rounded p-1 text-ink3 hover:bg-dangerSoft hover:text-danger"
                        onClick={() => void removeCluster(cluster)}
                        title="删除集群"
                        aria-label="删除集群"
                      >
                        <Trash2 size={11} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="min-w-0 space-y-3">
          {!currentCluster || !detail ? (
            <div className="card flex h-[240px] items-center justify-center">
              <Empty title="选择一个集群" description="查看节点健康、资产与漏洞分布" />
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4">
                <StatCard
                  label="节点健康"
                  value={`${nodeSummary.healthy}/${nodeSummary.total}`}
                  sub={`异常 ${nodeSummary.failed} · 可扫描 ${nodeSummary.scannable}`}
                  tone={nodeSummary.failed > 0 ? "danger" : nodeSummary.total > 0 ? "ok" : "normal"}
                />
                <StatCard
                  label="关联资产"
                  value={String(currentCluster.assetCount)}
                  sub="扫描后自动归入本集群"
                  onClick={() => navigate(`/assets?${clusterQuery}`)}
                />
                <StatCard
                  label="未关闭漏洞"
                  value={String(currentCluster.openFindings)}
                  sub={`P0 ${findings.P0 ?? 0} · P1 ${findings.P1 ?? 0}`}
                  tone={currentCluster.p0 > 0 ? "danger" : currentCluster.p1 > 0 ? "warn" : "normal"}
                  onClick={() => navigate(`/findings?${clusterQuery}`)}
                />
                <StatCard label="环境" value={envLabels[currentCluster.environment] ?? currentCluster.environment} sub={currentCluster.provider || "未填写云厂商"} />
              </div>

              <div className="card overflow-hidden">
                <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
                  <p className="text-[12px] font-medium text-ink">集群节点</p>
                  <span className="text-[10px] text-ink3">后端 / 数据库 / 缓存 / 代理 / 扫描目标</span>
                  <span className="ml-auto flex items-center gap-2">
                    {canOperate && (
                      <button
                        type="button"
                        className="btn btn-secondary h-7 px-2.5 text-[11px]"
                        onClick={() => {
                          setEditingNode(null);
                          setNodeOpen(true);
                        }}
                      >
                        <Plus size={12} />
                        添加节点
                      </button>
                    )}
                  </span>
                </div>
                {detail.nodes.length === 0 ? (
                  <Empty title="暂无节点" description="添加后端、数据库或扫描目标" />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[860px] border-collapse text-[11.5px]">
                      <thead>
                        <tr className="border-b border-line bg-subtle/60 text-left text-[10px] text-ink3">
                          <th className="px-3 py-1.5 font-medium">节点</th>
                          <th className="px-3 py-1.5 font-medium">角色</th>
                          <th className="px-3 py-1.5 font-medium">地址</th>
                          <th className="px-3 py-1.5 font-medium">状态</th>
                          <th className="px-3 py-1.5 text-right font-medium">延迟</th>
                          <th className="px-3 py-1.5 font-medium">详情</th>
                          <th className="px-3 py-1.5 text-right font-medium">操作</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.nodes.map((node) => {
                          const meta = statusMeta[node.status] ?? statusMeta.unknown;
                          return (
                            <tr key={node.id} className="border-b border-line/60 last:border-0">
                              <td className="px-3 py-1.5">
                                <span className="block text-[11.5px] text-ink">{node.name}</span>
                                {node.note && <span className="block text-[9.5px] text-ink3">{node.note}</span>}
                              </td>
                              <td className="px-3 py-1.5 text-ink2">{roleLabels[node.role] ?? node.role}</td>
                              <td className="max-w-[220px] truncate px-3 py-1.5 font-mono text-[10.5px] text-ink2">{endpointOf(node)}</td>
                              <td className="px-3 py-1.5">
                                <span className={`rounded-full px-1.5 py-0.5 text-[9.5px] ${meta.className}`}>{meta.label}</span>
                              </td>
                              <td className="px-3 py-1.5 text-right font-mono text-[10.5px] text-ink2">
                                {node.latencyMs > 0 ? `${node.latencyMs} ms` : "—"}
                              </td>
                              <td className="max-w-[240px] truncate px-3 py-1.5 text-[10.5px] text-ink3" title={node.detail}>
                                {node.detail || "—"}
                              </td>
                              <td className="px-3 py-1.5 text-right">
                                <span className="inline-flex items-center gap-1">
                                  <button
                                    type="button"
                                    className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                                    onClick={() => void checkNode(node)}
                                    disabled={busy !== ""}
                                    title="健康检查"
                                    aria-label="健康检查"
                                  >
                                    {busy === `node-check-${node.id}` ? <Loader2 size={11} className="animate-spin" /> : <CheckCircle2 size={11} />}
                                  </button>
                                  <button
                                    type="button"
                                    className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink disabled:opacity-40"
                                    onClick={() => void scanNode(node)}
                                    disabled={busy !== "" || node.sshHostId <= 0 || !canOperate}
                                    title={node.sshHostId > 0 ? "只读漏洞扫描" : "未关联 SSH 主机"}
                                    aria-label="漏洞扫描"
                                  >
                                    {busy === `node-scan-${node.id}` ? <Loader2 size={11} className="animate-spin" /> : <ScanLine size={11} />}
                                  </button>
                                  {canOperate && (
                                    <button
                                      type="button"
                                      className="rounded p-1 text-ink3 hover:bg-subtle hover:text-ink"
                                      onClick={() => {
                                        setEditingNode(node);
                                        setNodeOpen(true);
                                      }}
                                      title="编辑节点"
                                      aria-label="编辑节点"
                                    >
                                      <Pencil size={11} />
                                    </button>
                                  )}
                                  {canOperate && (
                                    <button
                                      type="button"
                                      className="rounded p-1 text-ink3 hover:bg-dangerSoft hover:text-danger"
                                      onClick={() => void removeNode(node)}
                                      title="删除节点"
                                      aria-label="删除节点"
                                    >
                                      <Trash2 size={11} />
                                    </button>
                                  )}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {job && (
                <div className="card px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[12px] font-medium text-ink">
                      {job.kind === "scan" ? "扫描任务" : "检查任务"} · {job.done}/{job.total}
                    </p>
                    <span className={`rounded-full px-1.5 py-0.5 text-[9.5px] ${(jobStatusMeta[job.status] ?? jobStatusMeta.queued).className}`}>
                      {(jobStatusMeta[job.status] ?? jobStatusMeta.queued).label}
                    </span>
                    <span className="text-[10px] text-ink3">
                      {job.createdBy || "系统"} · {job.createdAt}
                    </span>
                    {jobRunning && (
                      <button
                        type="button"
                        className="btn btn-secondary ml-auto h-6 px-2 text-[10.5px]"
                        onClick={() => void cancelJob()}
                        disabled={cancelBusy}
                      >
                        {cancelBusy ? <Loader2 size={10} className="animate-spin" /> : <X size={10} />}
                        取消任务
                      </button>
                    )}
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-subtle">
                    <div
                      className={`h-full rounded-full transition-all ${job.status === "failed" ? "bg-danger" : job.status === "partial" ? "bg-warn" : "bg-brand"}`}
                      style={{ width: `${job.total > 0 ? Math.round((job.done / job.total) * 100) : 0}%` }}
                    />
                  </div>
                  {job.message && <p className="mt-1.5 text-[10.5px] text-ink2">{job.message}</p>}
                  <div className="mt-1.5 space-y-1">
                    {job.items.map((item) => (
                      <p key={`${item.nodeId}-${item.status}`} className="flex items-center gap-2 text-[10.5px] text-ink2">
                        {item.status === "ok" ? (
                          <CheckCircle2 size={11} className="shrink-0 text-ok" />
                        ) : item.status === "failed" ? (
                          <TriangleAlert size={11} className="shrink-0 text-danger" />
                        ) : item.status === "running" ? (
                          <Loader2 size={11} className="shrink-0 animate-spin text-brand" />
                        ) : (
                          <TriangleAlert size={11} className="shrink-0 text-ink3" />
                        )}
                        <span className="shrink-0 font-medium text-ink">{item.nodeName}</span>
                        <span className="truncate text-ink3">
                          {item.message || (item.status === "queued" ? "等待执行" : item.status === "running" ? "执行中" : "—")}
                        </span>
                        {item.latencyMs ? <span className="ml-auto shrink-0 font-mono text-[10px] text-ink3">{item.latencyMs} ms</span> : null}
                      </p>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                <div className="card overflow-hidden">
                  <div className="flex items-center justify-between border-b border-line px-3 py-2">
                    <p className="text-[12px] font-medium text-ink">关联资产</p>
                    <span className="flex items-center gap-2">
                      <span className="text-[10px] text-ink3">{detail.assets.length} 项</span>
                      {canOperate && (
                        <button
                          type="button"
                          className="btn btn-secondary h-7 px-2 text-[10.5px]"
                          onClick={() => setLinkOpen(true)}
                        >
                          <Plus size={11} />
                          关联资产
                        </button>
                      )}
                    </span>
                  </div>
                  {detail.assets.length === 0 ? (
                    <Empty title="暂无资产" description="扫描关联 SSH 主机后自动归入集群" />
                  ) : (
                    <div className="max-h-[260px] overflow-auto">
                      <table className="w-full min-w-[420px] border-collapse text-[11px]">
                        <thead className="sticky top-0 bg-subtle/90 backdrop-blur">
                          <tr className="border-b border-line text-left text-[10px] text-ink3">
                            <th className="px-3 py-1.5 font-medium">主机</th>
                            <th className="px-3 py-1.5 font-medium">IP</th>
                            <th className="px-3 py-1.5 font-medium">系统</th>
                            <th className="px-3 py-1.5 font-medium">Agent</th>
                            <th className="px-3 py-1.5 text-right font-medium">操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail.assets.map((asset) => (
                            <tr
                              key={asset.id}
                              className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-subtle/60"
                              onClick={() => navigate(`/assets/${asset.id}`)}
                            >
                              <td className="px-3 py-1.5 text-ink2">{asset.hostname}</td>
                              <td className="px-3 py-1.5 font-mono text-[10.5px] text-ink3">{asset.ip || "—"}</td>
                              <td className="px-3 py-1.5 text-ink3">{asset.osFamily || "—"}</td>
                              <td className="px-3 py-1.5 text-ink3">{asset.agentStatus || "—"}</td>
                              <td className="px-3 py-1.5 text-right">
                                {canOperate && (
                                  <button
                                    type="button"
                                    className="rounded p-1 text-ink3 hover:bg-subtle hover:text-danger"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      void unlinkAsset(asset.id);
                                    }}
                                    title="解除关联"
                                    aria-label="解除关联"
                                  >
                                    <X size={11} />
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                <div className="card px-3 py-2.5">
                  <p className="text-[12px] font-medium text-ink">漏洞分布</p>
                  <div className="mt-2 grid grid-cols-4 gap-2">
                    {(["P0", "P1", "P2", "P3"] as const).map((priority) => (
                      <button
                        key={priority}
                        type="button"
                        className="rounded-[8px] bg-subtle px-2 py-1.5 text-center transition-colors hover:bg-brand-soft/60"
                        onClick={() => navigate(`/findings?${clusterQuery}&priority=${priority}`)}
                      >
                        <p className="text-[9.5px] text-ink3">{priority}</p>
                        <p
                          className={`mt-0.5 font-mono text-[16px] font-semibold ${
                            priority === "P0" && (findings.P0 ?? 0) > 0
                              ? "text-danger"
                              : priority === "P1" && (findings.P1 ?? 0) > 0
                                ? "text-warn"
                                : "text-ink"
                          }`}
                        >
                          {findings[priority] ?? 0}
                        </p>
                      </button>
                    ))}
                  </div>
                  <p className="mt-2 text-[10.5px] leading-[16px] text-ink3">
                    仅统计 open / triaged / fixing 状态的漏洞；数据来自关联资产的扫描结果。
                  </p>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {projectOpen && (
        <ProjectDialog
          project={editingProject}
          onClose={() => {
            setProjectOpen(false);
            setEditingProject(null);
          }}
          onDone={async () => {
            setProjectOpen(false);
            setEditingProject(null);
            await loadProjects();
          }}
        />
      )}
      {clusterOpen && currentProject && (
        <ClusterDialog
          project={currentProject}
          cluster={editingCluster}
          onClose={() => {
            setClusterOpen(false);
            setEditingCluster(null);
          }}
          onDone={async () => {
            setClusterOpen(false);
            setEditingCluster(null);
            await loadClusters(currentProject.id);
          }}
        />
      )}
      {nodeOpen && currentCluster && (
        <NodeDialog
          clusterId={currentCluster.id}
          node={editingNode}
          hosts={sshHosts}
          onClose={() => {
            setNodeOpen(false);
            setEditingNode(null);
          }}
          onDone={async () => {
            setNodeOpen(false);
            setEditingNode(null);
            await loadDetail(currentCluster.id);
          }}
        />
      )}
      {linkOpen && currentCluster && detail && (
        <LinkAssetsDialog
          clusterId={currentCluster.id}
          linked={detail.assets.map((asset) => asset.id)}
          onClose={() => setLinkOpen(false)}
          onDone={async () => {
            setLinkOpen(false);
            await loadDetail(currentCluster.id);
          }}
        />
      )}
    </div>
  );
}

function ModalShell({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 px-4" onClick={onClose}>
      <div className="w-full max-w-[520px] overflow-hidden rounded-card border border-line bg-surface shadow-float" onClick={(event) => event.stopPropagation()}>
        <header className="flex items-center gap-2 border-b border-line px-5 py-3.5">
          <h3 className="text-[14px] font-semibold text-ink">{title}</h3>
          <button type="button" className="ml-auto rounded p-1 text-ink3 hover:bg-subtle hover:text-ink" onClick={onClose} aria-label="关闭">
            <X size={15} />
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}

function ProjectDialog({
  project,
  onClose,
  onDone
}: {
  project?: ProjectItem | null;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const toast = useToast();
  const editing = Boolean(project);
  const [name, setName] = useState(project?.name ?? "");
  const [owner, setOwner] = useState(project?.owner ?? "");
  const [description, setDescription] = useState(project?.description ?? "");
  const [saving, setSaving] = useState(false);

  async function submit() {
    if (!name.trim()) {
      toast.push("请填写项目名称", "error");
      return;
    }
    setSaving(true);
    try {
      const payload = { name: name.trim(), owner: owner.trim(), description: description.trim() };
      if (project) {
        await api.updateProject(project.id, payload);
        toast.push("项目已更新", "success");
      } else {
        await api.createProject(payload);
        toast.push("项目已创建", "success");
      }
      await onDone();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : editing ? "更新项目失败" : "创建项目失败", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title={editing ? "编辑项目" : "新建项目"} onClose={onClose}>
      <div className="space-y-3 px-5 py-4">
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">项目名称</span>
          <input className="input h-9 text-[12.5px]" value={name} onChange={(event) => setName(event.target.value)} placeholder="例如 核心交易系统" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">负责人</span>
          <input className="input h-9 text-[12.5px]" value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="可选" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">说明</span>
          <input className="input h-9 text-[12.5px]" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="可选" />
        </label>
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          取消
        </button>
        <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void submit()} disabled={saving}>
          {saving ? <Loader2 size={13} className="animate-spin" /> : editing ? <Pencil size={13} /> : <Plus size={13} />}
          {editing ? "保存" : "创建"}
        </button>
      </footer>
    </ModalShell>
  );
}

function ClusterDialog({
  project,
  cluster,
  onClose,
  onDone
}: {
  project: ProjectItem;
  cluster?: ClusterItem | null;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const toast = useToast();
  const editing = Boolean(cluster);
  const [name, setName] = useState(cluster?.name ?? "");
  const [environment, setEnvironment] = useState<ClusterEnvironment>(cluster?.environment ?? "prod");
  const [provider, setProvider] = useState(cluster?.provider ?? "");
  const [region, setRegion] = useState(cluster?.region ?? "");
  const [description, setDescription] = useState(cluster?.description ?? "");
  const [saving, setSaving] = useState(false);

  async function submit() {
    if (!name.trim()) {
      toast.push("请填写集群名称", "error");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: name.trim(),
        environment,
        provider: provider.trim(),
        region: region.trim(),
        description: description.trim()
      };
      if (cluster) {
        await api.updateCluster(cluster.id, payload);
        toast.push("集群已更新", "success");
      } else {
        await api.createCluster({ projectId: project.id, ...payload });
        toast.push("集群已创建", "success");
      }
      await onDone();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : editing ? "更新集群失败" : "创建集群失败", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title={`${editing ? "编辑集群" : "新建集群"} · ${project.name}`} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3 px-5 py-4">
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">集群名称</span>
          <input className="input h-9 text-[12.5px]" value={name} onChange={(event) => setName(event.target.value)} placeholder="例如 prod-a / 华东-生产" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">环境</span>
          <select className="input h-9 text-[12.5px]" value={environment} onChange={(event) => setEnvironment(event.target.value as ClusterEnvironment)}>
            {Object.entries(envLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">云厂商</span>
          <input className="input h-9 text-[12.5px]" value={provider} onChange={(event) => setProvider(event.target.value)} placeholder="aliyun / aws / 自建" />
        </label>
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">地域</span>
          <input className="input h-9 text-[12.5px]" value={region} onChange={(event) => setRegion(event.target.value)} placeholder="cn-hangzhou" />
        </label>
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">说明</span>
          <input className="input h-9 text-[12.5px]" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="可选" />
        </label>
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          取消
        </button>
        <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void submit()} disabled={saving}>
          {saving ? <Loader2 size={13} className="animate-spin" /> : editing ? <Pencil size={13} /> : <Plus size={13} />}
          {editing ? "保存" : "创建"}
        </button>
      </footer>
    </ModalShell>
  );
}

function NodeDialog({
  clusterId,
  node,
  hosts,
  onClose,
  onDone
}: {
  clusterId: number;
  node: ClusterNodeItem | null;
  hosts: SshHost[];
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const toast = useToast();
  const [name, setName] = useState(node?.name ?? "");
  const [role, setRole] = useState<ClusterNodeRole>(node?.role ?? "backend");
  const [host, setHost] = useState(node?.host ?? "");
  const [port, setPort] = useState(String(node?.port ?? 0));
  const [url, setUrl] = useState(node?.url ?? "");
  const [sshHostId, setSshHostId] = useState(String(node?.sshHostId ?? 0));
  const [checkType, setCheckType] = useState(node?.checkType ?? "auto");
  const [path, setPath] = useState(node?.path ?? "");
  const [note, setNote] = useState(node?.note ?? "");
  const [saving, setSaving] = useState(false);

  async function submit() {
    if (!name.trim()) {
      toast.push("请填写节点名称", "error");
      return;
    }
    const payload = {
      name: name.trim(),
      role,
      host: host.trim(),
      port: Number(port) || 0,
      url: url.trim(),
      sshHostId: Number(sshHostId) || 0,
      checkType,
      path: path.trim(),
      note: note.trim()
    };
    setSaving(true);
    try {
      if (node) {
        await api.updateClusterNode(node.id, payload);
        toast.push("节点已更新", "success");
      } else {
        await api.createClusterNode(clusterId, payload);
        toast.push("节点已添加", "success");
      }
      await onDone();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "保存节点失败", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title={node ? "编辑节点" : "添加节点"} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3 px-5 py-4">
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">名称</span>
          <input className="input h-9 text-[12.5px]" value={name} onChange={(event) => setName(event.target.value)} placeholder="backend-1" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">角色</span>
          <select className="input h-9 text-[12.5px]" value={role} onChange={(event) => setRole(event.target.value as ClusterNodeRole)}>
            {Object.entries(roleLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">主机</span>
          <input className="input h-9 font-mono text-[11.5px]" value={host} onChange={(event) => setHost(event.target.value)} placeholder="10.0.0.12" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">端口</span>
          <input className="input h-9 font-mono text-[11.5px]" value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" placeholder="5432" />
        </label>
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">健康检查 URL（后端）</span>
          <input className="input h-9 font-mono text-[11.5px]" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="http://10.0.0.12:8787/api/v1/healthz" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">检查方式</span>
          <select className="input h-9 text-[12.5px]" value={checkType} onChange={(event) => setCheckType(event.target.value as typeof checkType)}>
            <option value="auto">自动</option>
            <option value="http">HTTP</option>
            <option value="tcp">TCP</option>
            <option value="ssh">SSH</option>
            <option value="ssh_file">SSH 文件</option>
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] text-ink2">关联 SSH 主机</span>
          <select className="input h-9 text-[12.5px]" value={sshHostId} onChange={(event) => setSshHostId(event.target.value)}>
            <option value="0">不关联</option>
            {hosts.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}（{item.host}）
              </option>
            ))}
          </select>
        </label>
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">文件路径（SQLite 数据库 / 存储）</span>
          <input className="input h-9 font-mono text-[11.5px]" value={path} onChange={(event) => setPath(event.target.value)} placeholder="/var/lib/app/app.db" />
        </label>
        <label className="col-span-2 block">
          <span className="mb-1 block text-[11px] text-ink2">备注</span>
          <input className="input h-9 text-[12.5px]" value={note} onChange={(event) => setNote(event.target.value)} placeholder="负责人、版本或端口说明" />
        </label>
        <p className="col-span-2 rounded-[8px] bg-subtle px-2.5 py-2 text-[10.5px] leading-[16px] text-ink3">
          后端填 URL 走 HTTP 健康检查；数据库填主机+端口走 TCP；SQLite 数据库填关联 SSH 主机与文件路径走远程文件检查。关联 SSH 主机后可一键做只读漏洞扫描。
        </p>
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          取消
        </button>
        <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void submit()} disabled={saving}>
          {saving ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
          保存
        </button>
      </footer>
    </ModalShell>
  );
}

function LinkAssetsDialog({
  clusterId,
  linked,
  onClose,
  onDone
}: {
  clusterId: number;
  linked: number[];
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const toast = useToast();
  const [queryText, setQueryText] = useState("");
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      setLoading(true);
      api
        .assets({ q: queryText.trim(), pageSize: 50 })
        .then((result) => {
          if (active) setAssets(result.items);
        })
        .catch((err) => {
          if (active) toast.push(err instanceof Error ? err.message : "读取资产失败", "error");
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, 250);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [queryText, toast]);

  function toggle(id: number) {
    setSelected((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  }

  async function submit() {
    if (selected.length === 0) {
      toast.push("请选择至少一个资产", "error");
      return;
    }
    setSaving(true);
    try {
      await api.linkClusterAssets(clusterId, selected);
      toast.push(`已关联 ${selected.length} 个资产`, "success");
      await onDone();
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "关联资产失败", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title="关联已有资产" onClose={onClose}>
      <div className="space-y-2 px-5 py-4">
        <input
          className="input h-9 text-[12px]"
          value={queryText}
          onChange={(event) => setQueryText(event.target.value)}
          placeholder="搜索主机名、IP 或业务系统"
        />
        <div className="max-h-[300px] overflow-auto rounded-[8px] border border-line">
          {loading && assets.length === 0 ? (
            <p className="px-3 py-6 text-center text-[11px] text-ink3">正在读取资产…</p>
          ) : assets.length === 0 ? (
            <p className="px-3 py-6 text-center text-[11px] text-ink3">没有匹配的资产</p>
          ) : (
            assets.map((asset) => {
              const already = linked.includes(asset.id);
              return (
                <label
                  key={asset.id}
                  className={`flex items-center gap-2 border-b border-line/60 px-3 py-1.5 text-[11.5px] last:border-0 ${
                    already ? "opacity-50" : ""
                  }`}
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5"
                    checked={already || selected.includes(asset.id)}
                    disabled={already}
                    onChange={() => toggle(asset.id)}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-ink">{asset.hostname}</span>
                    <span className="block truncate text-[10px] text-ink3">
                      {asset.ip || "—"} {asset.businessSystem ? `· ${asset.businessSystem}` : ""}
                    </span>
                  </span>
                  {already && <span className="shrink-0 text-[9.5px] text-ink3">已关联</span>}
                </label>
              );
            })
          )}
        </div>
        <p className="text-[10px] text-ink3">已关联的资产不会重复添加；单次最多 200 个。</p>
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
        <button type="button" className="btn btn-secondary h-8 px-3 text-[12px]" onClick={onClose}>
          取消
        </button>
        <button type="button" className="btn btn-primary h-8 px-3 text-[12px]" onClick={() => void submit()} disabled={saving}>
          {saving ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
          关联 {selected.length > 0 ? `(${selected.length})` : ""}
        </button>
      </footer>
    </ModalShell>
  );
}
