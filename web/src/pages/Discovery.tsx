import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Check,
  ChevronDown,
  Loader2,
  Radar,
  RefreshCw,
  ShieldCheck,
  Square,
  X
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { DiscoveryCandidate, DiscoveryJob, DiscoveryPolicy } from "../lib/types";
import { Badge, Empty, Pagination, Skeleton } from "../components/ui";
import { formatTime, timeAgo } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

const JOB_PAGE_SIZE = 8;
const CAND_PAGE_SIZE = 12;

const jobStatusMeta: Record<string, { label: string; tone: "neutral" | "brand" | "success" | "warn" | "danger" }> = {
  pending: { label: "等待中", tone: "neutral" },
  running: { label: "执行中", tone: "brand" },
  completed: { label: "已完成", tone: "success" },
  failed: { label: "失败", tone: "danger" },
  cancelled: { label: "已取消", tone: "warn" }
};

const decisionMeta: Record<string, { label: string; tone: "neutral" | "brand" | "success" | "warn" }> = {
  new: { label: "新发现", tone: "brand" },
  existing: { label: "疑似已有", tone: "warn" },
  approved: { label: "已确认", tone: "success" },
  ignored: { label: "已忽略", tone: "neutral" },
  merged: { label: "已合并", tone: "neutral" }
};

const decisionOptions = [
  { value: "all", label: "全部候选" },
  { value: "new", label: "新发现" },
  { value: "existing", label: "疑似已有" },
  { value: "approved", label: "已确认" },
  { value: "ignored", label: "已忽略" },
  { value: "merged", label: "已合并" }
];

function splitList(value: string): string[] {
  return value
    .split(/[\s,，;；]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePorts(value: string): number[] {
  return splitList(value)
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0 && item <= 65535);
}

export function DiscoveryPage() {
  const { canWrite, isAdmin } = useAuth();
  const toast = useToast();

  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [jobTotal, setJobTotal] = useState(0);
  const [jobPage, setJobPage] = useState(1);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [form, setForm] = useState({ name: "", cidrs: "", ports: "" });
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");
  const [cancelling, setCancelling] = useState<number | null>(null);

  const [policy, setPolicy] = useState<DiscoveryPolicy | null>(null);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [policyDraft, setPolicyDraft] = useState({ cidrs: "", ports: "", maxHosts: "", maxConcurrency: "", timeoutMs: "", maxJobsPerHour: "" });
  const [policySaving, setPolicySaving] = useState(false);

  const [jobFilter, setJobFilter] = useState(0);
  const [decision, setDecision] = useState("new");
  const [query, setQuery] = useState("");
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [candidateTotal, setCandidateTotal] = useState(0);
  const [candidatePage, setCandidatePage] = useState(1);
  const [candidatesLoading, setCandidatesLoading] = useState(true);
  const [selected, setSelected] = useState<number[]>([]);
  const [acting, setActing] = useState<number | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);
  const [merging, setMerging] = useState<DiscoveryCandidate | null>(null);
  const [mergeTarget, setMergeTarget] = useState("");
  const [mergeBusy, setMergeBusy] = useState(false);
  const [error, setError] = useState("");

  const loadJobs = useCallback(async () => {
    try {
      const result = await api.discoveryJobs({ page: jobPage, pageSize: JOB_PAGE_SIZE });
      setJobs(result.items ?? []);
      setJobTotal(result.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载发现任务失败");
    } finally {
      setJobsLoading(false);
    }
  }, [jobPage]);

  const loadCandidates = useCallback(async () => {
    setCandidatesLoading(true);
    try {
      const result = await api.discoveryCandidates({
        page: candidatePage,
        pageSize: CAND_PAGE_SIZE,
        jobId: jobFilter || undefined,
        decision: decision === "all" ? undefined : decision,
        q: query.trim() || undefined
      });
      setCandidates(result.items ?? []);
      setCandidateTotal(result.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载候选资产失败");
    } finally {
      setCandidatesLoading(false);
    }
  }, [candidatePage, jobFilter, decision, query]);

  const loadPolicy = useCallback(async () => {
    try {
      const result = await api.discoveryPolicy();
      setPolicy(result.policy);
    } catch {
      /* 策略读取失败不阻塞页面 */
    }
  }, []);

  useEffect(() => {
    void loadJobs();
    void loadPolicy();
  }, [loadJobs, loadPolicy]);

  const debouncedQuery = useMemo(() => query.trim(), [query]);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadCandidates();
    }, debouncedQuery === "" ? 0 : 320);
    return () => window.clearTimeout(timer);
  }, [loadCandidates, debouncedQuery]);

  const running = jobs.some((job) => job.status === "pending" || job.status === "running");
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      void loadJobs();
      void loadCandidates();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [running, loadJobs, loadCandidates]);

  useEffect(() => {
    setSelected([]);
  }, [candidatePage, decision, jobFilter]);

  const openPolicy = () => {
    if (!policy) return;
    setPolicyDraft({
      cidrs: policy.allowedCidrs.join(", "),
      ports: policy.defaultPorts.join(", "),
      maxHosts: String(policy.maxHosts),
      maxConcurrency: String(policy.maxConcurrency),
      timeoutMs: String(policy.timeoutMs),
      maxJobsPerHour: String(policy.maxJobsPerHour)
    });
    setPolicyOpen((open) => !open);
  };

  const submitJob = async (event: React.FormEvent) => {
    event.preventDefault();
    const cidrs = splitList(form.cidrs);
    if (cidrs.length === 0) {
      toast.push("请填写至少一个网段，例如 10.20.9.0/24", "error");
      return;
    }
    const ports = parsePorts(form.ports);
    if (form.ports.trim() !== "" && ports.length === 0) {
      toast.push("端口格式不正确，请填写 1-65535 的数字", "error");
      return;
    }
    setSubmitting(true);
    setFormError("");
    try {
      const result = await api.createDiscoveryJob({
        name: form.name.trim() || undefined,
        cidrs,
        ports: ports.length > 0 ? ports : undefined
      });
      toast.push(`发现任务已创建：${result.job.total} 台主机待扫描`, "success");
      setForm((prev) => ({ ...prev, name: "" }));
      setJobPage(1);
      await loadJobs();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "创建发现任务失败";
      setFormError(message);
      toast.push(message, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const cancelJob = async (job: DiscoveryJob) => {
    setCancelling(job.id);
    try {
      await api.cancelDiscoveryJob(job.id);
      toast.push(`已请求取消「${job.name}」`, "info");
      await loadJobs();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "取消失败", "error");
    } finally {
      setCancelling(null);
    }
  };

  const savePolicy = async () => {
    if (!policy) return;
    const cidrs = splitList(policyDraft.cidrs);
    if (cidrs.length === 0) {
      toast.push("授权网段不能为空", "error");
      return;
    }
    setPolicySaving(true);
    try {
      const ports = parsePorts(policyDraft.ports);
      const result = await api.updateDiscoveryPolicy({
        ...policy,
        allowedCidrs: cidrs,
        defaultPorts: ports.length > 0 ? ports : policy.defaultPorts,
        maxHosts: Number(policyDraft.maxHosts) || policy.maxHosts,
        maxConcurrency: Number(policyDraft.maxConcurrency) || policy.maxConcurrency,
        timeoutMs: Number(policyDraft.timeoutMs) || policy.timeoutMs,
        maxJobsPerHour: Number(policyDraft.maxJobsPerHour) || policy.maxJobsPerHour
      });
      setPolicy(result.policy);
      setPolicyOpen(false);
      toast.push("发现策略已保存", "success");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "保存策略失败", "error");
    } finally {
      setPolicySaving(false);
    }
  };

  const decide = async (candidate: DiscoveryCandidate, action: "approve" | "ignore") => {
    setActing(candidate.id);
    try {
      const result = await api.decideDiscoveryCandidate(candidate.id, action);
      if (action === "approve") {
        toast.push(`已确认 ${candidate.ip}${result.assetId ? ` → 资产 #${result.assetId}` : ""}`, "success");
      } else {
        toast.push(`已忽略 ${candidate.ip}`, "info");
      }
      await loadCandidates();
      await loadJobs();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "操作失败", "error");
    } finally {
      setActing(null);
    }
  };

  const runBatch = async (action: "approve" | "ignore") => {
    if (selected.length === 0) return;
    setBatchBusy(true);
    try {
      const result = await api.batchDiscoveryCandidates(selected, action);
      const failed = result.failed.length > 0 ? `，失败 ${result.failed.length}` : "";
      toast.push(`批量${action === "approve" ? "确认" : "忽略"} ${result.processed} 个${failed}`, result.failed.length ? "error" : "success");
      setSelected([]);
      await loadCandidates();
      await loadJobs();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "批量操作失败", "error");
    } finally {
      setBatchBusy(false);
    }
  };

  const submitMerge = async () => {
    if (!merging) return;
    const assetId = Number(mergeTarget);
    if (!assetId) {
      toast.push("请输入目标资产 ID", "error");
      return;
    }
    setMergeBusy(true);
    try {
      await api.decideDiscoveryCandidate(merging.id, "merge", { assetId });
      toast.push(`已把 ${merging.ip} 合并到资产 #${assetId}`, "success");
      setMerging(null);
      setMergeTarget("");
      await loadCandidates();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "合并失败", "error");
    } finally {
      setMergeBusy(false);
    }
  };

  const toggleSelected = (id: number) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const pageSelectable = candidates.filter((item) => item.decision === "new" || item.decision === "existing");

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-[9px] bg-brand-soft text-brand-strong">
              <Radar size={16} />
            </span>
            <div>
              <h2 className="text-[14.5px] font-semibold text-ink">发起网段发现</h2>
              <p className="mt-0.5 text-[11.5px] text-ink3">
                仅允许授权内网 CIDR；TCP 探活 + 反向 DNS，不发送任何业务请求
              </p>
            </div>
          </div>
          {policy && (
            <div className="flex flex-wrap items-center gap-1.5">
              {policy.allowedCidrs.map((cidr) => (
                <span key={cidr} className="pill bg-subtle text-[10.5px] text-ink2">{cidr}</span>
              ))}
              <span className="text-[10.5px] text-ink3">· 上限 {policy.maxHosts} 台</span>
            </div>
          )}
        </div>
        <form onSubmit={(event) => void submitJob(event)} className="border-t border-line px-5 py-4">
          <div className="grid gap-3 lg:grid-cols-[1.2fr_1.6fr_1fr_auto]">
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">任务名称（可选）</span>
              <input
                className="input h-9 text-[12.5px]"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                placeholder="例如：办公网周巡检"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">网段（支持多个，逗号或空格分隔）</span>
              <input
                className="input h-9 font-mono text-[12px]"
                value={form.cidrs}
                onChange={(event) => setForm({ ...form, cidrs: event.target.value })}
                placeholder="10.20.9.0/24, 10.20.10.0/28"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] text-ink3">端口（留空用默认）</span>
              <input
                className="input h-9 font-mono text-[12px]"
                value={form.ports}
                onChange={(event) => setForm({ ...form, ports: event.target.value })}
                placeholder="22,80,443,3389"
              />
            </label>
            <div className="flex items-end">
              <button type="submit" className="btn btn-primary h-9 w-full lg:w-auto" disabled={!canWrite || submitting}>
                {submitting ? <Loader2 size={13} className="animate-spin" /> : <Radar size={13} />}
                开始发现
              </button>
            </div>
          </div>
          {!canWrite && <p className="mt-2 text-[11px] text-ink3">当前角色只读，无法发起发现任务。</p>}
          {formError && <p className="mt-2 text-[11.5px] text-[#C4170E]">{formError}</p>}
        </form>

        {isAdmin && policy && (
          <div className="border-t border-line px-5 py-3">
            <button type="button" className="flex items-center gap-1.5 text-[11.5px] text-ink2 transition-colors hover:text-ink" onClick={openPolicy}>
              <ShieldCheck size={13} />
              授权范围与限速设置
              <ChevronDown size={12} className={`transition-transform ${policyOpen ? "rotate-180" : ""}`} />
            </button>
            {policyOpen && (
              <div className="mt-3 grid gap-3 rounded-panel bg-subtle/50 p-3.5 lg:grid-cols-2">
                <label className="block lg:col-span-2">
                  <span className="mb-1 block text-[11px] text-ink3">授权网段（任务必须落在这些网段内）</span>
                  <input
                    className="input h-9 font-mono text-[12px]"
                    value={policyDraft.cidrs}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, cidrs: event.target.value })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">默认端口</span>
                  <input
                    className="input h-9 font-mono text-[12px]"
                    value={policyDraft.ports}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, ports: event.target.value })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">单任务最大主机数</span>
                  <input
                    className="input h-9 text-[12px]"
                    value={policyDraft.maxHosts}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, maxHosts: event.target.value.replace(/[^0-9]/g, "") })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">最大并发</span>
                  <input
                    className="input h-9 text-[12px]"
                    value={policyDraft.maxConcurrency}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, maxConcurrency: event.target.value.replace(/[^0-9]/g, "") })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">单端口超时（毫秒）</span>
                  <input
                    className="input h-9 text-[12px]"
                    value={policyDraft.timeoutMs}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, timeoutMs: event.target.value.replace(/[^0-9]/g, "") })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-ink3">每小时任务上限</span>
                  <input
                    className="input h-9 text-[12px]"
                    value={policyDraft.maxJobsPerHour}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, maxJobsPerHour: event.target.value.replace(/[^0-9]/g, "") })}
                  />
                </label>
                <div className="flex items-end justify-end lg:col-span-2">
                  <button type="button" className="btn btn-primary h-8" onClick={() => void savePolicy()} disabled={policySaving}>
                    {policySaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                    保存策略
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {error && (
        <div className="card flex items-center justify-between gap-3 px-5 py-3 text-[12px] text-[#C4170E]">
          {error}
          <button type="button" className="btn btn-ghost h-7" onClick={() => setError("")}>
            <X size={12} />
          </button>
        </div>
      )}

      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3.5">
          <div>
            <h3 className="text-[13.5px] font-semibold text-ink">发现任务</h3>
            <p className="mt-0.5 text-[11px] text-ink3">同一时间只允许一个任务执行；进度每 3 秒刷新</p>
          </div>
          <button type="button" className="btn btn-secondary h-8" onClick={() => void loadJobs()}>
            <RefreshCw size={13} />
            刷新
          </button>
        </div>
        <div className="divider" />
        {jobsLoading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2].map((key) => <Skeleton key={key} className="h-11 w-full" />)}
          </div>
        ) : jobs.length === 0 ? (
          <Empty title="还没有发现任务" description="在上方填写授权网段后发起第一次网段发现。" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th pl-5">任务</th>
                  <th className="th w-[210px] hidden lg:table-cell">网段 / 端口</th>
                  <th className="th w-[92px]">状态</th>
                  <th className="th w-[190px]">进度</th>
                  <th className="th w-[80px] text-right">发现</th>
                  <th className="th w-[120px] hidden xl:table-cell">创建人</th>
                  <th className="th w-[110px] pr-5 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const meta = jobStatusMeta[job.status] ?? jobStatusMeta.pending;
                  const percent = job.total > 0 ? Math.min(100, Math.round((job.scanned / job.total) * 100)) : 0;
                  return (
                    <tr key={job.id} className="border-b border-line/70 last:border-0">
                      <td className="td pl-5">
                        <span className="block text-[12.5px] font-medium text-ink">{job.name}</span>
                        <span className="mt-0.5 block text-[10.5px] text-ink3">
                          #{job.id} · {timeAgo(job.createdAt)}
                          {job.error ? ` · ${job.error}` : ""}
                        </span>
                      </td>
                      <td className="td hidden font-mono text-[11px] text-ink2 lg:table-cell">
                        <span className="block truncate">{job.cidrs}</span>
                        <span className="mt-0.5 block text-ink3">端口 {job.ports}</span>
                      </td>
                      <td className="td"><Badge tone={meta.tone}>{meta.label}</Badge></td>
                      <td className="td">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-subtle">
                            <div
                              className={`h-full rounded-full ${job.status === "failed" ? "bg-[#C4170E]" : "bg-brand"}`}
                              style={{ width: `${job.status === "completed" ? 100 : percent}%` }}
                            />
                          </div>
                          <span className="w-[68px] shrink-0 text-right text-[10.5px] tabular-nums text-ink3">
                            {job.scanned}/{job.total}
                          </span>
                        </div>
                      </td>
                      <td className="td text-right tabular-nums text-ink">{job.found}</td>
                      <td className="td hidden text-[11.5px] text-ink2 xl:table-cell">{job.createdBy}</td>
                      <td className="td pr-5 text-right">
                        {(job.status === "pending" || job.status === "running") && canWrite ? (
                          <button
                            type="button"
                            className="btn btn-ghost h-7 px-2 text-[11px]"
                            onClick={() => void cancelJob(job)}
                            disabled={cancelling === job.id}
                          >
                            {cancelling === job.id ? <Loader2 size={12} className="animate-spin" /> : <Square size={11} />}
                            取消
                          </button>
                        ) : (
                          <span className="text-[10.5px] text-ink3">{job.finishedAt ? formatTime(job.finishedAt) : "—"}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {jobTotal > JOB_PAGE_SIZE && (
          <>
            <div className="divider" />
            <Pagination page={jobPage} pageSize={JOB_PAGE_SIZE} total={jobTotal} onChange={setJobPage} />
          </>
        )}
      </section>

      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3.5">
          <div>
            <h3 className="text-[13.5px] font-semibold text-ink">候选资产</h3>
            <p className="mt-0.5 text-[11px] text-ink3">确认后写入资产台账；疑似已有可合并到现有资产</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="input h-8 w-[140px] text-[12px]"
              value={jobFilter}
              onChange={(event) => {
                setJobPage(1);
                setCandidatePage(1);
                setJobFilter(Number(event.target.value));
              }}
              aria-label="按任务筛选"
            >
              <option value={0}>全部任务</option>
              {jobs.map((job) => (
                <option key={job.id} value={job.id}>#{job.id} {job.name}</option>
              ))}
            </select>
            <select
              className="input h-8 w-[118px] text-[12px]"
              value={decision}
              onChange={(event) => {
                setCandidatePage(1);
                setDecision(event.target.value);
              }}
              aria-label="按处置状态筛选"
            >
              {decisionOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <input
              className="input h-8 w-[170px] text-[12px]"
              value={query}
              onChange={(event) => {
                setCandidatePage(1);
                setQuery(event.target.value);
              }}
              placeholder="搜索 IP / 主机名"
            />
          </div>
        </div>

        {selected.length > 0 && canWrite && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line bg-subtle/50 px-5 py-2.5">
            <span className="text-[11.5px] text-ink2">已选 {selected.length} 个候选</span>
            <button type="button" className="btn btn-primary h-7 text-[11px]" onClick={() => void runBatch("approve")} disabled={batchBusy}>
              {batchBusy ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              批量确认
            </button>
            <button type="button" className="btn btn-secondary h-7 text-[11px]" onClick={() => void runBatch("ignore")} disabled={batchBusy}>
              批量忽略
            </button>
            <button type="button" className="btn btn-ghost h-7 text-[11px]" onClick={() => setSelected([])}>
              清除选择
            </button>
          </div>
        )}

        {merging && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line bg-[#FFF8F0] px-5 py-2.5">
            <span className="text-[11.5px] text-[#9A5B00]">把 {merging.ip} 合并到资产</span>
            <input
              className="input h-7 w-[140px] text-[11.5px]"
              value={mergeTarget}
              onChange={(event) => setMergeTarget(event.target.value.replace(/[^0-9]/g, ""))}
              placeholder="目标资产 ID"
              inputMode="numeric"
            />
            <button type="button" className="btn btn-secondary h-7 text-[11px]" onClick={() => void submitMerge()} disabled={mergeBusy}>
              {mergeBusy ? <Loader2 size={12} className="animate-spin" /> : null}
              确认合并
            </button>
            <button type="button" className="btn btn-ghost h-7 text-[11px]" onClick={() => { setMerging(null); setMergeTarget(""); }}>
              取消
            </button>
          </div>
        )}

        <div className="divider" />

        {candidatesLoading ? (
          <div className="flex flex-col gap-2 p-5">
            {[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-11 w-full" />)}
          </div>
        ) : candidates.length === 0 ? (
          <Empty title="没有匹配的候选资产" description="换一个筛选条件，或先执行一次网段发现。" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th className="th w-[44px] pl-5">
                    <input
                      type="checkbox"
                      aria-label="全选当前页"
                      checked={pageSelectable.length > 0 && pageSelectable.every((item) => selected.includes(item.id))}
                      onChange={(event) => {
                        setSelected(event.target.checked ? pageSelectable.map((item) => item.id) : []);
                      }}
                    />
                  </th>
                  <th className="th w-[190px]">主机</th>
                  <th className="th w-[100px]">开放端口</th>
                  <th className="th">证据</th>
                  <th className="th w-[132px]">匹配资产</th>
                  <th className="th w-[92px]">处置</th>
                  <th className="th w-[170px] pr-5 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((candidate) => {
                  const meta = decisionMeta[candidate.decision] ?? decisionMeta.new;
                  const pending = candidate.decision === "new" || candidate.decision === "existing";
                  return (
                    <tr key={candidate.id} className="border-b border-line/70 last:border-0 hover:bg-subtle/50">
                      <td className="td pl-5">
                        <input
                          type="checkbox"
                          aria-label={`选择 ${candidate.ip}`}
                          disabled={!pending}
                          checked={selected.includes(candidate.id)}
                          onChange={() => toggleSelected(candidate.id)}
                        />
                      </td>
                      <td className="td">
                        <span className="block font-mono text-[12px] text-ink">{candidate.ip}</span>
                        <span className="mt-0.5 block truncate text-[10.5px] text-ink3">{candidate.hostname || "未解析到主机名"}</span>
                      </td>
                      <td className="td font-mono text-[11px] text-ink2">{candidate.openPorts || "—"}</td>
                      <td className="td max-w-[300px]">
                        <span className="block truncate text-[11px] text-ink2" title={candidate.evidence}>
                          {candidate.evidence || "—"}
                        </span>
                        <span className="mt-0.5 block text-[10px] text-ink3">置信度 {Math.round(candidate.confidence * 100)}%</span>
                      </td>
                      <td className="td text-[11.5px]">
                        {candidate.matchedAssetId > 0 ? (
                          <Link to={`/assets/${candidate.matchedAssetId}`} className="text-brand-strong hover:underline">
                            #{candidate.matchedAssetId}
                          </Link>
                        ) : candidate.assetId > 0 ? (
                          <Link to={`/assets/${candidate.assetId}`} className="text-brand-strong hover:underline">
                            #{candidate.assetId}
                          </Link>
                        ) : (
                          <span className="text-ink3">未匹配</span>
                        )}
                      </td>
                      <td className="td"><Badge tone={meta.tone}>{meta.label}</Badge></td>
                      <td className="td pr-5 text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          {canWrite && pending && (
                            <>
                              <button
                                type="button"
                                className="btn btn-secondary h-7 px-2 text-[11px]"
                                onClick={() => void decide(candidate, "approve")}
                                disabled={acting === candidate.id}
                              >
                                {acting === candidate.id ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
                                确认
                              </button>
                              <button
                                type="button"
                                className="btn btn-ghost h-7 px-2 text-[11px]"
                                onClick={() => void decide(candidate, "ignore")}
                                disabled={acting === candidate.id}
                              >
                                忽略
                              </button>
                            </>
                          )}
                          {isAdmin && pending && (
                            <button
                              type="button"
                              className="btn btn-ghost h-7 px-2 text-[11px]"
                              onClick={() => { setMerging(candidate); setMergeTarget(String(candidate.matchedAssetId || "")); }}
                            >
                              合并
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {candidateTotal > CAND_PAGE_SIZE && (
          <>
            <div className="divider" />
            <Pagination page={candidatePage} pageSize={CAND_PAGE_SIZE} total={candidateTotal} onChange={setCandidatePage} />
          </>
        )}
      </section>
    </div>
  );
}
