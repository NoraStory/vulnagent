import { useEffect, useMemo, useRef, useState } from "react";
import { GitMerge, Loader2, Pencil, Plus, Save, Tag, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { AssetChange, AssetIdentifier, AssetItem } from "../lib/types";
import { formatTime } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useToast } from "../lib/toast";

type FieldKind = "text" | "email" | "select";

interface FieldDef {
  key: string;
  label: string;
  kind?: FieldKind;
  options?: { value: string; label: string }[];
  wide?: boolean;
}

const fieldGroups: { title: string; fields: FieldDef[] }[] = [
  {
    title: "归属信息",
    fields: [
      { key: "businessSystem", label: "业务系统" },
      { key: "department", label: "部门" },
      { key: "owner", label: "责任人" },
      { key: "ownerEmail", label: "责任人邮箱", kind: "email" },
      { key: "location", label: "机房位置" }
    ]
  },
  {
    title: "分类与状态",
    fields: [
      {
        key: "assetType",
        label: "资产类型",
        kind: "select",
        options: [
          { value: "server", label: "物理机" },
          { value: "vm", label: "虚拟机" },
          { value: "container", label: "容器" },
          { value: "network", label: "网络设备" },
          { value: "database", label: "数据库" },
          { value: "other", label: "其他" }
        ]
      },
      {
        key: "status",
        label: "状态",
        kind: "select",
        options: [
          { value: "active", label: "在用" },
          { value: "maintenance", label: "维护中" },
          { value: "retired", label: "已下线" },
          { value: "merged", label: "已合并" }
        ]
      },
      {
        key: "env",
        label: "环境",
        kind: "select",
        options: [
          { value: "prod", label: "生产" },
          { value: "staging", label: "预发" },
          { value: "dev", label: "开发" }
        ]
      },
      {
        key: "exposure",
        label: "暴露面",
        kind: "select",
        options: [
          { value: "public", label: "公网" },
          { value: "internal", label: "内网" },
          { value: "isolated", label: "隔离" }
        ]
      },
      {
        key: "tier",
        label: "业务等级",
        kind: "select",
        options: [
          { value: "core", label: "核心业务" },
          { value: "important", label: "重要业务" },
          { value: "normal", label: "一般业务" }
        ]
      }
    ]
  },
  {
    title: "系统信息",
    fields: [
      { key: "hostname", label: "主机名" },
      { key: "ip", label: "IP 地址" },
      { key: "osFamily", label: "操作系统" },
      { key: "osVersion", label: "系统版本" },
      { key: "osArch", label: "架构" },
      { key: "kernel", label: "内核版本" }
    ]
  },
  {
    title: "云与硬件",
    fields: [
      { key: "cloudProvider", label: "云厂商" },
      { key: "cloudAccount", label: "云账号" },
      { key: "region", label: "区域" },
      { key: "instanceId", label: "实例 ID" },
      { key: "mac", label: "MAC 地址" },
      { key: "serial", label: "序列号" },
      { key: "virtualized", label: "虚拟化" }
    ]
  }
];

const fieldLabels: Record<string, string> = {};
fieldGroups.forEach((group) => group.fields.forEach((field) => (fieldLabels[field.key] = field.label)));
fieldLabels["tags"] = "标签";
fieldLabels["merged_into"] = "合并去向";
fieldLabels["merged_from"] = "合并来源";
fieldLabels["created"] = "创建资产";

function assetValue(asset: AssetItem, key: string): string {
  if (key === "osFamily") return asset.os ?? "";
  const value = (asset as unknown as Record<string, unknown>)[key];
  return value == null ? "" : String(value);
}

const identifierLabels: Record<string, string> = {
  hostname: "主机名",
  ip: "IP",
  mac: "MAC",
  serial: "序列号",
  cloud_instance: "云实例"
};

export function AssetCmdbPanel({
  asset,
  identifiers,
  changes,
  onRefresh
}: {
  asset: AssetItem;
  identifiers: AssetIdentifier[];
  changes: AssetChange[];
  onRefresh: () => void;
}) {
  const { canWrite, isAdmin } = useAuth();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<Record<string, string>>({});
  const [tagInput, setTagInput] = useState("");
  const [tags, setTags] = useState<string[]>(asset.tags ?? []);
  const [mergeOpen, setMergeOpen] = useState(false);
  const [mergeTarget, setMergeTarget] = useState("");
  const [merging, setMerging] = useState(false);

  const initial = useMemo(() => {
    const next: Record<string, string> = {};
    fieldGroups.forEach((group) => group.fields.forEach((field) => (next[field.key] = assetValue(asset, field.key))));
    return next;
  }, [asset]);

  // 仅在切换到另一台资产时重置表单；同资产刷新（如标签变更）不能覆盖未保存的编辑
  const assetIdRef = useRef<number | null>(null);
  useEffect(() => {
    if (assetIdRef.current === asset.id) return;
    assetIdRef.current = asset.id;
    setForm(initial);
    setEditing(false);
  }, [asset.id, initial]);

  useEffect(() => {
    setTags(asset.tags ?? []);
  }, [asset.tags]);

  const setField = (key: string, value: string) => setForm((prev) => ({ ...prev, [key]: value }));

  const save = async () => {
    setSaving(true);
    try {
      const payload: Record<string, unknown> = { ...form };
      if (!payload.hostname) {
        toast.push("主机名不能为空", "error");
        return;
      }
      const result = await api.updateAsset(asset.id, payload);
      toast.push(`已保存${result.changes && result.changes.length > 0 ? ` ${result.changes.length} 项变更` : ""}`, "success");
      setEditing(false);
      onRefresh();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  const saveTags = async (next: string[]) => {
    try {
      const result = await api.setAssetTags(asset.id, next);
      setTags(result.tags ?? next);
      onRefresh();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "更新标签失败", "error");
    }
  };

  const addTag = () => {
    const value = tagInput.trim();
    if (!value) return;
    if (tags.includes(value)) {
      setTagInput("");
      return;
    }
    setTagInput("");
    void saveTags([...tags, value]);
  };

  const merge = async () => {
    const targetID = Number(mergeTarget);
    if (!targetID || targetID === asset.id) {
      toast.push("请输入有效的目标资产 ID", "error");
      return;
    }
    setMerging(true);
    try {
      const result = await api.mergeAsset(asset.id, targetID);
      toast.push(
        `已合并到 #${targetID}：组件 ${result.stats.components} · 漏洞 ${result.stats.findings} · 工单 ${result.stats.tickets}`,
        "success"
      );
      setMergeOpen(false);
      setMergeTarget("");
      onRefresh();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "合并失败", "error");
    } finally {
      setMerging(false);
    }
  };

  return (
    <div className="divide-y divide-line">
      <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="text-[13px] font-semibold text-ink">资产档案</span>
          <span className="text-[11px] text-ink3">CMDB 字段、标签、标识与变更历史</span>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <button type="button" className="btn btn-ghost h-8" onClick={() => setMergeOpen((open) => !open)}>
              <GitMerge size={13} />
              合并重复资产
            </button>
          )}
          {canWrite &&
            (editing ? (
              <>
                <button type="button" className="btn btn-ghost h-8" onClick={() => { setEditing(false); setForm(initial); }}>
                  取消
                </button>
                <button type="button" className="btn btn-primary h-8" onClick={() => void save()} disabled={saving}>
                  {saving ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                  保存
                </button>
              </>
            ) : (
              <button type="button" className="btn btn-secondary h-8" onClick={() => setEditing(true)}>
                <Pencil size={13} />
                编辑档案
              </button>
            ))}
        </div>
      </div>

      {mergeOpen && (
        <div className="bg-[#FFF8F0] px-5 py-3">
          <p className="text-[11.5px] leading-[17px] text-[#9A5B00]">
            合并会把当前资产（#{asset.id}）的组件、漏洞、工单、标签与标识迁移到目标资产，并把当前资产标记为「已合并」保留审计记录。
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <input
              className="input h-8 w-[160px] text-[12px]"
              value={mergeTarget}
              onChange={(event) => setMergeTarget(event.target.value.replace(/[^0-9]/g, ""))}
              placeholder="目标资产 ID"
              inputMode="numeric"
            />
            <button type="button" className="btn btn-secondary h-8" onClick={() => void merge()} disabled={merging}>
              {merging ? <Loader2 size={13} className="animate-spin" /> : <GitMerge size={13} />}
              确认合并
            </button>
          </div>
        </div>
      )}

      <div className="space-y-5 px-5 py-4">
        {fieldGroups.map((group) => (
          <div key={group.title}>
            <p className="mb-2 text-[11.5px] font-medium text-ink2">{group.title}</p>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {group.fields.map((field) => (
                <label key={field.key} className="block">
                  <span className="mb-1 block text-[10.5px] text-ink3">{field.label}</span>
                  {field.kind === "select" ? (
                    <select
                      className="input h-8 text-[12px] disabled:cursor-not-allowed disabled:bg-subtle/60 disabled:text-ink2"
                      value={form[field.key] ?? ""}
                      disabled={!editing}
                      onChange={(event) => setField(field.key, event.target.value)}
                    >
                      <option value="">未设置</option>
                      {field.options?.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      className="input h-8 text-[12px] disabled:cursor-not-allowed disabled:bg-subtle/60 disabled:text-ink2"
                      type={field.kind === "email" ? "email" : "text"}
                      value={form[field.key] ?? ""}
                      disabled={!editing}
                      onChange={(event) => setField(field.key, event.target.value)}
                      placeholder="未设置"
                    />
                  )}
                </label>
              ))}
            </div>
          </div>
        ))}

        <div>
          <p className="mb-2 flex items-center gap-1.5 text-[11.5px] font-medium text-ink2">
            <Tag size={12} />
            标签
            {canWrite && <span className="text-[10px] font-normal text-ink3">（修改即时生效）</span>}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {tags.length === 0 && <span className="text-[11.5px] text-ink3">暂无标签</span>}
            {tags.map((tag) => (
              <span key={tag} className="pill inline-flex items-center gap-1 bg-subtle text-[11px] text-ink2">
                {tag}
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`删除标签 ${tag}`}
                    className="text-ink3 transition-colors hover:text-[#C4170E]"
                    onClick={() => void saveTags(tags.filter((item) => item !== tag))}
                  >
                    <X size={10} />
                  </button>
                )}
              </span>
            ))}
            {canWrite && (
              <span className="inline-flex items-center gap-1">
                <input
                  className="input h-7 w-[120px] text-[11.5px]"
                  value={tagInput}
                  onChange={(event) => setTagInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addTag();
                    }
                  }}
                  placeholder="新增标签"
                />
                <button type="button" className="btn btn-ghost h-7 px-2" onClick={addTag}>
                  <Plus size={12} />
                </button>
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-5 px-5 py-4 lg:grid-cols-2">
        <div>
          <p className="mb-2 text-[11.5px] font-medium text-ink2">资产标识</p>
          {identifiers.length === 0 ? (
            <p className="text-[11.5px] text-ink3">暂无标识，Agent 上报后会自动登记主机名与 IP。</p>
          ) : (
            <div className="space-y-1.5">
              {identifiers.map((item) => (
                <div key={item.id} className="flex items-center gap-2 text-[11.5px]">
                  <span className="pill w-[64px] justify-center bg-subtle text-[10.5px] text-ink2">
                    {identifierLabels[item.kind] ?? item.kind}
                  </span>
                  <span className="font-mono text-ink">{item.value}</span>
                  <span className="text-[10px] text-ink3">{item.source}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <p className="mb-2 text-[11.5px] font-medium text-ink2">变更历史</p>
          {changes.length === 0 ? (
            <p className="text-[11.5px] text-ink3">暂无变更记录。</p>
          ) : (
            <div className="max-h-[260px] space-y-2 overflow-auto pr-1">
              {changes.map((change) => (
                <div key={change.id} className="rounded-[8px] bg-subtle/60 px-2.5 py-2 text-[11px] leading-[16px]">
                  <div className="flex flex-wrap items-center justify-between gap-1">
                    <span className="font-medium text-ink">
                      {fieldLabels[change.field] ?? change.field}
                    </span>
                    <span className="text-[10px] text-ink3">{formatTime(change.createdAt)}</span>
                  </div>
                  <p className="mt-0.5 break-all text-ink2">
                    <span className="text-ink3">{change.oldValue || "空"}</span>
                    <span className="mx-1 text-ink3">→</span>
                    <span className="text-ink">{change.newValue || "空"}</span>
                  </p>
                  <p className="mt-0.5 text-[10px] text-ink3">
                    {change.actor || "系统"} · {change.source || "manual"}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
