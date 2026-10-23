// Package harnessapp 实现 Agent Harness 的应用服务：
// 工具静态注册、对话循环、九道执行闸门、人工审批与一次性消费。
package harnessapp

import (
	"sort"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
	"vulnagent/server/internal/domain/identity"
)

// Registry 静态工具注册表。工具只能由代码注册，模型无法新增或替换。
type Registry struct {
	tools map[string]harness.Tool
	order []string
}

// NewRegistry 构造注册表
func NewRegistry(tools []harness.Tool) *Registry {
	r := &Registry{tools: make(map[string]harness.Tool, len(tools))}
	for _, t := range tools {
		if _, exists := r.tools[t.Spec.Name]; exists {
			continue
		}
		r.tools[t.Spec.Name] = t
		r.order = append(r.order, t.Spec.Name)
	}
	sort.Strings(r.order)
	return r
}

// Len 已注册工具数
func (r *Registry) Len() int { return len(r.order) }

// Get 按名称取工具
func (r *Registry) Get(name string) (harness.Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Specs 返回全部工具规格（按名称排序）
func (r *Registry) Specs() []harness.ToolSpec {
	out := make([]harness.ToolSpec, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.tools[name].Spec)
	}
	return out
}

// DefsFor 返回指定角色可见的工具定义
func (r *Registry) DefsFor(role string) []ports.LLMToolDef {
	minRank := identity.Role(role).Rank()
	out := make([]ports.LLMToolDef, 0, len(r.order))
	for _, name := range r.order {
		t := r.tools[name]
		if identity.Role(t.Spec.MinRole).Rank() > minRank {
			continue
		}
		out = append(out, ports.LLMToolDef{
			Name:        t.Spec.Name,
			Description: t.Spec.Description,
			Params:      t.Spec.Params,
		})
	}
	return out
}
