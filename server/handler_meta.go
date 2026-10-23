package main

import (
	"fmt"
	"net/http"
	"sort"

	"vulnagent/server/internal/domain/identity"
	"vulnagent/server/internal/domain/risk"
	"vulnagent/server/internal/domain/vuln"
)

// metaOption 字典项
type metaOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type metaPasswordPolicy struct {
	MinLength           int  `json:"minLength"`
	RequireLetterDigit  bool `json:"requireLetterDigit"`
	RequireDiffFromOld  bool `json:"requireDiffFromOld"`
	SessionIdleMinutes  int  `json:"sessionIdleMinutes"`
	LoginLockoutMinutes int  `json:"loginLockoutMinutes"`
}

type metaResp struct {
	Version        string             `json:"version"`
	Demo           bool               `json:"demo"`
	Statuses       []metaOption       `json:"statuses"`
	Priorities     []metaOption       `json:"priorities"`
	Roles          []metaOption       `json:"roles"`
	Exposures      []metaOption       `json:"exposures"`
	Tiers          []metaOption       `json:"tiers"`
	Ecosystems     []string           `json:"ecosystems"`
	DefaultPolicy  risk.Policy        `json:"defaultPolicy"`
	RiskFormula    string             `json:"riskFormula"`
	PasswordPolicy metaPasswordPolicy `json:"passwordPolicy"`
	Harness        bool               `json:"harnessEnabled"`
}

// handleMeta 返回前端需要的业务字典与默认策略，避免枚举在前端重复维护
func (a *App) handleMeta(w http.ResponseWriter, r *http.Request) {
	statuses := make([]metaOption, 0, len(vuln.AllStatuses))
	for _, s := range vuln.AllStatuses {
		statuses = append(statuses, metaOption{Value: string(s), Label: s.Label()})
	}
	priorities := make([]metaOption, 0, 4)
	for _, p := range []vuln.Priority{vuln.PriorityP0, vuln.PriorityP1, vuln.PriorityP2, vuln.PriorityP3} {
		priorities = append(priorities, metaOption{Value: string(p), Label: p.Label()})
	}
	roles := []metaOption{
		{Value: string(identity.RoleViewer), Label: "只读"},
		{Value: string(identity.RoleOperator), Label: "运维"},
		{Value: string(identity.RoleAdmin), Label: "管理员"},
	}
	exposures := []metaOption{
		{Value: "public", Label: risk.ExposureCN("public")},
		{Value: "internal", Label: risk.ExposureCN("internal")},
		{Value: "isolated", Label: risk.ExposureCN("isolated")},
	}
	tiers := []metaOption{
		{Value: "core", Label: risk.TierCN("core")},
		{Value: "important", Label: risk.TierCN("important")},
		{Value: "normal", Label: risk.TierCN("normal")},
	}

	ecoSet := map[string]bool{"deb": true, "rpm": true, "apk": true}
	for eco := range osvEcosystem {
		ecoSet[eco] = true
	}
	ecosystems := make([]string, 0, len(ecoSet))
	for eco := range ecoSet {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)

	p := defaultPolicy()
	formula := fmt.Sprintf("100 × (%.2f·CVSS/10 + %.2f·EPSS + %.2f·在野利用 + %.2f·资产权重)",
		p.Weights.Cvss, p.Weights.Epss, p.Weights.Exploit, p.Weights.Asset)
	writeJSON(w, http.StatusOK, metaResp{
		Version:       appVersion,
		Demo:          a.demoMode(),
		Statuses:      statuses,
		Priorities:    priorities,
		Roles:         roles,
		Exposures:     exposures,
		Tiers:         tiers,
		Ecosystems:    ecosystems,
		DefaultPolicy: p,
		RiskFormula:   formula,
		PasswordPolicy: metaPasswordPolicy{
			MinLength:           10,
			RequireLetterDigit:  true,
			RequireDiffFromOld:  true,
			SessionIdleMinutes:  int(sessionIdleFromEnv().Minutes()),
			LoginLockoutMinutes: 5,
		},
		Harness: a.harnessEnabled(),
	})
}

// harnessEnabled 当前是否启用 Agent Harness（模型凭据与工具就绪）
func (a *App) harnessEnabled() bool { return a.harness != nil && a.harness.Available() }
