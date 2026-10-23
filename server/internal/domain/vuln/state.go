package vuln

import "strings"

// Status 漏洞生命周期状态，共 8 种，状态名与库中存储值一致
type Status string

const (
	StatusOpen          Status = "open"
	StatusTriaged       Status = "triaged"
	StatusFixing        Status = "fixing"
	StatusFixed         Status = "fixed"
	StatusVerified      Status = "verified"
	StatusClosed        Status = "closed"
	StatusRiskAccepted  Status = "risk_accepted"
	StatusFalsePositive Status = "false_positive"
)

// AllStatuses 全部合法状态，顺序即前端展示顺序
var AllStatuses = []Status{
	StatusOpen, StatusTriaged, StatusFixing, StatusFixed,
	StatusVerified, StatusClosed, StatusRiskAccepted, StatusFalsePositive,
}

// ActiveStatuses 仍处于处置流程中的状态（复扫收敛只处理这些）
var ActiveStatuses = []Status{
	StatusOpen, StatusTriaged, StatusFixing, StatusFixed, StatusVerified,
}

var statusLabels = map[Status]string{
	StatusOpen:          "待处理",
	StatusTriaged:       "已定级",
	StatusFixing:        "修复中",
	StatusFixed:         "已修复",
	StatusVerified:      "已验证",
	StatusRiskAccepted:  "风险接受",
	StatusFalsePositive: "误报",
	StatusClosed:        "已关闭",
}

// transitions 合法状态迁移表。复扫与人工操作都必须落在表内，
// 唯一的例外是 verified → open（版本回退重新命中，由系统触发）。
var transitions = map[Status][]Status{
	StatusOpen:          {StatusTriaged, StatusFixing, StatusFixed, StatusClosed, StatusRiskAccepted, StatusFalsePositive},
	StatusTriaged:       {StatusOpen, StatusFixing, StatusFixed, StatusClosed, StatusRiskAccepted, StatusFalsePositive},
	StatusFixing:        {StatusOpen, StatusTriaged, StatusFixed, StatusClosed, StatusRiskAccepted, StatusFalsePositive},
	StatusFixed:         {StatusOpen, StatusFixing, StatusVerified, StatusClosed, StatusRiskAccepted, StatusFalsePositive},
	StatusVerified:      {StatusOpen, StatusClosed},
	StatusClosed:        {StatusOpen},
	StatusRiskAccepted:  {StatusOpen, StatusClosed},
	StatusFalsePositive: {StatusOpen, StatusClosed},
}

// Valid 是否为已知状态
func (s Status) Valid() bool {
	_, ok := statusLabels[s]
	return ok
}

// Active 是否仍在处置流程中
func (s Status) Active() bool {
	for _, v := range ActiveStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// Label 状态的中文名，未知状态原样返回
func (s Status) Label() string {
	if label, ok := statusLabels[s]; ok {
		return label
	}
	return string(s)
}

// CanTransition 判断状态迁移是否合法
func (s Status) CanTransition(to Status) bool {
	if s == to {
		return true
	}
	for _, v := range transitions[s] {
		if v == to {
			return true
		}
	}
	return false
}

// ParseStatus 把外部字符串解析为状态
func ParseStatus(v string) (Status, bool) {
	s := Status(strings.TrimSpace(v))
	return s, s.Valid()
}

// CanTransition 字符串版本的状态迁移校验，供接口层直接使用
func CanTransition(from, to string) bool {
	return Status(from).CanTransition(Status(to))
}

// StatusLabel 字符串版本的状态中文名
func StatusLabel(v string) string {
	return Status(v).Label()
}

// ActiveStatusSQL 生成 SQL IN 列表，例如 'open','triaged'
func ActiveStatusSQL() string {
	quoted := make([]string, 0, len(ActiveStatuses))
	for _, s := range ActiveStatuses {
		quoted = append(quoted, "'"+string(s)+"'")
	}
	return strings.Join(quoted, ",")
}

// Priority 优先级
type Priority string

const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
)

var priorityLabels = map[Priority]string{
	PriorityP0: "立即处置",
	PriorityP1: "本周处置",
	PriorityP2: "计划处置",
	PriorityP3: "观察",
}

// Label 优先级的中文含义
func (p Priority) Label() string {
	if label, ok := priorityLabels[p]; ok {
		return label
	}
	return string(p)
}
