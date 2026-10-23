package vuln

import "vulnagent/server/internal/domain/version"

// AffectedRange 一条受影响版本区间（左闭右开）
type AffectedRange struct {
	CveID            string
	Product          string
	VersionStartIncl string
	VersionEndExcl   string
	FixedVersion     string
}

// Matches 判断组件版本是否落在区间内，eco 决定版本比较规则
func (r AffectedRange) Matches(eco, v string) bool {
	return version.Range{StartIncl: r.VersionStartIncl, EndExcl: r.VersionEndExcl}.Matches(eco, v)
}
