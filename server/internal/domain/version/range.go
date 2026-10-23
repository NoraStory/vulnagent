package version

// Range 左闭右开的版本区间。边界为空表示不限。
type Range struct {
	StartIncl string
	EndExcl   string
}

// Matches 判断给定版本是否落在区间内，eco 决定比较规则
func (r Range) Matches(eco, v string) bool {
	if v == "" {
		return false
	}
	if r.StartIncl != "" && Compare(eco, v, r.StartIncl) < 0 {
		return false
	}
	if r.EndExcl != "" && Compare(eco, v, r.EndExcl) >= 0 {
		return false
	}
	return true
}
