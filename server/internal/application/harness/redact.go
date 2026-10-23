package harnessapp

import "regexp"

// 需要脱敏的字段名（JSON 输出与文本日志共用）
var secretKeyPattern = regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)"\s*:\s*")([^"]*)(")`)
var bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]+`)

// Redact 对工具输出做最小脱敏，避免凭据进入模型上下文与审计明细
func Redact(s string) string {
	s = secretKeyPattern.ReplaceAllString(s, `$1***$3`)
	s = bearerPattern.ReplaceAllString(s, `$1***`)
	return s
}
