// Package clock 提供统一时区与时间格式化，避免各处重复依赖系统时区。
package clock

import "time"

// zone 固定东八区，避免容器缺少时区数据库
var zone = time.FixedZone("CST", 8*3600)

// Now 返回东八区当前时间
func Now() time.Time { return time.Now().In(zone) }

// Zone 返回统一的东八区时区
func Zone() *time.Location { return zone }

// Format 统一的时间字符串格式（RFC3339，东八区）
func Format(t time.Time) string { return t.In(zone).Format(time.RFC3339) }

// FormatNow 返回当前时间的统一格式
func FormatNow() string { return Format(Now()) }

// Parse 解析统一格式的时间字符串
func Parse(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

// Midnight 返回当天零点（东八区）
func Midnight(t time.Time) time.Time {
	t = t.In(zone)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, zone)
}

// HoursSince 返回某时间字符串距今的小时数，解析失败返回 0
func HoursSince(s string) float64 {
	t, err := Parse(s)
	if err != nil {
		return 0
	}
	return Now().Sub(t).Hours()
}
