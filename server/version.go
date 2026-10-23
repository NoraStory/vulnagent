package main

import (
	"strconv"
	"strings"
)

// 版本比较：不同生态的版本号规则差异很大，必须按生态选择比较器。
// 返回 -1 表示 a < b，0 表示相等，1 表示 a > b。

// CompareVersion 按生态比较两个版本号
func CompareVersion(eco, a, b string) int {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return 0
	}
	switch strings.ToLower(eco) {
	case "deb":
		return compareDebian(a, b)
	case "rpm":
		return compareRPM(a, b)
	case "apk":
		return compareAPK(a, b)
	case "npm", "golang", "maven", "pypi", "nuget", "oci", "semver":
		return compareSemverish(a, b)
	default:
		return compareGeneric(a, b)
	}
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// ---------- Debian ----------

// compareDebian 实现 dpkg 的 epoch:upstream-revision 比较规则
func compareDebian(a, b string) int {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := dpkgVersionCompare(au, bu); c != 0 {
		return c
	}
	return dpkgVersionCompare(ar, br)
}

func splitDebian(v string) (epoch int, upstream, revision string) {
	epoch = 0
	if idx := strings.IndexByte(v, ':'); idx > 0 {
		if n, err := strconv.Atoi(v[:idx]); err == nil {
			epoch = n
		}
		v = v[idx+1:]
	}
	revision = ""
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		revision = v[idx+1:]
		v = v[:idx]
	}
	return epoch, v, revision
}

// dpkgOrder 复刻 dpkg 的字符序：~ < 结尾 < 字母 < 其他
func dpkgOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func dpkgVersionCompare(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc byte
			if i < len(a) {
				ac = a[i]
			}
			if j < len(b) {
				bc = b[j]
			}
			if ao, bo := dpkgOrder(ac), dpkgOrder(bc); ao != bo {
				return sign(ao - bo)
			}
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		si, sj := i, j
		for si < len(a) && isDigit(a[si]) {
			si++
		}
		for sj < len(b) && isDigit(b[sj]) {
			sj++
		}
		if si-i != sj-j {
			return sign((si - i) - (sj - j))
		}
		for i < si {
			if a[i] != b[j] {
				if a[i] < b[j] {
					return -1
				}
				return 1
			}
			i++
			j++
		}
	}
	return 0
}

// ---------- RPM ----------

func compareRPM(a, b string) int {
	ae, ar := splitRPM(a)
	be, br := splitRPM(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	return rpmvercmp(ar, br)
}

func splitRPM(v string) (epoch int, rest string) {
	epoch = 0
	if idx := strings.IndexByte(v, ':'); idx > 0 {
		if n, err := strconv.Atoi(v[:idx]); err == nil {
			epoch = n
		}
		v = v[idx+1:]
	}
	return epoch, v
}

// rpmvercmp 复刻 rpm 的分段比较：字母段与数字段交替，~ 最小
func rpmvercmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlpha(a[i]) && !isDigit(a[i]) && a[i] != '~' {
			i++
		}
		for j < len(b) && !isAlpha(b[j]) && !isDigit(b[j]) && b[j] != '~' {
			j++
		}
		// 处理 ~（预发布）优先
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		if isDigit(a[si]) {
			for si < len(a) && isDigit(a[si]) {
				si++
			}
			for sj < len(b) && isDigit(b[sj]) {
				sj++
			}
		} else {
			for si < len(a) && isAlpha(a[si]) {
				si++
			}
			for sj < len(b) && isAlpha(b[sj]) {
				sj++
			}
		}
		if i == si {
			// a 侧为空，b 侧还有内容
			return -1
		}
		if j == sj {
			return 1
		}
		segA, segB := a[i:si], b[j:sj]
		if isDigit(segA[0]) {
			trimA := strings.TrimLeft(segA, "0")
			trimB := strings.TrimLeft(segB, "0")
			if len(trimA) != len(trimB) {
				return sign(len(trimA) - len(trimB))
			}
			if c := strings.Compare(trimA, trimB); c != 0 {
				return sign(c)
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return sign(c)
		}
		i, j = si, sj
	}
	if i < len(a) {
		return 1
	}
	if j < len(b) {
		return -1
	}
	return 0
}

// ---------- APK ----------

func compareAPK(a, b string) int {
	ab, ar := splitAPKRevision(a)
	bb, br := splitAPKRevision(b)
	if c := compareGeneric(ab, bb); c != 0 {
		return c
	}
	return sign(ar - br)
}

func splitAPKRevision(v string) (string, int) {
	rev := 0
	if idx := strings.LastIndex(v, "-r"); idx >= 0 {
		if n, err := strconv.Atoi(v[idx+2:]); err == nil {
			rev = n
		}
		v = v[:idx]
	}
	return v, rev
}

// ---------- Semver / 常规语义化版本 ----------

var mavenQualifiers = map[string]int{
	"alpha": 1, "a": 1,
	"beta": 2, "b": 2,
	"milestone": 3, "m": 3,
	"rc": 4, "cr": 4,
	"snapshot": 5,
	"":         6,
	"ga":       6, "final": 6, "release": 6,
	"sp": 7,
}

// compareSemverish 处理 v 前缀、数字主干与预发布后缀
func compareSemverish(a, b string) int {
	a = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(a), "v"))
	b = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(b), "v"))
	if i := strings.IndexByte(a, '+'); i >= 0 {
		a = a[:i]
	}
	if i := strings.IndexByte(b, '+'); i >= 0 {
		b = b[:i]
	}
	mainA, preA := splitPrerelease(a)
	mainB, preB := splitPrerelease(b)

	if c := compareNumericSegments(mainA, mainB); c != 0 {
		return c
	}
	if preA == preB {
		return 0
	}
	// 无预发布后缀视为正式版，优先级更高
	if preA == "" {
		return 1
	}
	if preB == "" {
		return -1
	}
	return comparePrerelease(preA, preB)
}

func splitPrerelease(v string) (main, pre string) {
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func compareNumericSegments(a, b string) int {
	sep := func(r rune) bool { return r == '.' || r == '_' }
	as := strings.FieldsFunc(a, sep)
	bs := strings.FieldsFunc(b, sep)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xNum, xOK := parseLeadingNumber(x)
		yNum, yOK := parseLeadingNumber(y)
		if xOK && yOK {
			if xNum != yNum {
				return sign(xNum - yNum)
			}
			// 数字相同则比较剩余后缀
			xRest, yRest := strings.TrimPrefix(x, strconv.Itoa(xNum)), strings.TrimPrefix(y, strconv.Itoa(yNum))
			if c := compareQualifier(xRest, yRest); c != 0 {
				return c
			}
			continue
		}
		if c := compareQualifier(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func parseLeadingNumber(s string) (int, bool) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

func compareQualifier(a, b string) int {
	if a == b {
		return 0
	}
	ra, oka := mavenQualifiers[a]
	rb, okb := mavenQualifiers[b]
	switch {
	case oka && okb:
		return sign(ra - rb)
	case oka:
		return -1
	case okb:
		return 1
	}
	return sign(strings.Compare(a, b))
}

func comparePrerelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x == y {
			continue
		}
		xn, xOK := strconv.Atoi(x)
		yn, yOK := strconv.Atoi(y)
		switch {
		case xOK == nil && yOK == nil:
			if xn != yn {
				return sign(xn - yn)
			}
		case xOK == nil:
			return -1 // 数字标识符优先级低于字母
		case yOK == nil:
			return 1
		default:
			return sign(strings.Compare(x, y))
		}
	}
	return 0
}

// ---------- 通用 ----------

// compareGeneric 按数字段与字母段交替比较，用于无明确生态的版本
func compareGeneric(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) && !isAlpha(a[i]) {
			i++
		}
		for j < len(b) && !isDigit(b[j]) && !isAlpha(b[j]) {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		if isDigit(a[i]) {
			for si < len(a) && isDigit(a[si]) {
				si++
			}
			for sj < len(b) && isDigit(b[sj]) {
				sj++
			}
			xa := strings.TrimLeft(a[i:si], "0")
			xb := strings.TrimLeft(b[j:sj], "0")
			if len(xa) != len(xb) {
				return sign(len(xa) - len(xb))
			}
			if c := strings.Compare(xa, xb); c != 0 {
				return sign(c)
			}
		} else {
			for si < len(a) && isAlpha(a[si]) {
				si++
			}
			for sj < len(b) && isAlpha(b[sj]) {
				sj++
			}
			if c := strings.Compare(a[i:si], b[j:sj]); c != 0 {
				return sign(c)
			}
		}
		i, j = si, sj
	}
	if i < len(a) {
		return 1
	}
	if j < len(b) {
		return -1
	}
	return 0
}
