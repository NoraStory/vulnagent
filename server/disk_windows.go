//go:build windows

package main

// diskFree Windows 下不引入额外依赖，直接降级为 skip
func diskFree(dir string) (total uint64, free uint64, ok bool) {
	return 0, 0, false
}
