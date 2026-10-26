//go:build windows

package main

import "golang.org/x/sys/windows"

// diskFree 通过 GetDiskFreeSpaceExW 获取数据目录所在卷的总量与可用空间
func diskFree(dir string) (total uint64, free uint64, ok bool) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, false
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(path, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, false
	}
	return totalBytes, freeToCaller, true
}
