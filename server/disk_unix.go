//go:build !windows

package main

import "syscall"

// diskFree 通过 statfs 获取数据目录所在文件系统的可用空间
func diskFree(dir string) (total uint64, free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, false
	}
	bsize := uint64(st.Bsize)
	return st.Blocks * bsize, st.Bavail * bsize, true
}
