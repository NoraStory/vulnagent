package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCompressFileParallel(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "input.txt")
	dst := filepath.Join(dir, "input.txt.gz")

	payload := bytes.Repeat([]byte("vulnagent parallel gzip test data\n"), 200000)
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
	if err := compressFileParallel(src, dst, 4); err != nil {
		t.Fatalf("并行压缩失败：%v", err)
	}
	compressed, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("读取压缩文件失败：%v", err)
	}
	if len(compressed) >= len(payload) {
		t.Fatalf("压缩后体积未下降：%d >= %d", len(compressed), len(payload))
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("打开 gzip 失败：%v", err)
	}
	defer reader.Close()
	restored, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("解压失败：%v", err)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatalf("解压内容与原文不一致：%d != %d", len(restored), len(payload))
	}
}

func TestCompressFileParallelEmpty(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	dst := filepath.Join(dir, "empty.txt.gz")
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatalf("写入空文件失败：%v", err)
	}
	if err := compressFileParallel(src, dst, 0); err != nil {
		t.Fatalf("空文件压缩失败：%v", err)
	}
	compressed, err := os.ReadFile(dst)
	if err != nil || len(compressed) == 0 {
		t.Fatalf("空文件应生成合法 gzip：%v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("空文件 gzip 无效：%v", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil || len(data) != 0 {
		t.Fatalf("空文件解压异常：%v / %d", err, len(data))
	}
}
