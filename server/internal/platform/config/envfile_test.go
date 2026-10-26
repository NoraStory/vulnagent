package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyEnvFile(t *testing.T) {
	const newKey = "VA_TEST_ENV_NEW"
	const keepKey = "VA_TEST_ENV_KEEP"
	const quotedKey = "VA_TEST_ENV_QUOTED"
	_ = os.Unsetenv(newKey)
	_ = os.Unsetenv(quotedKey)
	t.Cleanup(func() {
		_ = os.Unsetenv(newKey)
		_ = os.Unsetenv(quotedKey)
	})
	t.Setenv(keepKey, "keep")

	applyEnvFile("\ufeff# 注释\n" + newKey + "=hello world\n" + keepKey + "=ignored\nexport " + quotedKey + "=\"a=b\"\n")

	if got := os.Getenv(newKey); got != "hello world" {
		t.Fatalf("新变量应写入，实际 %q", got)
	}
	if got := os.Getenv(keepKey); got != "keep" {
		t.Fatalf("已存在的变量不应被覆盖，实际 %q", got)
	}
	if got := os.Getenv(quotedKey); got != "a=b" {
		t.Fatalf("引号应被去除，实际 %q", got)
	}
}

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("VA_TEST_LOAD=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const key = "VA_TEST_LOAD"
	_ = os.Unsetenv(key)
	t.Cleanup(func() { _ = os.Unsetenv(key) })
	t.Setenv("VA_ENV_FILE", path)

	loadEnvFile()
	if got := os.Getenv(key); got != "from-file" {
		t.Fatalf("应从指定 .env 读取，实际 %q", got)
	}
}
