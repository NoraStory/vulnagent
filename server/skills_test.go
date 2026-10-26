package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSkillMeta(t *testing.T) {
	content := `---
name: demo-skill
display_name: "演示技能"
description: >
  第一行说明。
  第二行说明。
version: 1.2.3
platforms:
  - linux
  - windows
---
# 正文
`
	meta := parseSkillMeta(content)
	if meta.name != "demo-skill" || meta.displayName != "演示技能" {
		t.Fatalf("名称解析异常：%+v", meta)
	}
	if meta.version != "1.2.3" {
		t.Fatalf("版本解析异常：%q", meta.version)
	}
	if meta.description != "第一行说明。 第二行说明。" {
		t.Fatalf("描述多行解析异常：%q", meta.description)
	}
	if len(meta.platforms) != 2 || meta.platforms[0] != "linux" || meta.platforms[1] != "windows" {
		t.Fatalf("平台解析异常：%+v", meta.platforms)
	}
}

func TestSkillRegistryReadAndTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "guides"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "guides", "workflow.md"), []byte("flow"), 0o644); err != nil {
		t.Fatal(err)
	}
	registry := &SkillRegistry{
		root:  dir,
		items: map[string]Skill{"demo": {ID: "demo", DisplayName: "演示", Dir: dir}},
		order: []string{"demo"},
	}

	content, truncated, found, err := registry.ReadFile("demo", "guides/workflow.md", 1024)
	if err != nil || !found || truncated || content != "flow" {
		t.Fatalf("读取技能文件失败：content=%q truncated=%v found=%v err=%v", content, truncated, found, err)
	}
	if _, _, _, err := registry.ReadFile("demo", "../outside.md", 1024); err == nil {
		t.Fatal("越界路径应被拒绝")
	}
	if _, _, _, err := registry.ReadFile("demo", "/etc/passwd", 1024); err == nil {
		t.Fatal("绝对路径应被拒绝")
	}

	files, err := registry.Files("demo", "guides/")
	if err != nil || len(files) != 1 {
		t.Fatalf("文件列表异常：%+v err=%v", files, err)
	}
	ctxText, ok := registry.Context("demo")
	if !ok || ctxText == "" {
		t.Fatal("技能上下文应生成")
	}
	if _, ok := registry.Context("missing"); ok {
		t.Fatal("未知技能不应生成上下文")
	}
}

func TestCompareSkillVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.1.9", 1},
		{"v2.0.0", "2.0", 0},
		{"1.0", "1.0.1", -1},
		{"", "1.0", -1},
	}
	for _, item := range cases {
		got := compareSkillVersion(item.a, item.b)
		if (got > 0) != (item.want > 0) || (got < 0) != (item.want < 0) {
			t.Fatalf("版本比较异常：%q vs %q = %d，期望 %d", item.a, item.b, got, item.want)
		}
	}
}

func TestSkillRegistryKeepsLatestVersion(t *testing.T) {
	root := t.TempDir()
	for _, item := range []struct {
		dir, version string
	}{
		{"old", "1.0.0"},
		{"new", "2.0.0"},
	} {
		dir := filepath.Join(root, item.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		content := "---\nname: demo\ndisplay_name: 演示\nversion: " + item.version + "\n---\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VA_SKILLS_DIR", root)
	registry := loadSkills()
	if len(registry.order) != 1 {
		t.Fatalf("同一技能应只保留一份，实际 %d", len(registry.order))
	}
	skill, ok := registry.Get("demo")
	if !ok || skill.Version != "2.0.0" {
		t.Fatalf("应保留最高版本：%+v", skill)
	}
}

func TestSkillReadFileRange(t *testing.T) {
	dir := t.TempDir()
	lines := ""
	for i := 1; i <= 10; i++ {
		lines += "line-" + string(rune('0'+i)) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	registry := &SkillRegistry{items: map[string]Skill{"demo": {ID: "demo", Dir: dir}}}
	content, total, truncated, err := registry.ReadFileRange("demo", "SKILL.md", 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 11 || !truncated {
		t.Fatalf("行数/截断标记异常：total=%d truncated=%v", total, truncated)
	}
	if content != "line-3\nline-4" {
		t.Fatalf("行范围读取异常：%q", content)
	}
}
