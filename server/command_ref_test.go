package main

import (
	"strings"
	"testing"
)

func TestGuessCommandTopics(t *testing.T) {
	cases := []struct {
		question string
		want     []string
	}{
		{"tar 怎么打包并解压目录", []string{"tar"}},
		{"查看磁盘使用率和端口占用", []string{"df", "ss", "lsof"}},
		{"如何使用 systemctl 查看服务状态", []string{"systemctl"}},
		{"排查最近异常登录和大文件", []string{"find", "lastb"}},
		{"主机名是什么", nil},
	}
	for _, item := range cases {
		got := guessCommandTopics(item.question)
		if len(got) != len(item.want) {
			t.Fatalf("%q 期望 %v，实际 %v", item.question, item.want, got)
		}
		for index := range item.want {
			if got[index] != item.want[index] {
				t.Fatalf("%q 期望 %v，实际 %v", item.question, item.want, got)
			}
		}
	}
}

func TestGuessCommandTopicsCap(t *testing.T) {
	got := guessCommandTopics("用 tar、find、grep、sed、awk、ss 一起处理磁盘日志和端口")
	if len(got) > commandRefMaxTopics {
		t.Fatalf("主题数量应不超过 %d，实际 %v", commandRefMaxTopics, got)
	}
}

func TestSummarizeCommandReference(t *testing.T) {
	text := "#[cheat.sheets:df]\n# df\n# Show disk space usage.\n#\n# Options:\n# -h  human readable\ndf -h\n"
	title, snippet, content := summarizeCommandReference(text)
	if title != "df" {
		t.Fatalf("标题解析异常：%q", title)
	}
	if !strings.Contains(snippet, "Show disk space usage") || !strings.Contains(snippet, "df -h") {
		t.Fatalf("摘要解析异常：%q", snippet)
	}
	if !strings.Contains(content, "df -h") {
		t.Fatalf("内容解析异常：%q", content)
	}
}

func TestParseCommandTopicList(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{`["df","du"]`, []string{"df", "du"}},
		{"```json\n[\"ss\"]\n```", []string{"ss"}},
		{"df, du\nss", []string{"df", "du", "ss"}},
		{`["DF", "../etc/passwd", "tar"]`, []string{"df", "tar"}},
		{`[]`, nil},
	}
	for _, item := range cases {
		got := parseCommandTopicList(item.raw)
		if len(got) != len(item.want) {
			t.Fatalf("%q 期望 %v，实际 %v", item.raw, item.want, got)
		}
		for index := range item.want {
			if got[index] != item.want[index] {
				t.Fatalf("%q 期望 %v，实际 %v", item.raw, item.want, got)
			}
		}
	}
}

func TestExtractCheatSheetPre(t *testing.T) {
	document := `<html><head><title>cheat.sh/tar</title></head><body><pre># tar
# extract files
tar -xf a.tar -C /tmp
</pre></body></html>`
	got := extractCheatSheetPre(document)
	if !strings.Contains(got, "tar -xf a.tar -C /tmp") {
		t.Fatalf("HTML 正文提取失败：%q", got)
	}
	if strings.Contains(got, "<pre") {
		t.Fatalf("仍包含 HTML 标签：%q", got)
	}
}

func TestCommandReferencePrompt(t *testing.T) {
	if block := commandReferencePrompt(nil); block != "" {
		t.Fatalf("空参考应返回空字符串，实际 %q", block)
	}
	refs := []sshCommandReference{{Topic: "df", Content: "df -h\n"}}
	block := commandReferencePrompt(refs)
	if !strings.Contains(block, "command -v") || !strings.Contains(block, "df -h") {
		t.Fatalf("参考提示缺少验证约束：%q", block)
	}
}
