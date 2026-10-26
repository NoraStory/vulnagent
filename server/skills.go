package main

import (
	"archive/zip"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Skill 一个运维技能（从 SKILL.md 解析）
type Skill struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Platforms   []string `json:"platforms"`
	Dir         string   `json:"-"`
}

// SkillRegistry 技能注册表
type SkillRegistry struct {
	root  string
	items map[string]Skill
	order []string
}

// skillSearchRoots 依次尝试的目录，兼容从项目根或 server 目录启动
func skillSearchRoots(name string) []string {
	if env := strings.TrimSpace(os.Getenv("VA_" + strings.ToUpper(name) + "_DIR")); env != "" {
		return []string{env}
	}
	return []string{name, filepath.Join("..", name), filepath.Join("..", "..", name)}
}

func findExistingDir(name string) string {
	for _, candidate := range skillSearchRoots(name) {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			if abs, err := filepath.Abs(candidate); err == nil {
				return abs
			}
			return candidate
		}
	}
	return ""
}

// ensureSkills 把 skill/*.zip 解压到 skills/，已存在的目录跳过。
func ensureSkills() string {
	root := findExistingDir("skills")
	if root == "" {
		root, _ = filepath.Abs("skills")
	}
	zipDir := findExistingDir("skill")
	if zipDir == "" {
		return root
	}
	entries, err := os.ReadDir(zipDir)
	if err != nil {
		return root
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			continue
		}
		target := filepath.Join(root, strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())))
		if _, err := os.Stat(filepath.Join(target, "SKILL.md")); err == nil {
			continue
		}
		if err := unzipTo(filepath.Join(zipDir, entry.Name()), target); err != nil {
			slog.Warn("解压技能包失败", "zip", entry.Name(), "err", err)
			continue
		}
		if err := os.MkdirAll(root, 0o755); err != nil {
			slog.Warn("创建技能目录失败", "dir", root, "err", err)
		}
		slog.Info("已解压技能包", "zip", entry.Name(), "target", target)
	}
	return root
}

// unzipTo 解压单个 zip，拒绝路径穿越与绝对路径。
func unzipTo(zipPath, target string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		name := filepath.Clean(file.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("压缩包内含非法路径：%s", file.Name)
		}
		dest := filepath.Join(target, name)
		if !strings.HasPrefix(dest, filepath.Clean(target)+string(os.PathSeparator)) && dest != filepath.Clean(target) {
			return fmt.Errorf("压缩包内含越界路径：%s", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, io.LimitReader(src, 8<<20))
		dst.Close()
		src.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

// loadSkills 扫描 skills/*/SKILL.md 构建注册表
func loadSkills() *SkillRegistry {
	root := findExistingDir("skills")
	if root == "" {
		root = ensureSkills()
	}
	registry := &SkillRegistry{root: root, items: map[string]Skill{}}
	entries, err := os.ReadDir(root)
	if err != nil {
		return registry
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		content, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
		if err != nil {
			continue
		}
		meta := parseSkillMeta(string(content))
		id := meta.name
		if id == "" {
			id = entry.Name()
		}
		skill := Skill{
			ID:          id,
			DisplayName: firstNonEmpty(meta.displayName, id),
			Description: meta.description,
			Version:     meta.version,
			Platforms:   inferPlatforms(meta),
			Dir:         dir,
		}
		if existing, ok := registry.items[id]; ok {
			// 同一技能存在多份（旧版本解压目录）时保留版本更高的一份
			if compareSkillVersion(skill.Version, existing.Version) <= 0 {
				continue
			}
			registry.items[id] = skill
			continue
		}
		registry.items[id] = skill
		registry.order = append(registry.order, id)
	}
	sort.Strings(registry.order)
	return registry
}

type skillMeta struct {
	name        string
	displayName string
	description string
	version     string
	platforms   []string
}

// inferPlatforms 未声明平台时按名称/描述推断，便于前端展示。
func inferPlatforms(meta skillMeta) []string {
	if len(meta.platforms) > 0 {
		return meta.platforms
	}
	lower := strings.ToLower(meta.name + " " + meta.displayName + " " + meta.description)
	switch {
	case strings.Contains(lower, "tencentos"), strings.Contains(lower, "linux"):
		return []string{"linux"}
	case strings.Contains(lower, "windows"):
		return []string{"windows"}
	}
	return []string{}
}

// parseSkillMeta 解析 SKILL.md 顶部 YAML front matter 的少量字段。
func parseSkillMeta(content string) skillMeta {
	var meta skillMeta
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return meta
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return meta
	}
	blockKey := ""
	for i := 1; i < end; i++ {
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indented := strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
		if blockKey != "" && indented {
			value := strings.TrimSpace(line)
			switch blockKey {
			case "description":
				if value != "" {
					if meta.description != "" {
						meta.description += " "
					}
					meta.description += value
				}
			case "platforms":
				value = strings.TrimPrefix(value, "- ")
				value = strings.Trim(value, `"'`)
				if value != "" {
					meta.platforms = append(meta.platforms, value)
				}
			}
			continue
		}
		blockKey = ""
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "name":
			meta.name = strings.Trim(value, `"'`)
		case "display_name", "displayName":
			meta.displayName = strings.Trim(value, `"'`)
		case "version":
			meta.version = strings.Trim(value, `"'`)
		case "description":
			if value == ">" || value == "|" || value == "" {
				blockKey = "description"
				continue
			}
			meta.description = strings.Trim(value, `"'`)
			if strings.HasSuffix(value, ">") {
				blockKey = "description"
			}
		case "platforms":
			if strings.HasPrefix(value, "[") {
				for _, item := range strings.Split(strings.Trim(value, "[]"), ",") {
					item = strings.Trim(strings.TrimSpace(item), `"'`)
					if item != "" {
						meta.platforms = append(meta.platforms, item)
					}
				}
				continue
			}
			blockKey = "platforms"
		}
	}
	return meta
}

// List 返回按 ID 排序的技能
func (r *SkillRegistry) List() []Skill {
	if r == nil {
		return []Skill{}
	}
	out := make([]Skill, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.items[id])
	}
	return out
}

// Get 按 ID 查找技能
func (r *SkillRegistry) Get(id string) (Skill, bool) {
	if r == nil {
		return Skill{}, false
	}
	skill, ok := r.items[strings.TrimSpace(id)]
	return skill, ok
}

// Context 生成注入对话的系统提示
func (r *SkillRegistry) Context(id string) (string, bool) {
	skill, ok := r.Get(id)
	if !ok {
		return "", false
	}
	return fmt.Sprintf(`[skill] id=%s
用户通过 /%s 启用了技能「%s」。
技能目录只能通过 list_skill_files 与 read_skill_file 读取（skillId=%s）。请先读取 SKILL.md，再按其中指引按需读取 guides/references，不要一次性加载全部文档。
执行主机诊断时优先使用 host_diagnose / host_metrics / host_hardware；所有变更必须走审批，不得绕过。`, skill.ID, skill.ID, skill.DisplayName, skill.ID), true
}

// ReadFile 安全读取技能目录内的文本文件
func (r *SkillRegistry) ReadFile(id, rel string, maxBytes int64) (string, bool, bool, error) {
	skill, ok := r.Get(id)
	if !ok {
		return "", false, false, fmt.Errorf("未知技能：%s", id)
	}
	rel = strings.TrimSpace(rel)
	if rel == "" {
		rel = "SKILL.md"
	}
	if filepath.IsAbs(rel) {
		return "", false, false, fmt.Errorf("路径必须是技能目录内的相对路径")
	}
	cleaned := filepath.Clean(rel)
	if cleaned == "." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) || cleaned == ".." {
		return "", false, false, fmt.Errorf("路径越界")
	}
	path := filepath.Join(skill.Dir, cleaned)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", false, false, fmt.Errorf("文件不存在：%s", rel)
	}
	if maxBytes <= 0 || maxBytes > 256<<10 {
		maxBytes = 256 << 10
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", false, false, err
	}
	truncated := int64(len(data)) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	return string(data), truncated, true, nil
}

// compareSkillVersion 比较点分版本号，无法解析时按字符串比较。
func compareSkillVersion(a, b string) int {
	parse := func(v string) []int {
		parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
		out := make([]int, 0, len(parts))
		for _, part := range parts {
			n := 0
			for _, ch := range part {
				if ch < '0' || ch > '9' {
					break
				}
				n = n*10 + int(ch-'0')
			}
			out = append(out, n)
		}
		return out
	}
	left, right := parse(a), parse(b)
	for i := 0; i < len(left) || i < len(right); i++ {
		var x, y int
		if i < len(left) {
			x = left[i]
		}
		if i < len(right) {
			y = right[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ReadFileRange 按行范围读取技能文档，避免一次加载超大文件。
func (r *SkillRegistry) ReadFileRange(id, rel string, startLine, maxLines int) (string, int, bool, error) {
	content, _, _, err := r.ReadFile(id, rel, 2<<20)
	if err != nil {
		return "", 0, false, err
	}
	lines := strings.Split(content, "\n")
	total := len(lines)
	if startLine < 1 {
		startLine = 1
	}
	if startLine > total {
		return "", total, false, nil
	}
	if maxLines <= 0 {
		maxLines = 400
	}
	if maxLines > 2000 {
		maxLines = 2000
	}
	end := startLine - 1 + maxLines
	if end > total {
		end = total
	}
	selected := strings.Join(lines[startLine-1:end], "\n")
	truncated := end < total
	if len(selected) > 64<<10 {
		// 按字节截断可能切断 UTF-8，回退到最后一个换行
		cut := 64 << 10
		if idx := strings.LastIndex(selected[:cut], "\n"); idx > 0 {
			cut = idx
		}
		selected = selected[:cut]
		truncated = true
	}
	return selected, total, truncated, nil
}

// Files 列出技能目录下的文件（最多 500 个）
func (r *SkillRegistry) Files(id, prefix string) ([]map[string]any, error) {
	skill, ok := r.Get(id)
	if !ok {
		return nil, fmt.Errorf("未知技能：%s", id)
	}
	prefix = strings.TrimSpace(prefix)
	out := make([]map[string]any, 0, 64)
	err := filepath.WalkDir(skill.Dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(skill.Dir, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if prefix != "" && !strings.HasPrefix(rel, prefix) {
			return nil
		}
		info, _ := entry.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		out = append(out, map[string]any{"path": rel, "size": size})
		if len(out) >= 500 {
			return filepath.SkipAll
		}
		return nil
	})
	return out, err
}
