package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// cmdbProvider 外部 CMDB JSON API（GET，只读）
type cmdbProvider struct{}

const (
	defaultCMDBPageSize = 200
	defaultCMDBMaxPages = 50
)

// cmdbPaging 分页运行时参数（由 Config 归一化得到）
type cmdbPaging struct {
	mode          string
	pageParam     string
	pageSizeParam string
	pageSize      int
	startPage     int
	cursorParam   string
	cursorField   string
	itemsField    string
	totalField    string
	maxPages      int
}

func newCMDBPaging(cfg Config) cmdbPaging {
	p := cmdbPaging{
		mode: "auto", pageParam: "page", pageSizeParam: "pageSize", pageSize: defaultCMDBPageSize,
		startPage: 1, cursorParam: "cursor", cursorField: "next", maxPages: defaultCMDBMaxPages,
	}
	if value := strings.ToLower(strings.TrimSpace(cfg.Pagination)); value != "" {
		p.mode = value
	}
	if value := strings.TrimSpace(cfg.PageParam); value != "" {
		p.pageParam = value
	}
	if value := strings.TrimSpace(cfg.PageSizeParam); value != "" {
		p.pageSizeParam = value
	}
	if cfg.PageSize > 0 {
		p.pageSize = cfg.PageSize
	}
	if p.pageSize > 1000 {
		p.pageSize = 1000
	}
	if cfg.StartPage > 0 {
		p.startPage = cfg.StartPage
	}
	if value := strings.TrimSpace(cfg.CursorParam); value != "" {
		p.cursorParam = value
	}
	if value := strings.TrimSpace(cfg.CursorField); value != "" {
		p.cursorField = value
	}
	if value := strings.TrimSpace(cfg.ItemsField); value != "" {
		p.itemsField = value
	}
	if value := strings.TrimSpace(cfg.TotalField); value != "" {
		p.totalField = value
	}
	if cfg.MaxPages > 0 {
		p.maxPages = cfg.MaxPages
	}
	if p.maxPages > 500 {
		p.maxPages = 500
	}
	return p
}

// List 按分页契约拉取全部实例：
//   - auto（默认）：单页请求后若响应含 next 则继续，next 可以是游标、相对地址或同源绝对地址
//   - none：只取单页
//   - page：按 page/pageSize 翻页，依据 total 或不足一页停止
//   - cursor：按游标参数翻页，游标取自响应字段（默认 next）
func (cmdbProvider) List(ctx context.Context, cfg Config) ([]Instance, error) {
	target := strings.TrimSpace(cfg.URL)
	if target == "" {
		return nil, fmt.Errorf("外部 CMDB 同步需要填写 URL")
	}
	headers, err := cmdbHeaders(cfg)
	if err != nil {
		return nil, err
	}
	paging := newCMDBPaging(cfg)
	switch paging.mode {
	case "auto", "none", "page", "cursor":
	default:
		return nil, fmt.Errorf("不支持的分页方式：%s", paging.mode)
	}

	out := make([]Instance, 0, 64)
	seen := map[string]bool{target: true}
	next := ""
	for pageIndex := 0; pageIndex < paging.maxPages; pageIndex++ {
		requestURL := target
		switch paging.mode {
		case "page":
			requestURL = cmdbWithQuery(target, paging.pageParam, strconv.Itoa(paging.startPage+pageIndex))
			requestURL = cmdbWithQuery(requestURL, paging.pageSizeParam, strconv.Itoa(paging.pageSize))
		case "cursor", "auto":
			if pageIndex > 0 {
				requestURL = next
			}
		}
		if pageIndex > 0 && seen[requestURL] {
			break
		}
		seen[requestURL] = true

		body, err := httpGet(ctx, requestURL, headers)
		if err != nil {
			return nil, fmt.Errorf("请求外部 CMDB 失败（第 %d 页）：%w", pageIndex+1, err)
		}
		payload, items, err := parseCMDBPage(body, paging.itemsField)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(out) >= maxInstances {
			return out[:maxInstances], nil
		}
		if len(items) == 0 {
			break
		}
		switch paging.mode {
		case "none":
			return out, nil
		case "page":
			if total, ok := cmdbLookupNumber(payload, paging.totalField); ok {
				if (pageIndex+1)*paging.pageSize >= int(total) {
					return out, nil
				}
			} else if len(items) < paging.pageSize {
				return out, nil
			}
		case "cursor", "auto":
			value, ok := cmdbLookupString(payload, paging.cursorField)
			if !ok || strings.TrimSpace(value) == "" {
				return out, nil
			}
			if paging.mode == "cursor" {
				next = cmdbWithQuery(target, paging.cursorParam, value)
				break
			}
			resolved, err := cmdbResolveNext(target, paging.cursorParam, value)
			if err != nil {
				return nil, err
			}
			next = resolved
		}
	}
	return out, nil
}

// cmdbHeaders 按认证方式构造请求头
func cmdbHeaders(cfg Config) (map[string]string, error) {
	headers := map[string]string{"Accept": "application/json"}
	switch strings.ToLower(strings.TrimSpace(cfg.AuthType)) {
	case "", "none":
	case "bearer":
		token, err := requireCredential(cfg, "token")
		if err != nil {
			return nil, err
		}
		headers["Authorization"] = "Bearer " + token
	case "basic":
		username, err := requireCredential(cfg, "username")
		if err != nil {
			return nil, err
		}
		password, err := requireCredential(cfg, "password")
		if err != nil {
			return nil, err
		}
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	default:
		return nil, fmt.Errorf("不支持的认证方式：%s", cfg.AuthType)
	}
	return headers, nil
}

// cmdbWithQuery 在保留原查询参数的前提下设置一个参数
func cmdbWithQuery(rawURL, key, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// cmdbResolveNext 解析 next：同源地址直接使用，其余作为游标拼到配置 URL
func cmdbResolveNext(base, cursorParam, next string) (string, error) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "", nil
	}
	lower := strings.ToLower(next)
	isURL := strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(next, "/") || strings.HasPrefix(next, "?")
	if !isURL {
		return cmdbWithQuery(base, cursorParam, next), nil
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("CMDB 地址无效：%w", err)
	}
	ref, err := url.Parse(next)
	if err != nil {
		return "", fmt.Errorf("下一页地址无效：%w", err)
	}
	resolved := ref
	if !ref.IsAbs() {
		resolved = baseURL.ResolveReference(ref)
	}
	if !strings.EqualFold(resolved.Scheme, baseURL.Scheme) || !strings.EqualFold(resolved.Host, baseURL.Host) {
		return "", fmt.Errorf("下一页地址必须与配置的 CMDB 同源：%s", resolved.Host)
	}
	return resolved.String(), nil
}

// cmdbLookup 按点路径读取嵌套字段，例如 data.items
func cmdbLookup(payload map[string]any, path string) (any, bool) {
	if payload == nil || path == "" {
		return nil, false
	}
	var current any = payload
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func cmdbLookupString(payload map[string]any, path string) (string, bool) {
	value, ok := cmdbLookup(payload, path)
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	default:
		return "", false
	}
}

func cmdbLookupNumber(payload map[string]any, path string) (float64, bool) {
	value, ok := cmdbLookup(payload, path)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return typed, true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	case string:
		number, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return number, err == nil
	default:
		return 0, false
	}
}

// cmdbExtractList 从响应对象中定位条目数组，支持嵌套 data.items 等结构
func cmdbExtractList(payload map[string]any, itemsField string) []any {
	if itemsField != "" {
		if value, ok := cmdbLookup(payload, itemsField); ok {
			if list, ok := value.([]any); ok {
				return list
			}
		}
	}
	for _, key := range []string{"items", "data", "assets", "results", "list", "records"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		if list, ok := value.([]any); ok {
			return list
		}
		if nested, ok := value.(map[string]any); ok {
			for _, inner := range []string{"items", "assets", "results", "list", "records", "rows"} {
				if list, ok := nested[inner].([]any); ok {
					return list
				}
			}
		}
	}
	return nil
}

// parseCMDBPage 解析一页响应，返回完整对象（用于读取 total/next）与实例列表
func parseCMDBPage(body []byte, itemsField string) (map[string]any, []Instance, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("解析 CMDB 响应失败：%w", err)
	}
	switch typed := raw.(type) {
	case []any:
		return nil, cmdbMapInstances(typed), nil
	case map[string]any:
		list := cmdbExtractList(typed, itemsField)
		if list == nil {
			// 兼容单对象响应：把整个对象当作一台实例
			list = []any{typed}
		}
		return typed, cmdbMapInstances(list), nil
	default:
		return nil, nil, fmt.Errorf("CMDB 响应必须是数组或包含 items 的对象")
	}
}

// parseCMDBItems 解析数组或 {items|data|assets|results: [...]} 结构
func parseCMDBItems(body []byte) ([]Instance, error) {
	_, items, err := parseCMDBPage(body, "")
	return items, err
}

// cmdbMapInstances 把原始条目映射为实例
func cmdbMapInstances(list []any) []Instance {
	out := make([]Instance, 0, len(list))
	for _, rawItem := range list {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		inst := Instance{
			InstanceID:     firstValue(item, "instanceId", "instance_id", "id", "uuid"),
			Name:           firstValue(item, "name", "hostname", "hostName", "host"),
			Hostname:       firstValue(item, "hostname", "hostName", "host", "name"),
			PrivateIP:      firstValue(item, "privateIp", "private_ip", "ip", "ipAddress", "ip_address"),
			PublicIP:       firstValue(item, "publicIp", "public_ip", "publicIpAddress", "eip"),
			OSFamily:       normalizeOSFamily(firstValue(item, "osFamily", "os_family", "os", "osType", "platform")),
			OSVersion:      firstValue(item, "osVersion", "os_version", "version"),
			Region:         firstValue(item, "region", "zone", "availabilityZone"),
			InstanceType:   firstValue(item, "instanceType", "instance_type", "flavor", "spec"),
			Status:         firstValue(item, "status", "state"),
			Serial:         firstValue(item, "serial", "serialNumber", "sn"),
			MAC:            firstValue(item, "mac", "macAddress", "mac_address"),
			BusinessSystem: firstValue(item, "businessSystem", "business_system", "业务系统"),
			Department:     firstValue(item, "department", "部门"),
			Owner:          firstValue(item, "owner", "责任人", "负责人"),
			OwnerEmail:     firstValue(item, "ownerEmail", "owner_email", "邮箱"),
			Location:       firstValue(item, "location", "datacenter", "机房", "位置"),
			Tags:           tagsFromAny(item["tags"]),
		}
		if inst.Tags == nil {
			inst.Tags = map[string]string{}
		}
		applyWellKnownTags(&inst)
		if inst.Name == "" {
			inst.Name = inst.Hostname
		}
		out = append(out, inst)
	}
	return out
}

func normalizeOSFamily(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "":
		return ""
	case strings.Contains(value, "win"):
		return "windows"
	case strings.Contains(value, "linux"), strings.Contains(value, "debian"), strings.Contains(value, "ubuntu"),
		strings.Contains(value, "centos"), strings.Contains(value, "rhel"), strings.Contains(value, "rocky"),
		strings.Contains(value, "alpine"), strings.Contains(value, "suse"):
		return "linux"
	}
	return value
}
