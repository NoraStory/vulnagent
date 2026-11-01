package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// cmdbProvider 外部 CMDB JSON API（GET，只读）
type cmdbProvider struct{}

func (cmdbProvider) List(ctx context.Context, cfg Config) ([]Instance, error) {
	target := strings.TrimSpace(cfg.URL)
	if target == "" {
		return nil, fmt.Errorf("外部 CMDB 同步需要填写 URL")
	}
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
	body, err := httpGet(ctx, target, headers)
	if err != nil {
		return nil, fmt.Errorf("请求外部 CMDB 失败：%w", err)
	}
	items, err := parseCMDBItems(body)
	if err != nil {
		return nil, err
	}
	if len(items) > maxInstances {
		items = items[:maxInstances]
	}
	return items, nil
}

// parseCMDBItems 解析数组或 {items|data|assets|results: [...]} 结构
func parseCMDBItems(body []byte) ([]Instance, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 CMDB 响应失败：%w", err)
	}
	var list []any
	switch typed := raw.(type) {
	case []any:
		list = typed
	case map[string]any:
		for _, key := range []string{"items", "data", "assets", "results", "list"} {
			if arr, ok := typed[key].([]any); ok {
				list = arr
				break
			}
		}
		if list == nil {
			list = []any{typed}
		}
	default:
		return nil, fmt.Errorf("CMDB 响应必须是数组或包含 items 的对象")
	}

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
	return out, nil
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
