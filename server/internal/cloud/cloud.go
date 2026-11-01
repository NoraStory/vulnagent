// Package cloud 提供云厂商与外部 CMDB 的只读资产拉取适配器。
// 所有适配器只做查询，不创建、修改或删除云端资源。
package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Instance 云端或外部 CMDB 的一台实例
type Instance struct {
	InstanceID     string            `json:"instanceId"`
	Name           string            `json:"name"`
	Hostname       string            `json:"hostname"`
	PrivateIP      string            `json:"privateIp"`
	PublicIP       string            `json:"publicIp"`
	OSFamily       string            `json:"osFamily"`
	OSVersion      string            `json:"osVersion"`
	Region         string            `json:"region"`
	InstanceType   string            `json:"instanceType"`
	Status         string            `json:"status"`
	Serial         string            `json:"serial"`
	MAC            string            `json:"mac"`
	BusinessSystem string            `json:"businessSystem"`
	Department     string            `json:"department"`
	Owner          string            `json:"owner"`
	OwnerEmail     string            `json:"ownerEmail"`
	Location       string            `json:"location"`
	Tags           map[string]string `json:"tags"`
}

// Config 非敏感配置 + 解密后的凭据
type Config struct {
	Region         string
	Endpoint       string
	URL            string
	AuthType       string
	SubscriptionID string
	Credentials    map[string]string
}

// Provider 只读实例列表适配器
type Provider interface {
	List(ctx context.Context, cfg Config) ([]Instance, error)
}

// Kind 集成类型
type Kind string

const (
	KindAliyun Kind = "cloud_aliyun"
	KindAWS    Kind = "cloud_aws"
	KindAzure  Kind = "cloud_azure"
	KindCMDB   Kind = "cmdb_api"
)

// Kinds 返回支持的集成类型
func Kinds() []string {
	return []string{string(KindAliyun), string(KindAWS), string(KindAzure), string(KindCMDB)}
}

// New 按类型构造适配器
func New(kind string) (Provider, error) {
	switch Kind(strings.TrimSpace(kind)) {
	case KindAliyun:
		return aliyunProvider{}, nil
	case KindAWS:
		return awsProvider{}, nil
	case KindAzure:
		return azureProvider{}, nil
	case KindCMDB:
		return cmdbProvider{}, nil
	}
	return nil, fmt.Errorf("不支持的集成类型：%s", kind)
}

// maxInstances 单次同步上限，避免异常账号拖垮控制面
const maxInstances = 5000

// httpClient 统一的只读请求客户端
var httpClient = &http.Client{Timeout: 60 * time.Second}

func httpGet(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vulnagent-cloud-sync")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d：%s", resp.StatusCode, truncateText(string(body), 300))
	}
	return body, nil
}

func postForm(ctx context.Context, endpoint string, form map[string]string) ([]byte, error) {
	values := url.Values{}
	for key, value := range form {
		values.Set(key, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "vulnagent-cloud-sync")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d：%s", resp.StatusCode, truncateText(string(body), 300))
	}
	return body, nil
}

func firstValue(m map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case float64:
			return fmt.Sprintf("%.0f", typed)
		case json.Number:
			return typed.String()
		}
	}
	return ""
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return strings.Split(typed, ",")
	}
	return nil
}

func tagsFromAny(value any) map[string]string {
	out := map[string]string{}
	switch typed := value.(type) {
	case map[string]any:
		for key, raw := range typed {
			if text, ok := raw.(string); ok {
				out[key] = text
			}
		}
	case []any:
		for _, item := range typed {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key := firstValue(entry, "key", "Key", "tagKey", "TagKey", "name")
			val := firstValue(entry, "value", "Value", "tagValue", "TagValue")
			if key != "" {
				out[key] = val
			}
		}
	}
	return out
}

func truncateText(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}

func requireCredential(cfg Config, key string) (string, error) {
	value := strings.TrimSpace(cfg.Credentials[key])
	if value == "" {
		return "", errors.New("缺少凭据：" + key)
	}
	return value, nil
}
