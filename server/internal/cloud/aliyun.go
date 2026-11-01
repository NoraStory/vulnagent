package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// aliyunProvider 阿里云 ECS DescribeInstances（RPC 签名，只读）
type aliyunProvider struct{}

func (aliyunProvider) List(ctx context.Context, cfg Config) ([]Instance, error) {
	accessKeyID, err := requireCredential(cfg, "accessKeyId")
	if err != nil {
		return nil, err
	}
	accessKeySecret, err := requireCredential(cfg, "accessKeySecret")
	if err != nil {
		return nil, err
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, fmt.Errorf("阿里云同步需要填写 region")
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = "https://ecs." + region + ".aliyuncs.com"
	}

	out := make([]Instance, 0, 100)
	const pageSize = 100
	for page := 1; page <= maxInstances/pageSize; page++ {
		params := map[string]string{
			"AccessKeyId":      accessKeyID,
			"Action":           "DescribeInstances",
			"Format":           "JSON",
			"Version":          "2014-05-26",
			"RegionId":         region,
			"PageNumber":       strconv.Itoa(page),
			"PageSize":         strconv.Itoa(pageSize),
			"SignatureMethod":  "HMAC-SHA1",
			"SignatureNonce":   aliyunNonce(),
			"SignatureVersion": "1.0",
			"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}
		params["Signature"] = aliyunSignature(http.MethodGet, params, accessKeySecret)
		body, err := httpGet(ctx, strings.TrimRight(endpoint, "/")+"/?"+canonicalQuery(params), nil)
		if err != nil {
			return nil, fmt.Errorf("阿里云 DescribeInstances 失败：%w", err)
		}
		items, total, err := parseAliyunInstances(body)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(items) == 0 || len(out) >= total || page*pageSize >= total {
			break
		}
	}
	if len(out) > maxInstances {
		out = out[:maxInstances]
	}
	return out, nil
}

// parseAliyunInstances 解析阿里云 ECS 响应
func parseAliyunInstances(body []byte) ([]Instance, int, error) {
	var resp struct {
		TotalCount int `json:"TotalCount"`
		Instances  struct {
			Instance []struct {
				InstanceID   string `json:"InstanceId"`
				InstanceName string `json:"InstanceName"`
				HostName     string `json:"HostName"`
				RegionID     string `json:"RegionId"`
				InstanceType string `json:"InstanceType"`
				Status       string `json:"Status"`
				OSType       string `json:"OSType"`
				Vpc          struct {
					PrivateIP struct {
						IPAddress []string `json:"IpAddress"`
					} `json:"PrivateIpAddress"`
				} `json:"VpcAttributes"`
				PublicIP struct {
					IPAddress []string `json:"IpAddress"`
				} `json:"PublicIpAddress"`
				EIP struct {
					IPAddress string `json:"IpAddress"`
				} `json:"EipAddress"`
				Tags struct {
					Tag []struct {
						TagKey   string `json:"TagKey"`
						TagValue string `json:"TagValue"`
					} `json:"Tag"`
				} `json:"Tags"`
			} `json:"Instance"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("解析阿里云响应失败：%w", err)
	}
	out := make([]Instance, 0, len(resp.Instances.Instance))
	for _, item := range resp.Instances.Instance {
		inst := Instance{
			InstanceID:   item.InstanceID,
			Name:         item.InstanceName,
			Hostname:     item.HostName,
			Region:       item.RegionID,
			InstanceType: item.InstanceType,
			Status:       strings.ToLower(item.Status),
			OSFamily:     strings.ToLower(item.OSType),
			Tags:         map[string]string{},
		}
		if len(item.Vpc.PrivateIP.IPAddress) > 0 {
			inst.PrivateIP = item.Vpc.PrivateIP.IPAddress[0]
		}
		if inst.PrivateIP == "" && len(item.PublicIP.IPAddress) > 0 {
			inst.PrivateIP = item.PublicIP.IPAddress[0]
		}
		if len(item.PublicIP.IPAddress) > 0 {
			inst.PublicIP = item.PublicIP.IPAddress[0]
		}
		if item.EIP.IPAddress != "" {
			inst.PublicIP = item.EIP.IPAddress
		}
		for _, tag := range item.Tags.Tag {
			if tag.TagKey != "" {
				inst.Tags[tag.TagKey] = tag.TagValue
			}
		}
		applyWellKnownTags(&inst)
		out = append(out, inst)
	}
	return out, resp.TotalCount, nil
}

func aliyunNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(buf)
}

// aliyunSignature 按阿里云 RPC 规范生成 HMAC-SHA1 签名
func aliyunSignature(method string, params map[string]string, accessKeySecret string) string {
	stringToSign := method + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery(params))
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, percentEncode(key)+"="+percentEncode(params[key]))
	}
	return strings.Join(parts, "&")
}

// percentEncode 按 RFC3986 编码（阿里云要求的 URLEncoder 变体）
func percentEncode(value string) string {
	var builder strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			builder.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&builder, "%%%02X", ch)
	}
	return builder.String()
}

func applyWellKnownTags(inst *Instance) {
	if inst.Tags == nil {
		return
	}
	readTag := func(keys ...string) string {
		for _, key := range keys {
			if value := strings.TrimSpace(inst.Tags[key]); value != "" {
				return value
			}
		}
		return ""
	}
	if inst.BusinessSystem == "" {
		inst.BusinessSystem = readTag("business_system", "businessSystem", "业务系统")
	}
	if inst.Department == "" {
		inst.Department = readTag("department", "部门")
	}
	if inst.Owner == "" {
		inst.Owner = readTag("owner", "责任人", "负责人")
	}
	if inst.OwnerEmail == "" {
		inst.OwnerEmail = readTag("owner_email", "ownerEmail")
	}
	if inst.Location == "" {
		inst.Location = readTag("location", "机房", "位置")
	}
}
