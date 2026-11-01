package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// azureProvider Azure Resource Manager 虚拟机列表（OAuth2 客户端凭据，只读）
type azureProvider struct{}

func (azureProvider) List(ctx context.Context, cfg Config) ([]Instance, error) {
	tenantID, err := requireCredential(cfg, "tenantId")
	if err != nil {
		return nil, err
	}
	clientID, err := requireCredential(cfg, "clientId")
	if err != nil {
		return nil, err
	}
	clientSecret, err := requireCredential(cfg, "clientSecret")
	if err != nil {
		return nil, err
	}
	subscriptionID := strings.TrimSpace(cfg.SubscriptionID)
	if subscriptionID == "" {
		return nil, fmt.Errorf("Azure 同步需要填写 subscriptionId")
	}
	loginEndpoint := "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token"
	tokenBody, err := postForm(ctx, loginEndpoint, map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "https://management.azure.com/.default",
	})
	if err != nil {
		return nil, fmt.Errorf("Azure 获取访问令牌失败：%w", err)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenBody, &token); err != nil || token.AccessToken == "" {
		return nil, fmt.Errorf("Azure 令牌响应无效：%s", truncateText(string(tokenBody), 200))
	}

	management := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if management == "" {
		management = "https://management.azure.com"
	}
	nextLink := management + "/subscriptions/" + subscriptionID +
		"/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01"

	out := make([]Instance, 0, 64)
	for page := 0; page < 50 && nextLink != ""; page++ {
		body, err := httpGet(ctx, nextLink, map[string]string{
			"Authorization": "Bearer " + token.AccessToken,
		})
		if err != nil {
			return nil, fmt.Errorf("Azure 查询虚拟机失败：%w", err)
		}
		items, next, err := parseAzureVMs(body)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		nextLink = next
		if len(out) >= maxInstances {
			break
		}
	}
	if len(out) > maxInstances {
		out = out[:maxInstances]
	}
	return out, nil
}

// parseAzureVMs 解析 ARM 虚拟机列表
func parseAzureVMs(body []byte) ([]Instance, string, error) {
	var resp struct {
		NextLink string `json:"nextLink"`
		Value    []struct {
			ID       string            `json:"id"`
			Name     string            `json:"name"`
			Location string            `json:"location"`
			Tags     map[string]string `json:"tags"`
			Props    struct {
				VMID      string `json:"vmId"`
				OSProfile struct {
					ComputerName string `json:"computerName"`
				} `json:"osProfile"`
				StorageProfile struct {
					OSDisk struct {
						OSType string `json:"osType"`
					} `json:"osDisk"`
				} `json:"storageProfile"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("解析 Azure 响应失败：%w", err)
	}
	out := make([]Instance, 0, len(resp.Value))
	for _, vm := range resp.Value {
		inst := Instance{
			InstanceID: firstNonEmpty(vm.Props.VMID, vm.ID),
			Name:       vm.Name,
			Hostname:   firstNonEmpty(vm.Props.OSProfile.ComputerName, vm.Name),
			Region:     vm.Location,
			OSFamily:   strings.ToLower(vm.Props.StorageProfile.OSDisk.OSType),
			Status:     "running",
			Tags:       vm.Tags,
		}
		if inst.Tags == nil {
			inst.Tags = map[string]string{}
		}
		applyWellKnownTags(&inst)
		out = append(out, inst)
	}
	return out, resp.NextLink, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
