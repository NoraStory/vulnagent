package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// awsProvider AWS EC2 DescribeInstances（SigV4 签名，只读）
type awsProvider struct{}

func (awsProvider) List(ctx context.Context, cfg Config) ([]Instance, error) {
	accessKeyID, err := requireCredential(cfg, "accessKeyId")
	if err != nil {
		return nil, err
	}
	secretKey, err := requireCredential(cfg, "secretAccessKey")
	if err != nil {
		return nil, err
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, fmt.Errorf("AWS 同步需要填写 region")
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = "https://ec2." + region + ".amazonaws.com"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("AWS endpoint 无效：%w", err)
	}
	host := parsed.Host

	out := make([]Instance, 0, 100)
	nextToken := ""
	for page := 0; page < 50; page++ {
		params := map[string]string{
			"Action":  "DescribeInstances",
			"Version": "2016-11-15",
		}
		if nextToken != "" {
			params["NextToken"] = nextToken
		}
		query := canonicalQuery(params)
		requestURL := strings.TrimRight(endpoint, "/") + "/?" + query

		amzDate := time.Now().UTC().Format("20060102T150405Z")
		dateStamp := amzDate[:8]
		payloadHash := sha256Hex(nil)
		canonicalHeaders := "host:" + host + "\n" +
			"x-amz-content-sha256:" + payloadHash + "\n" +
			"x-amz-date:" + amzDate + "\n"
		signedHeaders := "host;x-amz-content-sha256;x-amz-date"
		canonicalRequest := "GET\n/\n" + query + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
		scope := dateStamp + "/" + region + "/ec2/aws4_request"
		stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
		signingKey := awsSigningKey(secretKey, dateStamp, region, "ec2")
		signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
		authorization := "AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/" + scope +
			", SignedHeaders=" + signedHeaders + ", Signature=" + signature

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, err
		}
		req.Host = host
		req.Header.Set("User-Agent", "vulnagent-cloud-sync")
		req.Header.Set("x-amz-date", amzDate)
		req.Header.Set("x-amz-content-sha256", payloadHash)
		req.Header.Set("Authorization", authorization)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("AWS DescribeInstances 失败：%w", err)
		}
		body, readErr := readLimited(resp.Body, 8<<20)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d：%s", resp.StatusCode, truncateText(string(body), 300))
		}
		items, token, err := parseAWSInstances(body)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		nextToken = token
		if nextToken == "" || len(out) >= maxInstances {
			break
		}
	}
	if len(out) > maxInstances {
		out = out[:maxInstances]
	}
	return out, nil
}

// parseAWSInstances 解析 AWS EC2 XML 响应
func parseAWSInstances(body []byte) ([]Instance, string, error) {
	type tag struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	}
	type instance struct {
		InstanceID   string `xml:"instanceId"`
		InstanceType string `xml:"instanceType"`
		PrivateIP    string `xml:"privateIpAddress"`
		PublicIP     string `xml:"ipAddress"`
		PrivateDNS   string `xml:"privateDnsName"`
		PublicDNS    string `xml:"dnsName"`
		State        string `xml:"instanceState>name"`
		Platform     string `xml:"platform"`
		Placement    struct {
			Zone string `xml:"availabilityZone"`
		} `xml:"placement"`
		Tags []tag `xml:"tagSet>item"`
	}
	var resp struct {
		NextToken    string `xml:"nextToken"`
		Reservations []struct {
			Instances []instance `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("解析 AWS 响应失败：%w", err)
	}
	out := make([]Instance, 0, 32)
	for _, reservation := range resp.Reservations {
		for _, item := range reservation.Instances {
			inst := Instance{
				InstanceID:   item.InstanceID,
				InstanceType: item.InstanceType,
				PrivateIP:    item.PrivateIP,
				PublicIP:     item.PublicIP,
				Hostname:     item.PrivateDNS,
				Region:       item.Placement.Zone,
				Status:       item.State,
				OSFamily:     "linux",
				Tags:         map[string]string{},
			}
			if item.Platform == "windows" {
				inst.OSFamily = "windows"
			}
			if inst.Hostname == "" || strings.HasSuffix(inst.Hostname, ".internal") {
				for _, t := range item.Tags {
					if strings.EqualFold(t.Key, "Name") && strings.TrimSpace(t.Value) != "" {
						inst.Hostname = t.Value
					}
				}
			}
			if inst.Hostname == "" {
				inst.Hostname = item.PublicDNS
			}
			for _, t := range item.Tags {
				if t.Key != "" {
					inst.Tags[t.Key] = t.Value
				}
			}
			applyWellKnownTags(&inst)
			out = append(out, inst)
		}
	}
	return out, resp.NextToken, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// readLimited 读取响应体上限
func readLimited(body io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, limit))
}
