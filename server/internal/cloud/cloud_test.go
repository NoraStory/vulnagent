package cloud

import (
	"strings"
	"testing"
)

func TestPercentEncode(t *testing.T) {
	cases := map[string]string{
		"abcXYZ019-_.~": "abcXYZ019-_.~",
		"a b":           "a%20b",
		"a*b":           "a%2Ab",
		"a/b":           "a%2Fb",
		"中文":            "%E4%B8%AD%E6%96%87",
	}
	for input, want := range cases {
		if got := percentEncode(input); got != want {
			t.Fatalf("percentEncode(%q) = %q，期望 %q", input, got, want)
		}
	}
}

func TestAliyunSignatureStable(t *testing.T) {
	params := map[string]string{
		"AccessKeyId":      "test-ak",
		"Action":           "DescribeInstances",
		"Format":           "JSON",
		"RegionId":         "cn-hangzhou",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "fixed",
		"SignatureVersion": "1.0",
		"Timestamp":        "2026-11-01T00:00:00Z",
		"Version":          "2014-05-26",
	}
	first := aliyunSignature("GET", params, "test-secret")
	second := aliyunSignature("GET", params, "test-secret")
	if first == "" || first != second {
		t.Fatalf("签名不稳定：%q / %q", first, second)
	}
	if other := aliyunSignature("GET", params, "other-secret"); other == first {
		t.Fatal("不同密钥不应产生相同签名")
	}
	query := canonicalQuery(params)
	if !strings.HasPrefix(query, "AccessKeyId=test-ak&Action=DescribeInstances") {
		t.Fatalf("参数未按字典序编码：%s", query)
	}
}

func TestParseAliyunInstances(t *testing.T) {
	body := []byte(`{
	  "TotalCount": 1,
	  "Instances": {"Instance": [{
	    "InstanceId": "i-bp1abc", "InstanceName": "web-01", "HostName": "web-01",
	    "RegionId": "cn-hangzhou", "InstanceType": "ecs.g6.large", "Status": "Running", "OSType": "linux",
	    "VpcAttributes": {"PrivateIpAddress": {"IpAddress": ["10.0.0.10"]}},
	    "PublicIpAddress": {"IpAddress": ["47.1.1.1"]},
	    "EipAddress": {"IpAddress": ""},
	    "Tags": {"Tag": [{"TagKey": "business_system", "TagValue": "交易系统"}, {"TagKey": "owner", "TagValue": "张三"}]}
	  }]}
	}`)
	items, total, err := parseAliyunInstances(body)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("解析阿里云响应失败：total=%d len=%d err=%v", total, len(items), err)
	}
	item := items[0]
	if item.InstanceID != "i-bp1abc" || item.PrivateIP != "10.0.0.10" || item.PublicIP != "47.1.1.1" ||
		item.OSFamily != "linux" || item.BusinessSystem != "交易系统" || item.Owner != "张三" {
		t.Fatalf("阿里云实例字段映射异常：%+v", item)
	}
}

func TestParseAWSInstances(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item><instancesSet>
      <item>
        <instanceId>i-aws-01</instanceId>
        <instanceType>t3.micro</instanceType>
        <privateIpAddress>10.1.0.5</privateIpAddress>
        <ipAddress>3.3.3.3</ipAddress>
        <privateDnsName>ip-10-1-0-5.ec2.internal</privateDnsName>
        <instanceState><name>running</name></instanceState>
        <placement><availabilityZone>us-east-1a</availabilityZone></placement>
        <tagSet>
          <item><key>Name</key><value>aws-web-01</value></item>
          <item><key>department</key><value>基础架构</value></item>
        </tagSet>
      </item>
    </instancesSet></item>
  </reservationSet>
  <nextToken>token-1</nextToken>
</DescribeInstancesResponse>`)
	items, next, err := parseAWSInstances(body)
	if err != nil || len(items) != 1 || next != "token-1" {
		t.Fatalf("解析 AWS 响应失败：len=%d next=%s err=%v", len(items), next, err)
	}
	item := items[0]
	if item.InstanceID != "i-aws-01" || item.Hostname != "aws-web-01" || item.PrivateIP != "10.1.0.5" ||
		item.Region != "us-east-1a" || item.Department != "基础架构" || item.OSFamily != "linux" {
		t.Fatalf("AWS 实例字段映射异常：%+v", item)
	}
}

func TestParseAzureVMs(t *testing.T) {
	body := []byte(`{
	  "nextLink": "https://management.azure.com/next",
	  "value": [{
	    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
	    "name": "vm1", "location": "eastus", "tags": {"business_system": "订单系统"},
	    "properties": {
	      "vmId": "vm-uuid-1",
	      "osProfile": {"computerName": "vm1-host"},
	      "storageProfile": {"osDisk": {"osType": "Windows"}}
	    }
	  }]
	}`)
	items, next, err := parseAzureVMs(body)
	if err != nil || len(items) != 1 || next == "" {
		t.Fatalf("解析 Azure 响应失败：len=%d next=%s err=%v", len(items), next, err)
	}
	item := items[0]
	if item.InstanceID != "vm-uuid-1" || item.Hostname != "vm1-host" || item.OSFamily != "windows" ||
		item.BusinessSystem != "订单系统" || item.Region != "eastus" {
		t.Fatalf("Azure 实例字段映射异常：%+v", item)
	}
}

func TestParseCMDBItems(t *testing.T) {
	body := []byte(`{
	  "items": [
	    {"id":"cmdb-1","hostname":"cmdb-web-01","private_ip":"10.2.0.5","os":"Ubuntu 22.04",
	     "business_system":"交易系统","owner":"李四","tags":{"env":"prod"},"serial":"SN-01"},
	    {"name":"cmdb-db-01","ip":"10.2.0.6","osType":"Windows","status":"running"}
	  ]
	}`)
	items, err := parseCMDBItems(body)
	if err != nil || len(items) != 2 {
		t.Fatalf("解析 CMDB 响应失败：len=%d err=%v", len(items), err)
	}
	if items[0].InstanceID != "cmdb-1" || items[0].PrivateIP != "10.2.0.5" || items[0].OSFamily != "linux" ||
		items[0].BusinessSystem != "交易系统" || items[0].Owner != "李四" || items[0].Serial != "SN-01" {
		t.Fatalf("CMDB 字段映射异常：%+v", items[0])
	}
	if items[1].Hostname != "cmdb-db-01" || items[1].OSFamily != "windows" {
		t.Fatalf("CMDB 主机名/OS 映射异常：%+v", items[1])
	}

	if _, err := parseCMDBItems([]byte(`{"foo":"bar"}`)); err != nil {
		t.Fatalf("单对象响应应可解析：%v", err)
	}
}
