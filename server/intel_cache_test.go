package main

import (
	"context"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

type countingIntel struct {
	ports.IntelRepository
	metaCalls    int
	rangeCalls   int
	mappingCalls int
}

func (c *countingIntel) CVEMeta(ctx context.Context) (map[string]ports.CVEMeta, error) {
	c.metaCalls++
	return map[string]ports.CVEMeta{"CVE-1": {Score: 9.8}}, nil
}

func (c *countingIntel) AffectedByProduct(ctx context.Context) (map[string][]vuln.AffectedRange, error) {
	c.rangeCalls++
	return map[string][]vuln.AffectedRange{"pkg": {{CveID: "CVE-1"}}}, nil
}

func (c *countingIntel) ProductMappings(ctx context.Context) (map[string]ports.ProductMapping, error) {
	c.mappingCalls++
	return map[string]ports.ProductMapping{"eco/name": {Product: "pkg"}}, nil
}

func TestIntelSnapshotCache(t *testing.T) {
	inner := &countingIntel{}
	cache := newIntelSnapshotCache(inner)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if meta, err := cache.CVEMeta(ctx); err != nil || meta["CVE-1"].Score != 9.8 {
			t.Fatalf("读取 CVE 快照失败：%v %v", meta, err)
		}
		if ranges, err := cache.AffectedByProduct(ctx); err != nil || len(ranges["pkg"]) != 1 {
			t.Fatalf("读取区间快照失败：%v %v", ranges, err)
		}
		if mappings, err := cache.ProductMappings(ctx); err != nil || mappings["eco/name"].Product != "pkg" {
			t.Fatalf("读取映射快照失败：%v %v", mappings, err)
		}
		if affected, found, err := cache.AffectedFor(ctx, "CVE-1", "PKG"); err != nil || !found || len(affected) != 1 {
			t.Fatalf("按 CVE 取区间失败：%v %v %v", affected, found, err)
		}
		if _, found, err := cache.AffectedFor(ctx, "CVE-404", "pkg"); err != nil || found {
			t.Fatalf("未命中的 CVE 不应返回区间：found=%v err=%v", found, err)
		}
	}
	if inner.metaCalls != 1 || inner.rangeCalls != 1 || inner.mappingCalls != 1 {
		t.Fatalf("快照应只加载一次，实际 meta=%d ranges=%d mappings=%d",
			inner.metaCalls, inner.rangeCalls, inner.mappingCalls)
	}

	cache.Invalidate()
	if _, err := cache.CVEMeta(ctx); err != nil {
		t.Fatalf("失效后重新加载失败：%v", err)
	}
	if inner.metaCalls != 2 {
		t.Fatalf("失效后应重新加载，实际 %d 次", inner.metaCalls)
	}
}
