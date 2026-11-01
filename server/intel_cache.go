package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

// intelCacheTTL 情报快照的兜底有效期；CVE/产品映射变更时会主动失效。
const intelCacheTTL = 60 * time.Second

// intelSnapshotCache 缓存全量情报索引，避免每次资产匹配都全表加载 CVEs/区间/映射。
// 返回的 map 只读，调用方不得修改。
type intelSnapshotCache struct {
	ports.IntelRepository

	mu       sync.Mutex
	loadedAt time.Time
	meta     map[string]ports.CVEMeta
	ranges   map[string][]vuln.AffectedRange
	mappings map[string]ports.ProductMapping
}

func newIntelSnapshotCache(inner ports.IntelRepository) *intelSnapshotCache {
	return &intelSnapshotCache{IntelRepository: inner}
}

func (c *intelSnapshotCache) ensure(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loadedAt.IsZero() && time.Since(c.loadedAt) < intelCacheTTL {
		return nil
	}
	meta, err := c.IntelRepository.CVEMeta(ctx)
	if err != nil {
		return err
	}
	ranges, err := c.IntelRepository.AffectedByProduct(ctx)
	if err != nil {
		return err
	}
	mappings, err := c.IntelRepository.ProductMappings(ctx)
	if err != nil {
		return err
	}
	c.meta, c.ranges, c.mappings = meta, ranges, mappings
	c.loadedAt = time.Now()
	return nil
}

func (c *intelSnapshotCache) CVEMeta(ctx context.Context) (map[string]ports.CVEMeta, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	return c.meta, nil
}

func (c *intelSnapshotCache) AffectedByProduct(ctx context.Context) (map[string][]vuln.AffectedRange, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	return c.ranges, nil
}

// AffectedFor 从快照中按 CVE + 产品过滤区间，避免复扫时逐条查库。
func (c *intelSnapshotCache) AffectedFor(ctx context.Context, cveID, product string) ([]vuln.AffectedRange, bool, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, false, err
	}
	all := c.ranges[strings.ToLower(product)]
	if len(all) == 0 {
		return nil, false, nil
	}
	out := make([]vuln.AffectedRange, 0, 2)
	for _, item := range all {
		if item.CveID == cveID {
			out = append(out, item)
		}
	}
	return out, len(out) > 0, nil
}

func (c *intelSnapshotCache) ProductMappings(ctx context.Context) (map[string]ports.ProductMapping, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	return c.mappings, nil
}

// Invalidate 让下一次匹配重新加载情报快照。
func (c *intelSnapshotCache) Invalidate() {
	c.mu.Lock()
	c.loadedAt = time.Time{}
	c.mu.Unlock()
}

// cachedIntelRepo 返回带进程内快照的只读情报仓储。
func (a *App) cachedIntelRepo() ports.IntelRepository {
	a.intelCacheOnce.Do(func() {
		a.intelCache = newIntelSnapshotCache(a.intelRepo())
	})
	return a.intelCache
}

// invalidateIntelCache 在情报或产品映射变更后主动失效缓存。
func (a *App) invalidateIntelCache() {
	a.intelCacheOnce.Do(func() {
		a.intelCache = newIntelSnapshotCache(a.intelRepo())
	})
	a.intelCache.Invalidate()
}
