package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/infrastructure/sqlite"
	"vulnagent/server/internal/platform/config"
)

// defaultIntelBaseURL 默认情报站，定义见 internal/platform/config
const defaultIntelBaseURL = config.DefaultIntelBaseURL

// intelItem 漏洞平台 /api/cve/ 返回的单条数据。
// 兼容 desc/description 两种字段名，以及 cwe_id 为 "CWE-502" 或数字两种形式。
type intelItem struct {
	CveID       string   `json:"cve_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Desc        string   `json:"desc"`
	CvssVector  string   `json:"cvss_vector"`
	CweID       flexInt  `json:"cwe_id"`
	CweCN       string   `json:"cwe_cn"`
	PublishedAt string   `json:"published_at"`
	UpdatedAt   string   `json:"updated_at"`
	Pocs        []string `json:"pocs"`
}

func (it intelItem) text() string {
	if it.Description != "" {
		return it.Description
	}
	return it.Desc
}

// flexInt 允许 JSON 数字或 "CWE-502" 形式的字符串
type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	raw := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if raw == "" || strings.EqualFold(raw, "null") {
		*f = 0
		return nil
	}
	raw = strings.TrimPrefix(strings.ToUpper(raw), "CWE-")
	n, err := strconv.Atoi(raw)
	if err != nil {
		*f = 0
		return nil
	}
	*f = flexInt(n)
	return nil
}

type intelEnvelope struct {
	Data    []intelItem `json:"data"`
	Success bool        `json:"success"`
}

// pocItemAPI /api/poc/ 返回的单条数据
type pocItemAPI struct {
	CveID       string `json:"cve_id"`
	Description string `json:"description"`
	InsertAt    string `json:"insert_at"`
	Link        string `json:"link"`
}

type pocEnvelope struct {
	Data    []pocItemAPI `json:"data"`
	Success bool         `json:"success"`
}

// cveClient 漏洞平台 API 客户端
type cveClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newCVEClient(baseURL, apiKey string) *cveClient {
	if baseURL == "" {
		baseURL = defaultIntelBaseURL
	}
	return &cveClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 20 * time.Second},
	}
}

func intelBaseURLFromEnv() string { return config.Load().IntelBaseURL }

// get 带 429/5xx 重试的 GET
func (c *cveClient) get(ctx context.Context, path string, params url.Values, out any) error {
	endpoint := c.baseURL + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if c.apiKey != "" {
			req.Header.Set("X-API-Key", c.apiKey)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = readErr
			case resp.StatusCode == http.StatusOK:
				if err := json.Unmarshal(body, out); err != nil {
					return fmt.Errorf("解析情报响应失败: %w", err)
				}
				return nil
			case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
				return fmt.Errorf("情报平台拒绝访问（HTTP %d），请检查 API Key", resp.StatusCode)
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				lastErr = fmt.Errorf("情报平台返回 HTTP %d", resp.StatusCode)
			default:
				return fmt.Errorf("情报平台返回 HTTP %d", resp.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return fmt.Errorf("情报请求失败: %w", lastErr)
}

func (c *cveClient) Latest(ctx context.Context, page, perPage int, search string) ([]intelItem, error) {
	params := url.Values{}
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("per_page", fmt.Sprintf("%d", perPage))
	if search != "" {
		params.Set("search", search)
	}
	var out intelEnvelope
	if err := c.get(ctx, "/api/cve/", params, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (c *cveClient) Detail(ctx context.Context, cveID string) (intelItem, error) {
	var out struct {
		Data    intelItem `json:"data"`
		Success bool      `json:"success"`
	}
	if err := c.get(ctx, "/api/cve/"+url.PathEscape(cveID), nil, &out); err != nil {
		return intelItem{}, err
	}
	return out.Data, nil
}

func (c *cveClient) LatestPOC(ctx context.Context, page, perPage int) ([]pocItemAPI, error) {
	params := url.Values{}
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("per_page", fmt.Sprintf("%d", perPage))
	var out pocEnvelope
	if err := c.get(ctx, "/api/poc/", params, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// ---------- 同步 ----------

type syncResult struct {
	Mode     string `json:"mode"`
	Fetched  int    `json:"fetched"`
	Inserted int    `json:"inserted"`
	Updated  int    `json:"updated"`
	Cursor   string `json:"cursor"`
}

// syncCVEFromAPI 按更新时间增量拉取，遇到不新于游标的数据即停止
func syncCVEFromAPI(ctx context.Context, db *sql.DB, client *cveClient, maxPages int) (syncResult, error) {
	res := syncResult{Mode: "api"}
	if maxPages <= 0 {
		maxPages = 20
	}
	cursor := cveCursor(db)
	stop := false
	for page := 1; page <= maxPages && !stop; page++ {
		items, err := client.Latest(ctx, page, 100, "")
		if err != nil {
			markSync(db, "cve", "fail", err.Error())
			return res, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			updated, _ := parseT(normalizeAPITime(item.UpdatedAt))
			if !cursor.IsZero() && !updated.After(cursor) {
				stop = true
				break
			}
			inserted, err := upsertCVE(db, item)
			if err != nil {
				markSync(db, "cve", "fail", err.Error())
				return res, err
			}
			res.Fetched++
			if inserted {
				res.Inserted++
			} else {
				res.Updated++
			}
		}
		if len(items) < 100 {
			break
		}
	}
	res.Cursor = fmtT(nowT())
	markSync(db, "cve", "ok", "")
	// 平台同步游标单独记录，避免 OSV 等其他来源写入 cves 干扰增量判断
	_ = setMeta(db, "cve_cursor", res.Cursor)
	return res, nil
}

// syncPOCFromAPI 增量拉取 POC 情报
func syncPOCFromAPI(ctx context.Context, db *sql.DB, client *cveClient, maxPages int) (syncResult, error) {
	res := syncResult{Mode: "api"}
	if maxPages <= 0 {
		maxPages = 10
	}
	cursor := pocCursor(db)
	stop := false
	for page := 1; page <= maxPages && !stop; page++ {
		items, err := client.LatestPOC(ctx, page, 100)
		if err != nil {
			markSync(db, "poc", "fail", err.Error())
			return res, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			if item.CveID == "" || item.Link == "" {
				continue
			}
			insertedAt := normalizeAPITime(item.InsertAt)
			insertedTime, _ := parseT(insertedAt)
			if !cursor.IsZero() && !insertedTime.After(cursor) {
				stop = true
				break
			}
			result, err := sqlite.NewIntelRepo(db).AddPOC(context.Background(), item.CveID, item.Link, insertedAt)
			if err != nil {
				return res, err
			}
			res.Fetched++
			if result {
				res.Inserted++
			}
		}
		if len(items) < 100 {
			break
		}
	}
	res.Cursor = fmtT(nowT())
	markSync(db, "poc", "ok", "")
	return res, nil
}

// importBundle 导入离线情报包（无外网环境使用）
func importBundle(db *sql.DB, path string) (syncResult, error) {
	res := syncResult{Mode: "bundle"}
	info, err := os.Stat(path)
	if err != nil {
		return res, fmt.Errorf("读取情报包失败: %w", err)
	}
	if info.Size() > 256<<20 {
		return res, errors.New("情报包超过 256MB 限制")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return res, err
	}

	var bundle struct {
		Source string       `json:"source"`
		Items  []intelItem  `json:"items"`
		POCs   []pocItemAPI `json:"pocs"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		// 兼容直接给数组的简化格式
		var items []intelItem
		if err2 := json.Unmarshal(raw, &items); err2 != nil {
			return res, fmt.Errorf("情报包格式无效: %w", err)
		}
		bundle.Items = items
	}
	if bundle.Source != "" && bundle.Source != "cve" {
		return res, fmt.Errorf("暂不支持的情报包类型：%s", bundle.Source)
	}
	for _, item := range bundle.Items {
		if item.CveID == "" {
			continue
		}
		inserted, err := upsertCVE(db, item)
		if err != nil {
			return res, err
		}
		res.Fetched++
		if inserted {
			res.Inserted++
		} else {
			res.Updated++
		}
	}
	for _, poc := range bundle.POCs {
		if poc.CveID == "" || poc.Link == "" {
			continue
		}
		if _, err := sqlite.NewIntelRepo(db).AddPOC(context.Background(), poc.CveID, poc.Link,
			normalizeAPITime(poc.InsertAt)); err != nil {
			return res, err
		}
	}
	res.Cursor = fmtT(nowT())
	markSync(db, "cve", "ok", "")
	slog.Info("离线情报包导入完成", "file", path, "inserted", res.Inserted, "updated", res.Updated)
	return res, nil
}

// upsertCVE 写入或更新单条 CVE，分值与严重级由向量本地计算
func upsertCVE(db *sql.DB, item intelItem) (bool, error) {
	repo := sqlite.NewIntelRepo(db)
	ctx := context.Background()
	score, err := BaseScore(item.CvssVector)
	if err != nil {
		score = 0
	}
	published := normalizeAPITime(item.PublishedAt)
	updated := normalizeAPITime(item.UpdatedAt)
	if updated == "" {
		updated = published
	}
	existing, err := repo.CVEExists(ctx, item.CveID)
	if err != nil {
		return false, err
	}
	if err := repo.UpsertCVE(ctx, ports.CVEInput{
		ID:          item.CveID,
		Title:       item.Title,
		Description: item.text(),
		Vector:      item.CvssVector,
		Score:       score,
		Severity:    SeverityOf(score),
		CWEID:       int(item.CweID),
		CWECN:       item.CweCN,
		PublishedAt: published,
		UpdatedAt:   updated,
	}); err != nil {
		return false, err
	}
	insertedAt := fmtT(nowT())
	for _, link := range item.Pocs {
		if link == "" {
			continue
		}
		if _, err := repo.AddPOC(ctx, item.CveID, link, insertedAt); err != nil {
			return false, err
		}
	}
	return !existing, nil
}

// normalizeAPITime 兼容 RFC1123(GMT) 与 RFC3339，统一为东八区 RFC3339
func normalizeAPITime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	layouts := []string{
		time.RFC3339,
		time.RFC1123,
		time.RFC1123Z,
		"Mon, 02 Jan 2006 15:04:05 GMT",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return fmtT(t)
		}
	}
	return ""
}

func cveCursor(db *sql.DB) time.Time {
	if v := getMeta(db, "cve_cursor"); v != "" {
		if t, err := parseT(v); err == nil {
			return t
		}
	}
	var latest string
	if v, err := sqlite.NewIntelRepo(db).LatestCVEUpdate(context.Background()); err == nil {
		latest = v
	}
	if latest != "" {
		if t, err := parseT(latest); err == nil {
			return t
		}
	}
	return time.Time{}
}

func pocCursor(db *sql.DB) time.Time {
	latest, err := sqlite.NewIntelRepo(db).LatestPOCUpdate(context.Background())
	if err == nil && latest != "" {
		if t, err := parseT(latest); err == nil {
			return t
		}
	}
	return time.Time{}
}

// normalizeSyncCounts 让同步计数与库内真实条数一致，避免展示演示期的大数字
func normalizeSyncCounts(db *sql.DB) {
	if err := sqlite.NewSyncRepo(db).NormalizeCounts(context.Background()); err != nil {
		slog.Warn("刷新同步计数失败", "err", err)
	}
}

// markSync 更新同步游标状态，供概览与自检读取
func markSync(db *sql.DB, source, status, errMsg string) {
	if err := sqlite.NewSyncRepo(db).MarkRun(context.Background(), source, status, errMsg, fmtT(nowT())); err != nil {
		slog.Warn("更新同步状态失败", "source", source, "err", err)
	}
}
