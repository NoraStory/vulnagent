package main

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/platform/config"
)

// epssResult EPSS 导入结果
type epssResult struct {
	Mode       string `json:"mode"`
	Rows       int    `json:"rows"`
	Matched    int    `json:"matched"`
	Unmatched  int    `json:"unmatched"`
	Invalid    int    `json:"invalid"`
	Recomputed int    `json:"recomputed"`
	Cursor     string `json:"cursor"`
}

// importEPSS 导入 FIRST 格式的 EPSS CSV（cve,epss,percentile），
// 只更新库内已存在的 CVE，导入后重算全部漏洞的风险分。
func (a *App) importEPSS(reader io.Reader) (epssResult, error) {
	res := epssResult{Mode: "epss-csv"}
	cr := csv.NewReader(reader)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true

	cveIdx, scoreIdx := 0, 1
	headerChecked := false

	tx, err := a.db.Begin()
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`UPDATE cves SET epss = ? WHERE cve_id = ?`)
	if err != nil {
		return res, err
	}
	defer stmt.Close()

	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("解析 CSV 失败: %w", err)
		}
		if len(record) < 2 {
			res.Invalid++
			continue
		}
		if !headerChecked {
			headerChecked = true
			if strings.EqualFold(strings.TrimSpace(record[0]), "cve") {
				for i, col := range record {
					switch strings.ToLower(strings.TrimSpace(col)) {
					case "cve":
						cveIdx = i
					case "epss":
						scoreIdx = i
					}
				}
				continue
			}
		}
		res.Rows++
		if res.Rows > 5_000_000 {
			return res, fmt.Errorf("CSV 行数超过 500 万限制")
		}
		if cveIdx >= len(record) || scoreIdx >= len(record) {
			res.Invalid++
			continue
		}
		cveID := strings.TrimSpace(record[cveIdx])
		score, parseErr := strconv.ParseFloat(strings.TrimSpace(record[scoreIdx]), 64)
		if cveID == "" || parseErr != nil || score < 0 || score > 1 {
			res.Invalid++
			continue
		}
		result, execErr := stmt.Exec(score, cveID)
		if execErr != nil {
			return res, execErr
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			res.Matched++
		} else {
			res.Unmatched++
		}
	}
	if res.Rows == 0 {
		return res, fmt.Errorf("CSV 中没有有效数据")
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}

	// 把最新 EPSS 同步到漏洞快照，再按当前策略重算风险分
	if err := a.findingRepo().SyncEPSSSnapshot(context.Background()); err != nil {
		return res, fmt.Errorf("同步漏洞 EPSS 快照失败: %w", err)
	}
	recomputed, err := a.recomputeFindings(loadPolicy(a.db))
	if err != nil {
		return res, fmt.Errorf("重算风险分失败: %w", err)
	}
	res.Recomputed = recomputed
	res.Cursor = fmtT(nowT())

	// 同步状态：count 表示已有 EPSS 数据的 CVE 数
	if err := a.syncRepo().MarkEPSS(context.Background(), res.Cursor); err != nil {
		slog.Warn("更新 EPSS 同步状态失败", "err", err)
	}
	slog.Info("EPSS 导入完成", "rows", res.Rows, "matched", res.Matched,
		"unmatched", res.Unmatched, "recomputed", res.Recomputed)
	return res, nil
}

// handleEPSSUpload 接收原始 CSV 上传（admin），导入后自动重算风险分
func (a *App) handleEPSSUpload(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	res, err := a.importEPSS(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		a.audit(r, "sync.epss", "epss", "导入失败："+err.Error())
		writeErr(w, http.StatusBadRequest, "epss_import_failed", err.Error())
		return
	}
	a.audit(r, "sync.epss", "epss",
		fmt.Sprintf("EPSS 导入：命中 %d 条，未命中 %d 条，重算 %d 条",
			res.Matched, res.Unmatched, res.Recomputed))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"mode":       res.Mode,
		"rows":       res.Rows,
		"matched":    res.Matched,
		"unmatched":  res.Unmatched,
		"invalid":    res.Invalid,
		"recomputed": res.Recomputed,
		"cursor":     res.Cursor,
	})
}

// epssURLFromEnv EPSS 数据源，配置见 internal/platform/config
func epssURLFromEnv() string { return config.Load().EPSSURL }

// syncEPSSFromRemote 从 FIRST 拉取 EPSS 全量数据并导入
func (a *App) syncEPSSFromRemote(ctx context.Context) (epssResult, error) {
	res := epssResult{Mode: "epss-remote"}
	target := epssURLFromEnv()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "vulnagent/"+appVersion)
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		markSync(a.db, "epss", "fail", err.Error())
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("EPSS 源返回 HTTP %d", resp.StatusCode)
		markSync(a.db, "epss", "fail", msg)
		return res, fmt.Errorf("%s", msg)
	}

	var reader io.Reader = io.LimitReader(resp.Body, 1<<30)
	if strings.HasSuffix(strings.ToLower(target), ".gz") || resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			markSync(a.db, "epss", "fail", err.Error())
			return res, fmt.Errorf("解压 EPSS 数据失败: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	res, err = a.importEPSS(reader)
	if err != nil {
		markSync(a.db, "epss", "fail", err.Error())
		return res, err
	}
	res.Mode = "epss-remote"
	return res, nil
}

// handleEPSSRefresh 从 FIRST 在线刷新 EPSS（admin）
func (a *App) handleEPSSRefresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := a.syncEPSSFromRemote(ctx)
	if err != nil {
		a.audit(r, "sync.epss", "epss", "在线拉取失败："+err.Error())
		writeErr(w, http.StatusBadGateway, "epss_fetch_failed", err.Error())
		return
	}
	a.audit(r, "sync.epss", "epss",
		fmt.Sprintf("在线刷新：命中 %d 条，重算 %d 条", res.Matched, res.Recomputed))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"mode":       res.Mode,
		"rows":       res.Rows,
		"matched":    res.Matched,
		"unmatched":  res.Unmatched,
		"invalid":    res.Invalid,
		"recomputed": res.Recomputed,
		"cursor":     res.Cursor,
	})
}
