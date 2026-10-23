package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// 支持的事件类型
var notifyEventCatalog = []string{"finding.new", "ticket.created", "sync.failed", "selfcheck.failed"}

type notifyConfig struct {
	URL        string   `json:"url"`
	Secret     string   `json:"secret"`
	Events     []string `json:"events"`
	LastEvent  string   `json:"lastEvent"`
	LastStatus string   `json:"lastStatus"`
	LastError  string   `json:"lastError"`
	LastSentAt string   `json:"lastSentAt"`
}

func (a *App) loadNotifyConfig() notifyConfig {
	s, _ := a.notifyRepo().Get(context.Background())
	return notifyConfig{
		URL:        s.URL,
		Secret:     s.Secret,
		Events:     s.Events,
		LastEvent:  s.LastEvent,
		LastStatus: s.LastStatus,
		LastError:  s.LastError,
		LastSentAt: s.LastSentAt,
	}
}

// dispatch 异步推送事件，未配置或未订阅时直接跳过
func (a *App) dispatch(event string, data map[string]any) {
	cfg := a.loadNotifyConfig()
	if strings.TrimSpace(cfg.URL) == "" || !containsString(cfg.Events, event) {
		return
	}
	go a.sendWebhook(cfg, event, data)
}

func (a *App) sendWebhook(cfg notifyConfig, event string, data map[string]any) {
	payload, err := json.Marshal(map[string]any{
		"event":  event,
		"sentAt": fmtT(nowT()),
		"data":   data,
	})
	if err != nil {
		return
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if lastErr = postWebhook(cfg, event, payload); lastErr == nil {
			a.markNotify(event, "ok", "")
			return
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}
	}
	a.markNotify(event, "error", lastErr.Error())
	slog.Warn("Webhook 推送失败", "event", event, "err", lastErr)
}

func postWebhook(cfg notifyConfig, event string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vulnagent/"+appVersion)
	req.Header.Set("X-VulnAgent-Event", event)
	if cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(payload)
		req.Header.Set("X-VulnAgent-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *App) markNotify(event, status, errMsg string) {
	if err := a.notifyRepo().MarkResult(context.Background(), event, status, errMsg, fmtT(nowT())); err != nil {
		slog.Warn("记录 Webhook 状态失败", "err", err)
	}
}

func validEvents(events []string) bool {
	for _, e := range events {
		if !containsString(notifyEventCatalog, e) {
			return false
		}
	}
	return true
}

// ---------- 通知设置接口（admin） ----------

func (a *App) handleNotifyGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	cfg := a.loadNotifyConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        cfg.URL,
		"secretSet":  cfg.Secret != "",
		"events":     cfg.Events,
		"catalog":    notifyEventCatalog,
		"lastEvent":  cfg.LastEvent,
		"lastStatus": cfg.LastStatus,
		"lastError":  cfg.LastError,
		"lastSentAt": cfg.LastSentAt,
	})
}

func (a *App) handleNotifyUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req struct {
		URL         string   `json:"url"`
		Secret      string   `json:"secret"`
		ClearSecret bool     `json:"clearSecret"`
		Events      []string `json:"events"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "Webhook 地址必须是合法的 http(s) URL")
			return
		}
	}
	if !validEvents(req.Events) {
		writeErr(w, http.StatusBadRequest, "bad_request", "包含不支持的事件类型")
		return
	}
	cur := a.loadNotifyConfig()
	secret := cur.Secret
	if req.ClearSecret {
		secret = ""
	} else if req.Secret != "" {
		secret = req.Secret
	}
	if err := a.notifyRepo().Save(r.Context(), ports.NotifySettings{
		URL:    req.URL,
		Secret: secret,
		Events: req.Events,
	}, fmtT(nowT())); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存通知设置失败")
		return
	}
	a.audit(r, "notify.update", req.URL, fmt.Sprintf("订阅事件：%s", strings.Join(req.Events, ",")))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	cfg := a.loadNotifyConfig()
	if strings.TrimSpace(cfg.URL) == "" {
		writeErr(w, http.StatusBadRequest, "not_configured", "请先配置 Webhook 地址")
		return
	}
	data := map[string]any{
		"message": "VulnAgent 通知测试",
		"actor":   "控制面",
	}
	payload, _ := json.Marshal(map[string]any{"event": "notify.test", "sentAt": fmtT(nowT()), "data": data})
	start := time.Now()
	if err := postWebhook(cfg, "notify.test", payload); err != nil {
		a.markNotify("notify.test", "error", err.Error())
		writeErr(w, http.StatusBadGateway, "webhook_failed", "测试推送失败："+err.Error())
		return
	}
	a.markNotify("notify.test", "ok", "")
	a.audit(r, "notify.test", cfg.URL, "测试推送成功")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "elapsedMs": time.Since(start).Milliseconds()})
}
