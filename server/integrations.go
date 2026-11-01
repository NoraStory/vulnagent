package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/cloud"
)

// ---------- 数据结构 ----------

type integrationRequest struct {
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	Config          map[string]any    `json:"config"`
	Credentials     map[string]string `json:"credentials"`
	Enabled         *bool             `json:"enabled"`
	IntervalMinutes int               `json:"intervalMinutes"`
	ClearSecret     bool              `json:"clearSecret"`
}

type integrationSyncStats struct {
	SourceID   int64    `json:"sourceId"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Fetched    int      `json:"fetched"`
	Created    int      `json:"created"`
	Updated    int      `json:"updated"`
	Unchanged  int      `json:"unchanged"`
	Failed     int      `json:"failed"`
	Errors     []string `json:"errors,omitempty"`
	FinishedAt string   `json:"finishedAt"`
}

func decodeIntegrationConfig(raw string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func integrationConfigString(cfg map[string]any, key string) string {
	value, ok := cfg[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func toIntegrationItem(src ports.IntegrationSource) map[string]any {
	return map[string]any{
		"id":              src.ID,
		"kind":            src.Kind,
		"name":            src.Name,
		"config":          decodeIntegrationConfig(src.Config),
		"hasCredential":   src.Secret != "",
		"enabled":         src.Enabled,
		"intervalMinutes": src.IntervalMinutes,
		"lastRunAt":       src.LastRunAt,
		"lastStatus":      src.LastStatus,
		"lastError":       src.LastError,
		"lastCount":       src.LastCount,
		"createdAt":       src.CreatedAt,
		"updatedAt":       src.UpdatedAt,
	}
}

func validateIntegration(kind string, config map[string]any, credentials map[string]string, hasStoredSecret bool) error {
	if _, err := cloud.New(kind); err != nil {
		return err
	}
	requireKey := func(key string, label string) error {
		if strings.TrimSpace(credentials[key]) != "" || (len(credentials) == 0 && hasStoredSecret) {
			return nil
		}
		return fmt.Errorf("缺少凭据：%s", label)
	}
	switch kind {
	case string(cloud.KindAliyun):
		if integrationConfigString(config, "region") == "" {
			return fmt.Errorf("阿里云同步需要填写 region")
		}
		if err := requireKey("accessKeyId", "accessKeyId"); err != nil {
			return err
		}
		return requireKey("accessKeySecret", "accessKeySecret")
	case string(cloud.KindAWS):
		if integrationConfigString(config, "region") == "" {
			return fmt.Errorf("AWS 同步需要填写 region")
		}
		if err := requireKey("accessKeyId", "accessKeyId"); err != nil {
			return err
		}
		return requireKey("secretAccessKey", "secretAccessKey")
	case string(cloud.KindAzure):
		if integrationConfigString(config, "subscriptionId") == "" {
			return fmt.Errorf("Azure 同步需要填写 subscriptionId")
		}
		for _, key := range []string{"tenantId", "clientId", "clientSecret"} {
			if err := requireKey(key, key); err != nil {
				return err
			}
		}
		return nil
	case string(cloud.KindCMDB):
		if integrationConfigString(config, "url") == "" {
			return fmt.Errorf("外部 CMDB 同步需要填写 URL")
		}
		switch strings.ToLower(integrationConfigString(config, "authType")) {
		case "", "none":
			return nil
		case "bearer":
			return requireKey("token", "token")
		case "basic":
			if err := requireKey("username", "username"); err != nil {
				return err
			}
			return requireKey("password", "password")
		default:
			return fmt.Errorf("认证方式仅支持 none / bearer / basic")
		}
	}
	return nil
}

// ---------- 接口 ----------

// handleIntegrations 列出或创建集成源（admin）
func (a *App) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	if r.Method == http.MethodGet {
		list, err := a.integrationRepo().List(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "查询集成源失败")
			return
		}
		items := make([]map[string]any, 0, len(list))
		for _, src := range list {
			items = append(items, toIntegrationItem(src))
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "kinds": cloud.Kinds()})
		return
	}

	var req integrationRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	kind := strings.TrimSpace(req.Kind)
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "名称不能为空且不超过 128 字")
		return
	}
	if req.Config == nil {
		req.Config = map[string]any{}
	}
	if err := validateIntegration(kind, req.Config, req.Credentials, false); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	configJSON, _ := json.Marshal(req.Config)
	secret := ""
	if len(req.Credentials) > 0 {
		raw, _ := json.Marshal(req.Credentials)
		sealed, err := a.sealSSHSecret(string(raw))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "加密凭据失败")
			return
		}
		secret = sealed
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	interval := clampInterval(req.IntervalMinutes)
	now := fmtT(nowT())
	src := ports.IntegrationSource{
		Kind: kind, Name: name, Config: string(configJSON), Secret: secret,
		Enabled: enabled, IntervalMinutes: interval, CreatedAt: now, UpdatedAt: now,
	}
	id, err := a.integrationRepo().Create(r.Context(), src)
	if err != nil {
		if isUniqueConstraint(err) {
			writeErr(w, http.StatusConflict, "conflict", "同类型下已存在同名集成源")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建集成源失败")
		return
	}
	a.audit(r, "integration.create", fmt.Sprintf("integration:%d", id),
		fmt.Sprintf("%s · %s · 间隔 %d 分钟", kind, name, interval))
	created, _ := a.integrationRepo().Get(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": toIntegrationItem(created)})
}

// handleIntegrationUpdate 更新或删除集成源（admin）
func (a *App) handleIntegrationUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的集成 ID")
		return
	}
	src, err := a.integrationRepo().Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "集成源不存在")
		return
	}
	if r.Method == http.MethodDelete {
		if err := a.integrationRepo().Delete(r.Context(), id); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "删除集成源失败")
			return
		}
		a.audit(r, "integration.delete", fmt.Sprintf("integration:%d", id), src.Kind+" · "+src.Name)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	var req integrationRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		src.Name = name
	}
	config := decodeIntegrationConfig(src.Config)
	if req.Config != nil {
		config = req.Config
	}
	if err := validateIntegration(src.Kind, config, req.Credentials, src.Secret != ""); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	configJSON, _ := json.Marshal(config)
	src.Config = string(configJSON)
	switch {
	case req.ClearSecret:
		src.Secret = ""
	case len(req.Credentials) > 0:
		raw, _ := json.Marshal(req.Credentials)
		sealed, err := a.sealSSHSecret(string(raw))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "加密凭据失败")
			return
		}
		src.Secret = sealed
	}
	if req.Enabled != nil {
		src.Enabled = *req.Enabled
	}
	if req.IntervalMinutes > 0 {
		src.IntervalMinutes = clampInterval(req.IntervalMinutes)
	}
	src.UpdatedAt = fmtT(nowT())
	if err := a.integrationRepo().Update(r.Context(), src); err != nil {
		if isUniqueConstraint(err) {
			writeErr(w, http.StatusConflict, "conflict", "同类型下已存在同名集成源")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新集成源失败")
		return
	}
	a.audit(r, "integration.update", fmt.Sprintf("integration:%d", id),
		fmt.Sprintf("%s · %s · enabled=%v", src.Kind, src.Name, src.Enabled))
	updated, _ := a.integrationRepo().Get(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": toIntegrationItem(updated)})
}

// handleIntegrationTest 只读拉取并返回样例，不写入资产（admin）
func (a *App) handleIntegrationTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的集成 ID")
		return
	}
	src, err := a.integrationRepo().Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "集成源不存在")
		return
	}
	provider, cfg, err := a.integrationRuntime(src)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	instances, err := provider.List(ctx, cfg)
	if err != nil {
		a.audit(r, "integration.test", fmt.Sprintf("integration:%d", id), "失败："+err.Error())
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "error": err.Error(), "elapsedMs": time.Since(start).Milliseconds(),
		})
		return
	}
	sample := make([]map[string]any, 0, 8)
	for index, inst := range instances {
		if index >= 8 {
			break
		}
		sample = append(sample, map[string]any{
			"instanceId": inst.InstanceID, "name": inst.Name, "hostname": inst.Hostname,
			"privateIp": inst.PrivateIP, "publicIp": inst.PublicIP, "osFamily": inst.OSFamily,
			"region": inst.Region, "status": inst.Status,
		})
	}
	a.audit(r, "integration.test", fmt.Sprintf("integration:%d", id), fmt.Sprintf("拉取 %d 台", len(instances)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "count": len(instances), "sample": sample,
		"elapsedMs": time.Since(start).Milliseconds(),
	})
}

// handleIntegrationSync 手动同步一次并写入资产台账（admin）
func (a *App) handleIntegrationSync(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的集成 ID")
		return
	}
	src, err := a.integrationRepo().Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "集成源不存在")
		return
	}
	if !a.beginIntegrationSync(id) {
		writeErr(w, http.StatusConflict, "already_running", "该集成源正在同步，请稍后再试")
		return
	}
	defer a.endIntegrationSync(id)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stats, err := a.syncIntegration(ctx, src, u.Name)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stats": stats, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": stats.Failed == 0, "stats": stats})
}

// ---------- 同步执行 ----------

func clampInterval(minutes int) int {
	if minutes <= 0 {
		return 360
	}
	if minutes < 5 {
		return 5
	}
	if minutes > 10080 {
		return 10080
	}
	return minutes
}

func (a *App) integrationRuntime(src ports.IntegrationSource) (cloud.Provider, cloud.Config, error) {
	provider, err := cloud.New(src.Kind)
	if err != nil {
		return nil, cloud.Config{}, err
	}
	cfg := cloud.Config{Credentials: map[string]string{}}
	raw := decodeIntegrationConfig(src.Config)
	cfg.Region = integrationConfigString(raw, "region")
	cfg.Endpoint = integrationConfigString(raw, "endpoint")
	cfg.URL = integrationConfigString(raw, "url")
	cfg.AuthType = integrationConfigString(raw, "authType")
	cfg.SubscriptionID = integrationConfigString(raw, "subscriptionId")
	if src.Secret != "" {
		plain, err := a.openSSHSecret(src.Secret)
		if err != nil {
			return nil, cfg, fmt.Errorf("解密凭据失败：%w", err)
		}
		var credentials map[string]string
		if err := json.Unmarshal([]byte(plain), &credentials); err != nil {
			return nil, cfg, fmt.Errorf("凭据格式错误：%w", err)
		}
		cfg.Credentials = credentials
	}
	return provider, cfg, nil
}

func (a *App) beginIntegrationSync(id int64) bool {
	a.integrationMu.Lock()
	defer a.integrationMu.Unlock()
	if a.integrationSyncing == nil {
		a.integrationSyncing = map[int64]bool{}
	}
	if a.integrationSyncing[id] {
		return false
	}
	a.integrationSyncing[id] = true
	return true
}

func (a *App) endIntegrationSync(id int64) {
	a.integrationMu.Lock()
	delete(a.integrationSyncing, id)
	a.integrationMu.Unlock()
}

// syncIntegration 拉取并写入资产；fetch 失败时记录状态与告警
func (a *App) syncIntegration(ctx context.Context, src ports.IntegrationSource, actor string) (integrationSyncStats, error) {
	stats := integrationSyncStats{SourceID: src.ID, Kind: src.Kind, Name: src.Name}
	provider, cfg, err := a.integrationRuntime(src)
	if err != nil {
		a.recordIntegrationFailure(src, actor, err)
		return stats, err
	}
	instances, err := provider.List(ctx, cfg)
	if err != nil {
		a.recordIntegrationFailure(src, actor, err)
		return stats, err
	}
	stats.Fetched = len(instances)
	for _, inst := range instances {
		action, err := a.upsertIntegrationAsset(ctx, src, inst)
		if err != nil {
			stats.Failed++
			if len(stats.Errors) < 20 {
				stats.Errors = append(stats.Errors, fmt.Sprintf("%s：%v", integrationInstanceLabel(inst), err))
			}
			continue
		}
		switch action {
		case "created":
			stats.Created++
		case "updated":
			stats.Updated++
		default:
			stats.Unchanged++
		}
	}
	stats.FinishedAt = fmtT(nowT())
	status := "ok"
	errText := ""
	if stats.Failed > 0 {
		status = "partial"
		errText = fmt.Sprintf("%d 台处理失败", stats.Failed)
	}
	_ = a.integrationRepo().MarkRun(context.Background(), src.ID, status, stats.Fetched, errText, stats.FinishedAt)
	a.auditAs(actor, "system", "127.0.0.1", "", "integration.sync", fmt.Sprintf("integration:%d", src.ID),
		fmt.Sprintf("%s · %s：拉取 %d，新增 %d，更新 %d，未变 %d，失败 %d",
			src.Kind, src.Name, stats.Fetched, stats.Created, stats.Updated, stats.Unchanged, stats.Failed))
	if stats.Failed > 0 {
		a.dispatch("integration.sync_failed", map[string]any{
			"sourceId": src.ID, "kind": src.Kind, "name": src.Name,
			"failed": stats.Failed, "errors": stats.Errors,
		})
	}
	return stats, nil
}

func (a *App) recordIntegrationFailure(src ports.IntegrationSource, actor string, err error) {
	now := fmtT(nowT())
	_ = a.integrationRepo().MarkRun(context.Background(), src.ID, "failed", 0, err.Error(), now)
	a.auditAs(actor, "system", "127.0.0.1", "", "integration.sync", fmt.Sprintf("integration:%d", src.ID),
		src.Kind+" · "+src.Name+" 失败："+err.Error())
	a.dispatch("integration.sync_failed", map[string]any{
		"sourceId": src.ID, "kind": src.Kind, "name": src.Name, "error": err.Error(),
	})
}

func integrationInstanceLabel(inst cloud.Instance) string {
	for _, value := range []string{inst.Hostname, inst.Name, inst.InstanceID, inst.PrivateIP, inst.PublicIP} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "未知实例"
}

// upsertIntegrationAsset 按云实例 ID / 序列号 / MAC / 主机名 / IP 解析身份并写入资产
func (a *App) upsertIntegrationAsset(ctx context.Context, src ports.IntegrationSource, inst cloud.Instance) (string, error) {
	hostname := firstNonEmptyText(inst.Hostname, inst.Name)
	ip := firstNonEmptyText(inst.PrivateIP, inst.PublicIP)

	matches, err := a.findIntegrationMatches(ctx, inst, hostname, ip)
	if err != nil {
		return "", err
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("同时命中多个资产，请先人工合并")
	}

	providerName := integrationProviderName(src.Kind)
	if len(matches) == 1 {
		var assetID int64
		for id := range matches {
			assetID = id
		}
		updates := map[string]string{}
		set := func(key, value string) {
			if strings.TrimSpace(value) != "" {
				updates[key] = value
			}
		}
		set("ip", ip)
		set("osFamily", inst.OSFamily)
		set("osVersion", inst.OSVersion)
		set("serial", inst.Serial)
		set("mac", inst.MAC)
		set("cloudProvider", providerName)
		set("cloudAccount", src.Name)
		set("region", inst.Region)
		set("instanceId", inst.InstanceID)
		set("businessSystem", inst.BusinessSystem)
		set("department", inst.Department)
		set("owner", inst.Owner)
		set("ownerEmail", inst.OwnerEmail)
		set("location", inst.Location)
		changes, err := a.assetRepo().UpdateFields(ctx, assetID, updates, "云同步", "cloud")
		if err != nil {
			return "", err
		}
		if err := a.linkCloudIdentifiers(ctx, assetID, inst, hostname, ip); err != nil {
			return "", err
		}
		if len(changes) > 0 {
			return "updated", nil
		}
		return "unchanged", nil
	}

	if hostname == "" {
		hostname = firstNonEmptyText(inst.InstanceID, ip)
	}
	if hostname == "" {
		return "", fmt.Errorf("实例缺少主机名与 IP，无法建档")
	}
	if existing, found, err := a.assetRepo().FindByHostname(ctx, hostname); err == nil && found {
		suffix := firstNonEmptyText(inst.InstanceID, strings.ReplaceAll(ip, ".", "-"))
		if suffix == "" {
			suffix = strconv.FormatInt(nowT().UnixNano(), 36)
		}
		hostname = hostname + "-" + suffix
		_ = existing
	}
	fields := map[string]string{
		"hostname":       hostname,
		"ip":             ip,
		"osFamily":       inst.OSFamily,
		"osVersion":      inst.OSVersion,
		"serial":         inst.Serial,
		"mac":            inst.MAC,
		"cloudProvider":  providerName,
		"cloudAccount":   src.Name,
		"region":         inst.Region,
		"instanceId":     inst.InstanceID,
		"businessSystem": inst.BusinessSystem,
		"department":     inst.Department,
		"owner":          inst.Owner,
		"ownerEmail":     inst.OwnerEmail,
		"location":       inst.Location,
	}
	for _, pair := range []struct{ tag, field string }{
		{"env", "env"}, {"tier", "tier"}, {"exposure", "exposure"},
	} {
		if value := strings.TrimSpace(inst.Tags[pair.tag]); value != "" {
			fields[pair.field] = value
		}
	}
	identifiers := map[string]string{}
	if inst.InstanceID != "" {
		identifiers["cloud_instance"] = inst.InstanceID
	}
	if inst.Serial != "" {
		identifiers["serial"] = inst.Serial
	}
	if inst.MAC != "" {
		identifiers["mac"] = inst.MAC
	}
	identifiers["hostname"] = hostname
	if ip != "" {
		identifiers["ip"] = ip
	}
	assetID, err := a.assetRepo().Create(ctx, fields, cloudTagList(inst.Tags), identifiers, "cloud")
	if err != nil {
		return "", err
	}
	a.dispatch("asset.created", map[string]any{
		"assetId": assetID, "hostname": hostname, "ip": ip,
		"source": "cloud", "provider": providerName, "account": src.Name,
	})
	return "created", nil
}

func (a *App) findIntegrationMatches(ctx context.Context, inst cloud.Instance, hostname, ip string) (map[int64]bool, error) {
	matches := map[int64]bool{}
	find := func(kind, value string) error {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		id, ok, err := a.assetRepo().FindByIdentity(ctx, kind, value)
		if err != nil {
			return err
		}
		if ok {
			matches[id] = true
		}
		return nil
	}
	if err := find("cloud_instance", inst.InstanceID); err != nil {
		return nil, err
	}
	if err := find("serial", inst.Serial); err != nil {
		return nil, err
	}
	if err := find("mac", inst.MAC); err != nil {
		return nil, err
	}
	if err := find("hostname", hostname); err != nil {
		return nil, err
	}
	if err := find("ip", ip); err != nil {
		return nil, err
	}
	return matches, nil
}

func (a *App) linkCloudIdentifiers(ctx context.Context, assetID int64, inst cloud.Instance, hostname, ip string) error {
	for kind, value := range map[string]string{
		"cloud_instance": inst.InstanceID,
		"serial":         inst.Serial,
		"mac":            inst.MAC,
		"hostname":       hostname,
		"ip":             ip,
	} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := a.assetRepo().AddIdentifiers(ctx, assetID, kind, "cloud", []string{value}); err != nil {
			return err
		}
	}
	return nil
}

func integrationProviderName(kind string) string {
	switch kind {
	case string(cloud.KindAliyun):
		return "aliyun"
	case string(cloud.KindAWS):
		return "aws"
	case string(cloud.KindAzure):
		return "azure"
	}
	return "cmdb"
}

func cloudTagList(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for index, key := range keys {
		if index >= 20 {
			break
		}
		out = append(out, key+"="+tags[key])
	}
	return out
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// ---------- 定时调度 ----------

// integrationLoop 每 5 分钟检查一次到期集成源
func (a *App) integrationLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	a.runDueIntegrations(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runDueIntegrations(ctx)
		}
	}
}

func (a *App) runDueIntegrations(ctx context.Context) {
	sources, err := a.integrationRepo().List(ctx)
	if err != nil {
		slog.Warn("读取集成源失败", "err", err)
		return
	}
	now := nowT()
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		interval := clampInterval(src.IntervalMinutes)
		if src.LastRunAt != "" {
			if last, err := parseT(src.LastRunAt); err == nil && now.Sub(last) < time.Duration(interval)*time.Minute {
				continue
			}
		}
		if !a.beginIntegrationSync(src.ID) {
			continue
		}
		go func(source ports.IntegrationSource) {
			defer a.endIntegrationSync(source.ID)
			runCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			stats, err := a.syncIntegration(runCtx, source, "系统")
			if err != nil {
				slog.Warn("定时集成同步失败", "source", source.Name, "kind", source.Kind, "err", err)
				return
			}
			slog.Info("定时集成同步完成", "source", source.Name, "kind", source.Kind,
				"created", stats.Created, "updated", stats.Updated, "failed", stats.Failed)
		}(src)
	}
}
