package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// ---------- 资产档案编辑 ----------

// assetPatchRequest 资产档案更新请求，nil 表示不修改该字段
type assetPatchRequest struct {
	Hostname       *string   `json:"hostname"`
	IP             *string   `json:"ip"`
	OSFamily       *string   `json:"osFamily"`
	OSVersion      *string   `json:"osVersion"`
	OSArch         *string   `json:"osArch"`
	Kernel         *string   `json:"kernel"`
	Env            *string   `json:"env"`
	Exposure       *string   `json:"exposure"`
	Tier           *string   `json:"tier"`
	AssetType      *string   `json:"assetType"`
	Status         *string   `json:"status"`
	Owner          *string   `json:"owner"`
	OwnerEmail     *string   `json:"ownerEmail"`
	Department     *string   `json:"department"`
	BusinessSystem *string   `json:"businessSystem"`
	Location       *string   `json:"location"`
	CloudProvider  *string   `json:"cloudProvider"`
	CloudAccount   *string   `json:"cloudAccount"`
	Region         *string   `json:"region"`
	InstanceID     *string   `json:"instanceId"`
	MAC            *string   `json:"mac"`
	Serial         *string   `json:"serial"`
	Virtualized    *string   `json:"virtualized"`
	Tags           *[]string `json:"tags"`
}

func (p assetPatchRequest) toMap() map[string]string {
	out := map[string]string{}
	add := func(key string, value *string) {
		if value != nil {
			out[key] = truncateField(strings.TrimSpace(*value), 512)
		}
	}
	add("hostname", p.Hostname)
	add("ip", p.IP)
	add("osFamily", p.OSFamily)
	add("osVersion", p.OSVersion)
	add("osArch", p.OSArch)
	add("kernel", p.Kernel)
	add("env", p.Env)
	add("exposure", p.Exposure)
	add("tier", p.Tier)
	add("assetType", p.AssetType)
	add("status", p.Status)
	add("owner", p.Owner)
	add("ownerEmail", p.OwnerEmail)
	add("department", p.Department)
	add("businessSystem", p.BusinessSystem)
	add("location", p.Location)
	add("cloudProvider", p.CloudProvider)
	add("cloudAccount", p.CloudAccount)
	add("region", p.Region)
	add("instanceId", p.InstanceID)
	add("mac", p.MAC)
	add("serial", p.Serial)
	add("virtualized", p.Virtualized)
	return out
}

func truncateField(value string, max int) string {
	if len([]rune(value)) <= max {
		return value
	}
	return string([]rune(value)[:max])
}

// handleAssetPatch 更新资产档案字段并写入变更历史
func (a *App) handleAssetPatch(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	var req assetPatchRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	updates := req.toMap()
	if hostname, exists := updates["hostname"]; exists && hostname == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机名不能为空")
		return
	}
	changes, err := a.assetRepo().UpdateFields(r.Context(), id, updates, u.Name, "manual")
	if err != nil {
		if isUniqueConstraint(err) {
			writeErr(w, http.StatusConflict, "conflict", "主机名已被其他资产占用")
			return
		}
		if err == ports.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新资产失败")
		return
	}
	if req.Tags != nil {
		if err := a.assetRepo().SetTags(r.Context(), id, *req.Tags, u.Name, "manual"); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "更新资产标签失败")
			return
		}
	}
	if len(changes) > 0 {
		a.audit(r, "asset.update", fmt.Sprintf("asset:%d", id),
			fmt.Sprintf("更新 %d 个字段：%s", len(changes), changeSummary(changes)))
	}
	detail, err := a.assetRepo().Detail(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取资产失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"asset":   toAssetItem(detail),
		"changes": changes,
	})
}

func changeSummary(changes []ports.AssetChange) string {
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		parts = append(parts, c.Field)
	}
	return strings.Join(parts, ",")
}

// handleAssetTags 整体替换资产标签
func (a *App) handleAssetTags(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	var req struct {
		Tags []string `json:"tags"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if err := a.assetRepo().SetTags(r.Context(), id, req.Tags, u.Name, "manual"); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新资产标签失败")
		return
	}
	tags, err := a.assetRepo().Tags(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取资产标签失败")
		return
	}
	a.audit(r, "asset.tags", fmt.Sprintf("asset:%d", id), "设置标签："+strings.Join(tags, ","))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tags": tags})
}

// handleAssetChanges 返回资产变更历史
func (a *App) handleAssetChanges(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	changes, err := a.assetRepo().Changes(r.Context(), id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产变更失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": changes})
}

// handleAssetMerge 把重复资产合并到目标资产（仅管理员）
func (a *App) handleAssetMerge(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req struct {
		SourceID int64 `json:"sourceId"`
		TargetID int64 `json:"targetId"`
	}
	if err := readJSON(r, &req); err != nil || req.SourceID <= 0 || req.TargetID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "请提供有效的 sourceId 与 targetId")
		return
	}
	stats, err := a.assetRepo().Merge(r.Context(), req.SourceID, req.TargetID, actorName(r))
	if err != nil {
		if err == ports.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
			return
		}
		writeErr(w, http.StatusBadRequest, "merge_failed", err.Error())
		return
	}
	a.audit(r, "asset.merge", fmt.Sprintf("asset:%d→%d", req.SourceID, req.TargetID),
		fmt.Sprintf("组件 %d、漏洞 %d、工单 %d、标识 %d、标签 %d", stats.Components, stats.Findings,
			stats.Tickets, stats.Identifiers, stats.Tags))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stats": stats})
}

// ---------- CSV 导入导出 ----------

const (
	assetImportRowLimit = 5000
	assetImportMaxBytes = 5 << 20
	assetExportRowLimit = 5000
)

type assetCSVColumn struct {
	key     string
	header  string
	aliases []string
}

var assetCSVColumns = []assetCSVColumn{
	{"hostname", "主机名", []string{"hostname", "主机", "主机名", "名称", "name"}},
	{"ip", "IP", []string{"ip", "ipaddress", "ip地址", "地址"}},
	{"osFamily", "操作系统", []string{"os", "osfamily", "操作系统", "系统"}},
	{"osVersion", "系统版本", []string{"osversion", "系统版本", "版本"}},
	{"osArch", "架构", []string{"osarch", "arch", "架构"}},
	{"kernel", "内核", []string{"kernel", "内核"}},
	{"env", "环境", []string{"env", "environment", "环境"}},
	{"exposure", "暴露面", []string{"exposure", "暴露面"}},
	{"tier", "业务等级", []string{"tier", "业务等级", "重要性"}},
	{"assetType", "资产类型", []string{"assettype", "type", "资产类型", "类型"}},
	{"status", "状态", []string{"status", "状态"}},
	{"owner", "责任人", []string{"owner", "责任人", "负责人"}},
	{"ownerEmail", "责任人邮箱", []string{"owneremail", "email", "邮箱", "责任人邮箱"}},
	{"department", "部门", []string{"department", "部门"}},
	{"businessSystem", "业务系统", []string{"businesssystem", "业务系统", "业务"}},
	{"location", "机房位置", []string{"location", "机房位置", "位置", "机房"}},
	{"cloudProvider", "云厂商", []string{"cloudprovider", "cloud", "云厂商", "云平台"}},
	{"cloudAccount", "云账号", []string{"cloudaccount", "云账号", "云账户"}},
	{"region", "区域", []string{"region", "区域", "地域"}},
	{"instanceId", "实例ID", []string{"instanceid", "实例", "实例id"}},
	{"mac", "MAC", []string{"mac", "mac地址"}},
	{"serial", "序列号", []string{"serial", "sn", "序列号"}},
	{"virtualized", "虚拟化", []string{"virtualized", "虚拟化", "虚拟化类型"}},
	{"tags", "标签", []string{"tags", "tag", "标签"}},
	{"source", "来源", []string{"source", "来源"}},
}

var assetCSVHeaderIndex = buildAssetCSVHeaderIndex()

func buildAssetCSVHeaderIndex() map[string]string {
	index := map[string]string{}
	for _, col := range assetCSVColumns {
		index[normalizeAssetHeader(col.header)] = col.key
		index[normalizeAssetHeader(col.key)] = col.key
		for _, alias := range col.aliases {
			index[normalizeAssetHeader(alias)] = col.key
		}
	}
	return index
}

func normalizeAssetHeader(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	replacer := strings.NewReplacer("\uFEFF", "", " ", "", "_", "", "-", "", "（", "(", "）", ")", "：", "", ":", "")
	return replacer.Replace(value)
}

// handleAssetExport 导出资产档案 CSV（UTF-8 BOM，便于 Excel 打开）
func (a *App) handleAssetExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	list, _, err := a.assetRepo().List(r.Context(), assetFilterFromQuery(r), assetExportRowLimit, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "导出失败")
		return
	}
	name := "vulnagent-assets-" + nowT().Format("20060102-1504") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})

	cw := csv.NewWriter(w)
	header := make([]string, 0, len(assetCSVColumns))
	for _, col := range assetCSVColumns {
		header = append(header, col.header)
	}
	_ = cw.Write(header)
	for _, it := range list {
		row := make([]string, 0, len(assetCSVColumns))
		for _, col := range assetCSVColumns {
			row = append(row, assetCSVValue(it, col.key))
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	a.audit(r, "asset.export_csv", "assets.csv", fmt.Sprintf("导出 %d 台资产", len(list)))
}

func assetCSVValue(it ports.AssetListItem, key string) string {
	switch key {
	case "hostname":
		return it.Hostname
	case "ip":
		return it.IP
	case "osFamily":
		return it.OSFamily
	case "osVersion":
		return it.OSVersion
	case "osArch":
		return it.OSArch
	case "kernel":
		return it.Kernel
	case "env":
		return it.Env
	case "exposure":
		return it.Exposure
	case "tier":
		return it.Tier
	case "assetType":
		return it.AssetType
	case "status":
		return it.Status
	case "owner":
		return it.Owner
	case "ownerEmail":
		return it.OwnerEmail
	case "department":
		return it.Department
	case "businessSystem":
		return it.BusinessSystem
	case "location":
		return it.Location
	case "cloudProvider":
		return it.CloudProvider
	case "cloudAccount":
		return it.CloudAccount
	case "region":
		return it.Region
	case "instanceId":
		return it.InstanceID
	case "mac":
		return it.MAC
	case "serial":
		return it.Serial
	case "virtualized":
		return it.Virtualized
	case "tags":
		return strings.Join(it.Tags, "|")
	case "source":
		return it.Source
	}
	return ""
}

type assetImportRow struct {
	Row      int      `json:"row"`
	Action   string   `json:"action"`
	AssetID  int64    `json:"assetId,omitempty"`
	Hostname string   `json:"hostname"`
	Message  string   `json:"message,omitempty"`
	Changed  []string `json:"changed,omitempty"`
}

type assetImportReport struct {
	DryRun   bool             `json:"dryRun"`
	Strategy string           `json:"strategy"`
	Total    int              `json:"total"`
	Created  int              `json:"created"`
	Updated  int              `json:"updated"`
	Skipped  int              `json:"skipped"`
	Errors   int              `json:"errors"`
	Items    []assetImportRow `json:"items"`
}

// handleAssetImport 导入资产档案 CSV，支持预览（dryRun）与跳过/更新冲突策略
func (a *App) handleAssetImport(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, assetImportMaxBytes)
	if err := r.ParseMultipartForm(assetImportMaxBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "上传文件过大或表单格式错误（上限 5MB）")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请上传 CSV 文件")
		return
	}
	defer file.Close()

	strategy := strings.ToLower(strings.TrimSpace(r.FormValue("strategy")))
	if strategy != "skip" && strategy != "update" && strategy != "create" {
		strategy = "update"
	}
	dryRun := r.FormValue("dryRun") == "1" || r.FormValue("dryRun") == "true"

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "CSV 解析失败："+err.Error())
		return
	}
	if len(records) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "CSV 内容为空")
		return
	}
	if len(records)-1 > assetImportRowLimit {
		writeErr(w, http.StatusBadRequest, "too_many_rows", fmt.Sprintf("单次最多导入 %d 行", assetImportRowLimit))
		return
	}

	mapping := map[int]string{}
	for index, raw := range records[0] {
		if key, ok := assetCSVHeaderIndex[normalizeAssetHeader(raw)]; ok {
			mapping[index] = key
		}
	}
	if mapping == nil || len(mapping) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "未识别到有效表头，请先导出模板再填写")
		return
	}

	report := assetImportReport{DryRun: dryRun, Strategy: strategy, Items: make([]assetImportRow, 0)}
	for i, record := range records[1:] {
		rowNum := i + 2
		if isBlankRecord(record) {
			continue
		}
		fields := map[string]string{}
		for index, key := range mapping {
			if index < len(record) {
				fields[key] = strings.TrimSpace(record[index])
			}
		}
		report.Total++
		row := a.importAssetRow(r, fields, strategy, dryRun)
		switch row.Action {
		case "created":
			report.Created++
		case "updated":
			report.Updated++
		case "skipped":
			report.Skipped++
		default:
			report.Errors++
		}
		row.Row = rowNum
		report.Items = append(report.Items, row)
	}

	if !dryRun {
		a.audit(r, "asset.import", "assets.csv", fmt.Sprintf(
			"策略 %s：新增 %d、更新 %d、跳过 %d、失败 %d", strategy,
			report.Created, report.Updated, report.Skipped, report.Errors))
	}
	writeJSON(w, http.StatusOK, report)
}

func isBlankRecord(record []string) bool {
	for _, cell := range record {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

// importAssetRow 处理单行导入，返回该行结果
func (a *App) importAssetRow(r *http.Request, fields map[string]string, strategy string, dryRun bool) assetImportRow {
	hostname := fields["hostname"]
	row := assetImportRow{Hostname: hostname}

	matches := map[int64]bool{}
	find := func(kind, value string) {
		if value == "" {
			return
		}
		id, ok, err := a.assetRepo().FindByIdentity(r.Context(), kind, value)
		if err == nil && ok {
			matches[id] = true
		}
	}
	find("cloud_instance", fields["instanceId"])
	find("serial", fields["serial"])
	find("mac", fields["mac"])
	find("hostname", hostname)
	find("ip", fields["ip"])
	if hostname != "" {
		if id, ok, err := a.assetRepo().FindByHostname(r.Context(), hostname); err == nil && ok {
			matches[id] = true
		}
	}

	if len(matches) > 1 {
		row.Action = "error"
		row.Message = "该行同时命中多个资产，请先人工合并重复资产"
		return row
	}

	if len(matches) == 0 {
		if hostname == "" {
			row.Action = "error"
			row.Message = "缺少主机名，无法新建资产"
			return row
		}
		if strategy == "skip" {
			row.Action = "skipped"
			row.Message = "按策略跳过新资产"
			return row
		}
		if dryRun {
			row.Action = "created"
			row.Message = "将新建资产"
			return row
		}
		id, err := a.assetRepo().Create(r.Context(), fields, splitAssetTags(fields["tags"]), importIdentifiers(fields))
		if err != nil {
			row.Action = "error"
			row.Message = "新建资产失败：" + err.Error()
			return row
		}
		row.Action = "created"
		row.AssetID = id
		row.Message = "已新建资产"
		return row
	}

	var assetID int64
	for id := range matches {
		assetID = id
	}
	row.AssetID = assetID
	if strategy == "create" {
		row.Action = "error"
		row.Message = fmt.Sprintf("主机已存在（资产 #%d），create 策略不允许覆盖", assetID)
		return row
	}
	if strategy == "skip" {
		row.Action = "skipped"
		row.Message = fmt.Sprintf("资产 #%d 已存在，按策略跳过", assetID)
		return row
	}
	if dryRun {
		row.Action = "updated"
		row.Message = fmt.Sprintf("将更新资产 #%d", assetID)
		return row
	}

	updates := map[string]string{}
	for _, key := range []string{"hostname", "ip", "osFamily", "osVersion", "osArch", "kernel", "env", "exposure",
		"tier", "assetType", "status", "owner", "ownerEmail", "department", "businessSystem", "location",
		"cloudProvider", "cloudAccount", "region", "instanceId", "mac", "serial", "virtualized"} {
		if value := fields[key]; value != "" {
			updates[key] = value
		}
	}
	changes, err := a.assetRepo().UpdateFields(r.Context(), assetID, updates, actorName(r), "import")
	if err != nil {
		row.Action = "error"
		row.Message = "更新资产失败：" + err.Error()
		return row
	}
	for kind, value := range importIdentifiers(fields) {
		if err := a.assetRepo().AddIdentifiers(r.Context(), assetID, kind, "import", []string{value}); err != nil {
			row.Action = "error"
			row.Message = "写入标识失败：" + err.Error()
			return row
		}
	}
	if tags := splitAssetTags(fields["tags"]); len(tags) > 0 {
		existing, err := a.assetRepo().Tags(r.Context(), assetID)
		if err == nil {
			if err := a.assetRepo().SetTags(r.Context(), assetID, append(existing, tags...), actorName(r), "import"); err != nil {
				row.Action = "error"
				row.Message = "更新标签失败：" + err.Error()
				return row
			}
		}
	}
	if len(changes) == 0 {
		row.Action = "skipped"
		row.Message = "字段无变化"
		return row
	}
	row.Action = "updated"
	row.Changed = make([]string, 0, len(changes))
	for _, c := range changes {
		row.Changed = append(row.Changed, c.Field)
	}
	row.Message = fmt.Sprintf("已更新 %d 个字段", len(changes))
	return row
}

func importIdentifiers(fields map[string]string) map[string]string {
	out := map[string]string{}
	if v := fields["instanceId"]; v != "" {
		out["cloud_instance"] = v
	}
	if v := fields["serial"]; v != "" {
		out["serial"] = v
	}
	if v := fields["mac"]; v != "" {
		out["mac"] = v
	}
	if v := fields["hostname"]; v != "" {
		out["hostname"] = v
	}
	if v := fields["ip"]; v != "" {
		out["ip"] = v
	}
	return out
}

func splitAssetTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '|' || r == ',' || r == ';' || r == '、' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, item := range fields {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// actorName 返回当前操作人名称，无会话时返回「系统」
func actorName(r *http.Request) string {
	if u := userFrom(r); u != nil {
		return u.Name
	}
	return "系统"
}
