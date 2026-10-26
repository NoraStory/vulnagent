package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/asset"
	"vulnagent/server/internal/domain/harness"
)

func newTestDB(t *testing.T) *AssetRepo {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('host-01','public','core','agent')`); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	return NewAssetRepo(db)
}

func TestFindingRepoUpsertAndList(t *testing.T) {
	assets := newTestDB(t)
	db := assets.db
	ctx := context.Background()

	assetID, err := assets.UpsertReported(ctx, "host-02", "10.0.0.2", "linux", "debian12", "agent", "online", "2026-01-01T00:00:00+08:00")
	if err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	if err := assets.ReplaceComponents(ctx, assetID, []asset.Component{
		{PURL: "pkg:npm/lodash@4.17.20", Eco: "npm", Name: "lodash", Version: "4.17.20"},
	}); err != nil {
		t.Fatalf("写入组件失败：%v", err)
	}
	comps, err := assets.Components(ctx, assetID)
	if err != nil || len(comps) != 1 {
		t.Fatalf("读取组件失败：%v len=%d", err, len(comps))
	}

	if _, err := db.Exec(`INSERT INTO cves(cve_id, title, cvss_score, epss, exploit_state, fixed_version)
		VALUES('CVE-2026-1000','测试漏洞',9.8,0.9,'kev','4.17.21')`); err != nil {
		t.Fatalf("写入 CVE 失败：%v", err)
	}

	repo := NewFindingRepo(db)
	in := ports.MatchInput{
		AssetID:      assetID,
		Component:    comps[0],
		CVEID:        "CVE-2026-1000",
		CVSS:         9.8,
		EPSS:         0.9,
		Exploit:      "kev",
		AssetWeight:  1,
		Risk:         99,
		Priority:     "P0",
		Breakdown:    "[]",
		FixedVersion: "4.17.21",
		Now:          "2026-01-01T00:00:00+08:00",
	}
	created, err := repo.UpsertMatch(ctx, in)
	if err != nil || !created {
		t.Fatalf("首次写入应新增：created=%v err=%v", created, err)
	}
	// 处置状态必须保留
	if _, err := db.Exec(`UPDATE findings SET status = 'fixed', assignee = '李维' WHERE asset_id = ?`, assetID); err != nil {
		t.Fatal(err)
	}
	in.Risk = 88
	in.Priority = "P1"
	created, err = repo.UpsertMatch(ctx, in)
	if err != nil || created {
		t.Fatalf("第二次写入应更新：created=%v err=%v", created, err)
	}

	items, total, err := repo.List(ctx, ports.FindingFilter{Priority: "P1", Limit: 10})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("列表查询失败：total=%d len=%d err=%v", total, len(items), err)
	}
	if items[0].Status != "fixed" || items[0].Assignee != "李维" {
		t.Fatalf("更新不应改动处置字段：%+v", items[0])
	}
	if items[0].AssetHostname != "host-02" || items[0].ComponentEco != "npm" {
		t.Fatalf("关联字段不完整：%+v", items[0])
	}

	if err := repo.MarkStatus(ctx, items[0].ID, "verified", "2026-01-02T00:00:00+08:00",
		"rescan: ok", "系统", "自动验证"); err != nil {
		t.Fatalf("更新状态失败：%v", err)
	}
	got, err := repo.Get(ctx, items[0].ID)
	if err != nil || got.Status != "verified" {
		t.Fatalf("状态未更新：%v %+v", err, got)
	}
	if _, err := repo.Get(ctx, 99999); err == nil {
		t.Fatal("不存在的记录应返回错误")
	}

	total, assetsCount, err := repo.ReportTotals(ctx, ports.ReportFilter{})
	if err != nil || assetsCount != 1 || total != 1 {
		t.Fatalf("报告统计异常：total=%d assets=%d err=%v", total, assetsCount, err)
	}
	byPrio, err := repo.ReportByPriority(ctx, ports.ReportFilter{})
	if err != nil || byPrio["P1"] != 1 {
		t.Fatalf("优先级分布异常：%+v err=%v", byPrio, err)
	}
	report, err := repo.ReportRows(ctx, ports.ReportFilter{Status: "verified"}, 10)
	if err != nil || len(report) != 1 || report[0].CVEID != "CVE-2026-1000" {
		t.Fatalf("报告明细异常：%+v err=%v", report, err)
	}
}

func TestIdentityRepoAndProductMap(t *testing.T) {
	assets := newTestDB(t)
	db := assets.db
	ctx := context.Background()

	repo := NewIdentityRepo(db)
	if err := repo.CreateAccount(ctx, ports.Account{
		Username: "alice", Name: "爱丽丝", PwdHash: "h1", Role: "admin",
	}); err != nil {
		t.Fatalf("创建账号失败：%v", err)
	}
	if n, _ := repo.CountByUsername(ctx, "alice"); n != 1 {
		t.Fatalf("账号数应为 1，实际 %d", n)
	}
	if n, _ := repo.CountActiveAdmins(ctx); n != 1 {
		t.Fatalf("管理员数应为 1，实际 %d", n)
	}
	acc, err := repo.FindAccount(ctx, "alice")
	if err != nil || acc.Name != "爱丽丝" || acc.Disabled {
		t.Fatalf("读取账号异常：%+v err=%v", acc, err)
	}
	if err := repo.UpdateAccount(ctx, "alice", "Alice", "viewer", true); err != nil {
		t.Fatal(err)
	}
	acc, _ = repo.FindAccount(ctx, "alice")
	if acc.Role != "viewer" || !acc.Disabled {
		t.Fatalf("账号更新未生效：%+v", acc)
	}
	if err := repo.UpdatePassword(ctx, "nobody", "h2"); err == nil {
		t.Fatal("不存在的账号应返回错误")
	}
	if err := repo.ReplaceToken(ctx, "hash-1", "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	hashes, err := repo.ListTokenHashes(ctx)
	if err != nil || len(hashes) != 1 {
		t.Fatalf("替换令牌后应只剩 1 个：%v %v", hashes, err)
	}
	// 重复写入同一摘要保持幂等
	if err := repo.SaveTokenHash(ctx, "hash-1", "2026-01-02"); err != nil {
		t.Fatal(err)
	}
	hashes, _ = repo.ListTokenHashes(ctx)
	if len(hashes) != 1 {
		t.Fatalf("重复写入不应新增：%v", hashes)
	}

	intel := NewIntelRepo(db)
	if err := intel.UpsertProductMapping(ctx, ports.ProductMapping{
		Eco: "deb", Name: "node-lodash", Product: "lodash", Confidence: 0.9,
	}, "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	list, err := intel.ProductMapList(ctx, "lodash", 10)
	if err != nil || len(list) != 1 || list[0].Product != "lodash" {
		t.Fatalf("映射查询异常：%+v err=%v", list, err)
	}
	mappings, err := intel.ProductMappings(ctx)
	if err != nil || len(mappings) != 1 {
		t.Fatalf("映射索引异常：%v %v", mappings, err)
	}
	if err := intel.DeleteProductMapping(ctx, "deb", "node-lodash"); err != nil {
		t.Fatal(err)
	}
	if err := intel.DeleteProductMapping(ctx, "deb", "node-lodash"); err == nil {
		t.Fatal("重复删除应返回 ErrNotFound")
	}
}

func TestHarnessRepoPendingApprovalSkipsExpired(t *testing.T) {
	assets := newTestDB(t)
	db := assets.db
	repo := NewHarnessRepo(db)
	ctx := context.Background()
	base := harness.Approval{
		SessionID: "s-1", Tool: "rescan_asset", ArgsHash: "hash-1", Args: "{}",
		Risk: "medium", RequestedBy: "alice", Status: "pending",
		RequestedAt: "2026-10-27T03:00:00+08:00",
	}
	expired := base
	expired.ID = "ap-expired"
	expired.ExpiresAt = "2026-10-27T02:59:00+08:00"
	if err := repo.CreateApproval(ctx, expired); err != nil {
		t.Fatal(err)
	}
	now := "2026-10-27T03:00:00+08:00"
	if ap, found, err := repo.PendingApproval(ctx, "s-1", "rescan_asset", "hash-1", now); err != nil || found {
		t.Fatalf("过期审批不应被复用：found=%v ap=%+v err=%v", found, ap, err)
	}
	if pending, err := repo.HasPendingApproval(ctx, "s-1", now); err != nil || pending {
		t.Fatalf("过期审批不应阻塞会话：pending=%v err=%v", pending, err)
	}

	valid := base
	valid.ID = "ap-valid"
	valid.ExpiresAt = "2026-10-27T03:10:00+08:00"
	if err := repo.CreateApproval(ctx, valid); err != nil {
		t.Fatal(err)
	}
	ap, found, err := repo.PendingApproval(ctx, "s-1", "rescan_asset", "hash-1", now)
	if err != nil || !found || ap.ID != "ap-valid" {
		t.Fatalf("应命中未过期审批：found=%v ap=%+v err=%v", found, ap, err)
	}
	list, err := repo.PendingApprovals(ctx, "s-1", now)
	if err != nil || len(list) != 1 || list[0].ID != "ap-valid" {
		t.Fatalf("待审批列表应只含未过期项：%+v err=%v", list, err)
	}
}

func TestAuditRepoFilters(t *testing.T) {
	assets := newTestDB(t)
	repo := NewAuditRepo(assets.db)
	ctx := context.Background()
	entries := []ports.AuditEntry{
		{Actor: "admin", Role: "admin", Action: "auth.login", Target: "admin", IP: "10.0.0.1", Detail: "登录成功", CreatedAt: "2026-10-25T09:00:00+08:00"},
		{Actor: "王浩", Role: "admin", Action: "agent.approval.approve", Target: "rescan_asset", IP: "10.0.0.2", Detail: "审批通过", CreatedAt: "2026-10-26T23:22:16+08:00"},
		{Actor: "李维", Role: "operator", Action: "finding.status", Target: "CVE-2021-44228 @ web-01", IP: "10.0.0.3", Detail: "open → fixing", CreatedAt: "2026-10-27T03:00:00+08:00"},
	}
	for _, entry := range entries {
		if err := repo.Insert(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name   string
		filter ports.AuditFilter
		want   int
	}{
		{"按动作前缀", ports.AuditFilter{Action: "agent."}, 1},
		{"按操作人", ports.AuditFilter{Actor: "王浩"}, 1},
		{"关键字匹配对象", ports.AuditFilter{Query: "rescan"}, 1},
		{"关键字匹配 IP", ports.AuditFilter{Query: "10.0.0.3"}, 1},
		{"起始时间", ports.AuditFilter{From: "2026-10-26T00:00:00+08:00"}, 2},
		{"结束时间", ports.AuditFilter{To: "2026-10-26T23:59:59+08:00"}, 2},
		{"组合条件", ports.AuditFilter{Action: "auth.", Query: "登录"}, 1},
		{"无匹配", ports.AuditFilter{Query: "不存在的关键字"}, 0},
	}
	for _, item := range cases {
		filter := item.filter
		filter.Limit, filter.Offset = 50, 0
		list, err := repo.List(ctx, filter)
		if err != nil {
			t.Fatalf("%s：查询失败 %v", item.name, err)
		}
		total, err := repo.Count(ctx, filter)
		if err != nil || total != item.want || len(list) != item.want {
			t.Fatalf("%s：期望 %d 条，实际 total=%d len=%d err=%v", item.name, item.want, total, len(list), err)
		}
	}
}
