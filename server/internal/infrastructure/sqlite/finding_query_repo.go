package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"vulnagent/server/internal/application/ports"
)

var _ ports.FindingQueryRepository = (*FindingRepo)(nil)

const findingSelect = `SELECT f.id, f.cve_id, c.title, f.priority, f.risk, f.cvss, f.epss, f.exploit,
	f.status, f.assignee, f.inferred, f.first_seen,
	a.id, a.hostname, a.env, a.exposure, a.tier,
	f.component_name, f.component_version, f.eco, f.purl, f.fixed_version
	FROM findings f
	JOIN assets a ON a.id = f.asset_id
	JOIN cves c ON c.cve_id = f.cve_id`

func scanFindingItem(sc interface{ Scan(...any) error }) (ports.FindingListItem, error) {
	var it ports.FindingListItem
	var inferred int
	err := sc.Scan(&it.ID, &it.CVEID, &it.Title, &it.Priority, &it.Risk, &it.CVSS, &it.EPSS, &it.Exploit,
		&it.Status, &it.Assignee, &inferred, &it.FirstSeen,
		&it.AssetID, &it.AssetHostname, &it.AssetEnv, &it.AssetExposure, &it.AssetTier,
		&it.ComponentName, &it.ComponentVersion, &it.ComponentEco, &it.PURL, &it.FixedVersion)
	it.Inferred = inferred != 0
	return it, err
}

// List 返回当前页数据与总条数
func (r *FindingRepo) List(ctx context.Context, filter ports.FindingFilter) ([]ports.FindingListItem, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if filter.Priority != "" {
		where = append(where, "f.priority = ?")
		args = append(args, filter.Priority)
	}
	if filter.Status != "" {
		where = append(where, "f.status = ?")
		args = append(args, filter.Status)
	}
	if filter.Query != "" {
		like := "%" + filter.Query + "%"
		where = append(where, "(a.hostname LIKE ? OR f.cve_id LIKE ? OR f.component_name LIKE ?)")
		args = append(args, like, like, like)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), filter.Limit, filter.Offset)
	rows, err := r.db.QueryContext(ctx,
		findingSelect+" WHERE "+whereSQL+" ORDER BY f.risk DESC, f.id ASC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ports.FindingListItem, 0, filter.Limit)
	for rows.Next() {
		it, err := scanFindingItem(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, it)
	}
	return items, total, rows.Err()
}

// Get 按 ID 读取漏洞
func (r *FindingRepo) Get(ctx context.Context, id int64) (ports.FindingListItem, error) {
	it, err := scanFindingItem(r.db.QueryRowContext(ctx, findingSelect+" WHERE f.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.FindingListItem{}, ports.ErrNotFound
	}
	return it, err
}

// ListByAsset 返回某资产的全部漏洞结论
func (r *FindingRepo) ListByAsset(ctx context.Context, assetID int64) ([]ports.FindingListItem, error) {
	rows, err := r.db.QueryContext(ctx, findingSelect+" WHERE f.asset_id = ? ORDER BY f.risk DESC, f.id ASC", assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.FindingListItem, 0)
	for rows.Next() {
		it, err := scanFindingItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Extra 读取详情页附加信息
func (r *FindingRepo) Extra(ctx context.Context, id int64) (ports.FindingExtra, error) {
	var out ports.FindingExtra
	err := r.db.QueryRowContext(ctx, `SELECT c.description, c.cwe_id, c.cwe_cn, c.published_at, f.score_breakdown
		FROM findings f JOIN cves c ON c.cve_id = f.cve_id WHERE f.id = ?`, id).
		Scan(&out.Description, &out.CWEID, &out.CWECN, &out.PublishedAt, &out.Breakdown)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.FindingExtra{}, nil
	}
	return out, err
}

// POCs 返回公开 POC 链接
func (r *FindingRepo) POCs(ctx context.Context, cveID string) ([]ports.PocLink, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT link, inserted_at FROM cve_poc WHERE cve_id = ? ORDER BY inserted_at DESC`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.PocLink, 0)
	for rows.Next() {
		var item ports.PocLink
		if err := rows.Scan(&item.Link, &item.InsertedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Events 返回处置事件
func (r *FindingRepo) Events(ctx context.Context, findingID int64) ([]ports.FindingEventRow, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT created_at, event, actor, detail FROM finding_events
		WHERE finding_id = ? ORDER BY created_at ASC, id ASC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.FindingEventRow, 0)
	for rows.Next() {
		var item ports.FindingEventRow
		if err := rows.Scan(&item.Time, &item.Event, &item.Actor, &item.Detail); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// AddEvent 追加一条处置事件
func (r *FindingRepo) AddEvent(ctx context.Context, findingID int64, event, actor, detail, at string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO finding_events(finding_id, event, actor, detail, created_at)
		VALUES(?,?,?,?,?)`, findingID, event, actor, detail, at)
	return err
}

// UpdateStatusAssignee 更新状态与责任人
func (r *FindingRepo) UpdateStatusAssignee(ctx context.Context, id int64, status, assignee string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET status = ?, assignee = ? WHERE id = ?`, status, assignee, id)
	return err
}

// CreateTicket 写入工单号并同步状态与责任人
func (r *FindingRepo) CreateTicket(ctx context.Context, id int64, ticketID, status, assignee string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET ticket_id = ?, status = ?, assignee = ? WHERE id = ?`,
		ticketID, status, assignee, id)
	return err
}

// NextTicketSeq 返回当前工单号的最大序号
func (r *FindingRepo) NextTicketSeq(ctx context.Context) (int, error) {
	var maxSeq int
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(CAST(substr(ticket_id, 9) AS INTEGER)), 0)
		FROM findings WHERE ticket_id LIKE 'VA-%'`).Scan(&maxSeq)
	return maxSeq, err
}

// reportWhere 生成报告筛选条件；withPriority 为 false 时忽略优先级
func reportWhere(filter ports.ReportFilter, withPriority bool) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	if filter.Status != "" {
		where = append(where, "f.status = ?")
		args = append(args, filter.Status)
	}
	if filter.Query != "" {
		like := "%" + filter.Query + "%"
		where = append(where, "(a.hostname LIKE ? OR f.cve_id LIKE ? OR f.component_name LIKE ?)")
		args = append(args, like, like, like)
	}
	if withPriority && filter.Priority != "" {
		where = append(where, "f.priority = ?")
		args = append(args, filter.Priority)
	}
	return strings.Join(where, " AND "), args
}

// ReportRows 返回报告明细
func (r *FindingRepo) ReportRows(ctx context.Context, filter ports.ReportFilter, limit int) ([]ports.ReportRow, error) {
	where, args := reportWhere(filter, true)
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `SELECT f.priority, f.cve_id, c.title, f.component_name, f.component_version,
		f.fixed_version, a.hostname, f.status, f.cvss, f.epss, f.risk
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		JOIN cves c ON c.cve_id = f.cve_id
		WHERE `+where+` ORDER BY f.risk DESC, f.id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.ReportRow, 0, limit)
	for rows.Next() {
		var it ports.ReportRow
		if err := rows.Scan(&it.Priority, &it.CVEID, &it.Title, &it.Component, &it.Version,
			&it.FixedVersion, &it.Hostname, &it.Status, &it.CVSS, &it.EPSS, &it.Risk); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// ReportTotals 返回筛选范围内的漏洞总数与涉及资产数
func (r *FindingRepo) ReportTotals(ctx context.Context, filter ports.ReportFilter) (int, int, error) {
	where, args := reportWhere(filter, true)
	var total, assets int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT f.asset_id) FROM findings f
		JOIN assets a ON a.id = f.asset_id WHERE `+where, args...).Scan(&total, &assets)
	return total, assets, err
}

// ReportByPriority 返回忽略优先级筛选的优先级分布
func (r *FindingRepo) ReportByPriority(ctx context.Context, filter ports.ReportFilter) (map[string]int, error) {
	where, args := reportWhere(filter, false)
	rows, err := r.db.QueryContext(ctx, `SELECT f.priority, COUNT(*) FROM findings f
		JOIN assets a ON a.id = f.asset_id WHERE `+where+` GROUP BY f.priority`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		out[name] = count
	}
	return out, rows.Err()
}
