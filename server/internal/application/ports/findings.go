package ports

import "context"

// FindingListItem 漏洞列表/详情的主体字段
type FindingListItem struct {
	ID               int64   `json:"id"`
	CVEID            string  `json:"cveId"`
	Title            string  `json:"title"`
	Priority         string  `json:"priority"`
	Risk             int     `json:"risk"`
	CVSS             float64 `json:"cvss"`
	EPSS             float64 `json:"epss"`
	Exploit          string  `json:"exploit"`
	Status           string  `json:"status"`
	Assignee         string  `json:"assignee"`
	Inferred         bool    `json:"inferred"`
	FirstSeen        string  `json:"firstSeen"`
	AssetID          int64   `json:"assetId"`
	AssetHostname    string  `json:"assetHostname"`
	AssetEnv         string  `json:"assetEnv"`
	AssetExposure    string  `json:"assetExposure"`
	AssetTier        string  `json:"assetTier"`
	ComponentName    string  `json:"componentName"`
	ComponentVersion string  `json:"componentVersion"`
	ComponentEco     string  `json:"componentEco"`
	PURL             string  `json:"purl"`
	FixedVersion     string  `json:"fixedVersion"`
}

// FindingFilter 漏洞列表筛选条件
type FindingFilter struct {
	Priority string
	Status   string
	Query    string
	Limit    int
	Offset   int
}

// FindingExtra 详情页的附加信息
type FindingExtra struct {
	Description string `json:"description"`
	CWEID       int    `json:"cweId"`
	CWECN       string `json:"cweCn"`
	PublishedAt string `json:"publishedAt"`
	Breakdown   string `json:"breakdown"`
}

// PocLink 公开 POC 链接
type PocLink struct {
	Link       string `json:"link"`
	InsertedAt string `json:"insertedAt"`
}

// FindingEventRow 处置事件
type FindingEventRow struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

// ReportFilter 报告/导出筛选条件
type ReportFilter struct {
	Priority string
	Status   string
	Query    string
}

// ReportRow 报告中的一行
type ReportRow struct {
	Priority     string
	CVEID        string
	Title        string
	Component    string
	Version      string
	FixedVersion string
	Hostname     string
	Status       string
	CVSS         float64
	EPSS         float64
	Risk         int
}

// FindingQueryRepository 漏洞读取与处置写入端口
type FindingQueryRepository interface {
	// List 返回当前页数据与总条数
	List(ctx context.Context, filter FindingFilter) ([]FindingListItem, int, error)
	// ListByAsset 返回某资产的全部漏洞结论（按风险分降序）
	ListByAsset(ctx context.Context, assetID int64) ([]FindingListItem, error)
	// Get 按 ID 读取，不存在时返回 ErrNotFound
	Get(ctx context.Context, id int64) (FindingListItem, error)
	// Extra 读取描述、CWE、发布时间与打分明细；关联的 CVE 记录缺失时返回零值
	Extra(ctx context.Context, id int64) (FindingExtra, error)
	POCs(ctx context.Context, cveID string) ([]PocLink, error)
	Events(ctx context.Context, findingID int64) ([]FindingEventRow, error)
	// AddEvent 追加一条处置事件
	AddEvent(ctx context.Context, findingID int64, event, actor, detail, at string) error
	// UpdateStatusAssignee 更新状态与责任人
	UpdateStatusAssignee(ctx context.Context, id int64, status, assignee string) error
	// CreateTicket 写入工单号并同步状态与责任人
	CreateTicket(ctx context.Context, id int64, ticketID, status, assignee string) error
	// NextTicketSeq 返回当前工单号的最大序号
	NextTicketSeq(ctx context.Context) (int, error)
	// ReportRows 返回报告明细（按风险分降序，最多 limit 条）
	ReportRows(ctx context.Context, filter ReportFilter, limit int) ([]ReportRow, error)
	// ReportTotals 返回筛选范围内的漏洞总数与涉及资产数
	ReportTotals(ctx context.Context, filter ReportFilter) (int, int, error)
	// ReportByPriority 返回忽略优先级筛选的优先级分布
	ReportByPriority(ctx context.Context, filter ReportFilter) (map[string]int, error)
}
