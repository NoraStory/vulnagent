package ports

import "context"

// DiscoveryJob 网段发现任务
type DiscoveryJob struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	CIDRs           string `json:"cidrs"`
	Ports           string `json:"ports"`
	Status          string `json:"status"`
	Total           int    `json:"total"`
	Scanned         int    `json:"scanned"`
	Found           int    `json:"found"`
	Options         string `json:"options"`
	CancelRequested bool   `json:"cancelRequested"`
	CreatedBy       string `json:"createdBy"`
	CreatedAt       string `json:"createdAt"`
	StartedAt       string `json:"startedAt"`
	FinishedAt      string `json:"finishedAt"`
	Error           string `json:"error"`
}

// DiscoveryCandidate 发现到的候选资产（按 IP 聚合）
type DiscoveryCandidate struct {
	ID             int64   `json:"id"`
	JobID          int64   `json:"jobId"`
	IP             string  `json:"ip"`
	Hostname       string  `json:"hostname"`
	MAC            string  `json:"mac"`
	OpenPorts      string  `json:"openPorts"`
	Services       string  `json:"services"`
	Evidence       string  `json:"evidence"`
	MatchedAssetID int64   `json:"matchedAssetId"`
	Decision       string  `json:"decision"`
	Confidence     float64 `json:"confidence"`
	DecidedBy      string  `json:"decidedBy"`
	DecidedAt      string  `json:"decidedAt"`
	AssetID        int64   `json:"assetId"`
	CreatedAt      string  `json:"createdAt"`
}

// DiscoveryCandidateFilter 候选资产筛选
type DiscoveryCandidateFilter struct {
	JobID    int64
	Decision string
	Query    string
}

// DiscoveryRepository 网段发现任务的存储端口
type DiscoveryRepository interface {
	CreateJob(ctx context.Context, job DiscoveryJob) (int64, error)
	GetJob(ctx context.Context, id int64) (DiscoveryJob, error)
	ListJobs(ctx context.Context, status string, limit, offset int) ([]DiscoveryJob, int, error)
	CountRunningJobs(ctx context.Context) (int, error)
	CountJobsSince(ctx context.Context, since string) (int, error)
	UpdateJobProgress(ctx context.Context, id int64, scanned, found int) error
	FinishJob(ctx context.Context, id int64, status, errText, finishedAt string) error
	RequestCancel(ctx context.Context, id int64) error
	CancelRequested(ctx context.Context, id int64) (bool, error)
	InterruptUnfinishedJobs(ctx context.Context) (int, error)

	InsertCandidate(ctx context.Context, candidate DiscoveryCandidate) (int64, error)
	GetCandidate(ctx context.Context, id int64) (DiscoveryCandidate, error)
	ListCandidates(ctx context.Context, filter DiscoveryCandidateFilter, limit, offset int) ([]DiscoveryCandidate, int, error)
	SetCandidateDecision(ctx context.Context, id int64, decision string, assetID int64, actor, decidedAt string) error
	CountCandidates(ctx context.Context, jobID int64) (map[string]int, error)
}
