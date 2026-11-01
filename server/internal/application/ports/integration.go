package ports

// IntegrationSource 云厂商或外部 CMDB 集成源
type IntegrationSource struct {
	ID              int64  `json:"id"`
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Config          string `json:"config"`
	Secret          string `json:"-"`
	Enabled         bool   `json:"enabled"`
	IntervalMinutes int    `json:"intervalMinutes"`
	LastRunAt       string `json:"lastRunAt"`
	LastStatus      string `json:"lastStatus"`
	LastError       string `json:"lastError"`
	LastCount       int    `json:"lastCount"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
}
