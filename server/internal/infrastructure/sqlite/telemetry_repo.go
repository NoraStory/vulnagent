package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"vulnagent/server/internal/application/ports"
)

// TelemetryRepo 主机遥测的 SQLite 仓储
type TelemetryRepo struct {
	db *sql.DB
}

// NewTelemetryRepo 构造遥测仓储
func NewTelemetryRepo(db *sql.DB) *TelemetryRepo { return &TelemetryRepo{db: db} }

var _ ports.TelemetryRepository = (*TelemetryRepo)(nil)

// Save 写入一次性能采样，并用最新快照整体替换硬件/服务/端口
func (r *TelemetryRepo) Save(ctx context.Context, assetID int64, t ports.HostTelemetry) error {
	if t.CollectedAt == "" {
		t.CollectedAt = time.Now().Format(time.RFC3339)
	}
	metricsJSON, err := json.Marshal(t.Metrics)
	if err != nil {
		return err
	}
	hardwareJSON, err := json.Marshal(t.Hardware)
	if err != nil {
		return err
	}
	services := t.Services
	if services == nil {
		services = []ports.HostService{}
	}
	portsList := t.Ports
	if portsList == nil {
		portsList = []ports.HostPort{}
	}
	servicesJSON, err := json.Marshal(services)
	if err != nil {
		return err
	}
	portsJSON, err := json.Marshal(portsList)
	if err != nil {
		return err
	}
	processes := t.Processes
	if processes == nil {
		processes = []ports.HostProcess{}
	}
	processesJSON, err := json.Marshal(processes)
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `INSERT INTO host_metrics(asset_id, ts, cpu_percent, load1, load5, load15,
		mem_used, mem_total, swap_used, swap_total, disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps,
		uptime_sec, process_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		assetID, t.CollectedAt, t.Metrics.CPUPercent, t.Metrics.Load1, t.Metrics.Load5, t.Metrics.Load15,
		t.Metrics.MemUsed, t.Metrics.MemTotal, t.Metrics.SwapUsed, t.Metrics.SwapTotal,
		t.Metrics.DiskReadBps, t.Metrics.DiskWriteBps, t.Metrics.NetRxBps, t.Metrics.NetTxBps,
		t.Metrics.UptimeSec, t.Metrics.ProcessCount); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_telemetry(asset_id, collected_at, metrics_json,
		hardware_json, services_json, ports_json, processes_json) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(asset_id) DO UPDATE SET collected_at = excluded.collected_at,
			metrics_json = excluded.metrics_json, hardware_json = excluded.hardware_json,
			services_json = excluded.services_json, ports_json = excluded.ports_json,
			processes_json = excluded.processes_json`,
		assetID, t.CollectedAt, string(metricsJSON), string(hardwareJSON),
		string(servicesJSON), string(portsJSON), string(processesJSON)); err != nil {
		return err
	}
	return tx.Commit()
}

// Latest 读取最新遥测快照
func (r *TelemetryRepo) Latest(ctx context.Context, assetID int64) (ports.HostTelemetry, bool, error) {
	var t ports.HostTelemetry
	var metricsJSON, hardwareJSON, servicesJSON, portsJSON, processesJSON string
	err := r.db.QueryRowContext(ctx, `SELECT collected_at, metrics_json, hardware_json, services_json,
		ports_json, processes_json FROM asset_telemetry WHERE asset_id = ?`, assetID).
		Scan(&t.CollectedAt, &metricsJSON, &hardwareJSON, &servicesJSON, &portsJSON, &processesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.HostTelemetry{}, false, nil
	}
	if err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if err := json.Unmarshal([]byte(metricsJSON), &t.Metrics); err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if err := json.Unmarshal([]byte(hardwareJSON), &t.Hardware); err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if err := json.Unmarshal([]byte(servicesJSON), &t.Services); err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if err := json.Unmarshal([]byte(portsJSON), &t.Ports); err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if err := json.Unmarshal([]byte(processesJSON), &t.Processes); err != nil {
		return ports.HostTelemetry{}, false, err
	}
	if t.Hardware.Disks == nil {
		t.Hardware.Disks = []ports.DiskInfo{}
	}
	if t.Hardware.NICs == nil {
		t.Hardware.NICs = []ports.NICInfo{}
	}
	if t.Services == nil {
		t.Services = []ports.HostService{}
	}
	if t.Ports == nil {
		t.Ports = []ports.HostPort{}
	}
	if t.Processes == nil {
		t.Processes = []ports.HostProcess{}
	}
	return t, true, nil
}

// Series 返回最近 limit 个采样点（时间升序）
func (r *TelemetryRepo) Series(ctx context.Context, assetID int64, limit int) ([]ports.MetricPoint, error) {
	if limit <= 0 {
		limit = 48
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := r.db.QueryContext(ctx, `SELECT ts, cpu_percent, load1, mem_used, mem_total,
		net_rx_bps, net_tx_bps, disk_read_bps, disk_write_bps FROM host_metrics
		WHERE asset_id = ? ORDER BY ts DESC, id DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.MetricPoint, 0, limit)
	for rows.Next() {
		var p ports.MetricPoint
		if err := rows.Scan(&p.TS, &p.CPUPercent, &p.Load1, &p.MemUsed, &p.MemTotal,
			&p.NetRxBps, &p.NetTxBps, &p.DiskReadBps, &p.DiskWriteBps); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
