package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"vulnagent/server/internal/application/ports"
)

// NotifyRepo Webhook 通知配置的 SQLite 仓储
type NotifyRepo struct {
	db *sql.DB
}

// NewNotifyRepo 构造通知仓储
func NewNotifyRepo(db *sql.DB) *NotifyRepo { return &NotifyRepo{db: db} }

var _ ports.NotifyRepository = (*NotifyRepo)(nil)

// Get 读取通知配置，记录缺失时返回空配置
func (r *NotifyRepo) Get(ctx context.Context) (ports.NotifySettings, error) {
	var cfg ports.NotifySettings
	var events string
	err := r.db.QueryRowContext(ctx, `SELECT webhook_url, secret, events, last_event, last_status, last_error, last_sent_at
		FROM notify_settings WHERE id = 1`).
		Scan(&cfg.URL, &cfg.Secret, &events, &cfg.LastEvent, &cfg.LastStatus, &cfg.LastError, &cfg.LastSentAt)
	if err != nil {
		return ports.NotifySettings{Events: []string{}}, nil
	}
	if err := json.Unmarshal([]byte(events), &cfg.Events); err != nil || cfg.Events == nil {
		cfg.Events = []string{}
	}
	return cfg, nil
}

// Save 保存通知配置
func (r *NotifyRepo) Save(ctx context.Context, s ports.NotifySettings, updatedAt string) error {
	events, err := json.Marshal(s.Events)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `UPDATE notify_settings SET webhook_url = ?, secret = ?, events = ?, updated_at = ?
		WHERE id = 1`, s.URL, s.Secret, string(events), updatedAt)
	return err
}

// MarkResult 记录最近一次推送结果
func (r *NotifyRepo) MarkResult(ctx context.Context, event, status, errMsg, at string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE notify_settings SET last_event = ?, last_status = ?, last_error = ?, last_sent_at = ?
		WHERE id = 1`, event, status, errMsg, at)
	return err
}
