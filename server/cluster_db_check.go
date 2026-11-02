package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// checkClusterDatabase 使用保存的只读账号做连接、版本、连接数与容量检查。
// 凭据仅在内存中解密，不写日志、不回传前端。
func (a *App) checkClusterDatabase(ctx context.Context, node clusterNodeRecord) (string, int64, string) {
	started := time.Now()
	if node.Host == "" || node.Port <= 0 {
		return "failed", 0, "数据库深检需要主机与端口"
	}
	if node.DBUser == "" {
		return "failed", 0, "未配置只读数据库账号"
	}
	password := ""
	if node.dbSecret != "" {
		plain, err := a.openSSHSecret(node.dbSecret)
		if err != nil {
			return "failed", 0, "数据库凭据解密失败"
		}
		password = plain
	}
	driver, dsn := buildDatabaseDSN(node, password)
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return "failed", time.Since(started).Milliseconds(), "连接参数无效：" + truncateRunes(err.Error(), 160)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := db.PingContext(checkCtx); err != nil {
		return "failed", time.Since(started).Milliseconds(), "连接失败：" + dbErrorText(err, password)
	}
	var detail string
	if node.DBEngine == "postgresql" {
		detail, err = collectPostgresMetrics(checkCtx, db, node)
	} else {
		detail, err = collectMySQLMetrics(checkCtx, db, node)
	}
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return "failed", latency, "连接成功但读取指标失败：" + dbErrorText(err, password)
	}
	return "ok", latency, detail
}

func buildDatabaseDSN(node clusterNodeRecord, password string) (string, string) {
	if node.DBEngine == "postgresql" {
		dbName := node.DBName
		if dbName == "" {
			dbName = "postgres"
		}
		u := url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(node.DBUser, password),
			Host:   net.JoinHostPort(node.Host, strconv.Itoa(node.Port)),
			Path:   "/" + dbName,
		}
		query := url.Values{}
		query.Set("connect_timeout", "6")
		if node.DBSSLMode == "require" {
			query.Set("sslmode", "require")
		} else {
			query.Set("sslmode", "disable")
		}
		u.RawQuery = query.Encode()
		return "postgres", u.String()
	}
	cfg := mysqldriver.NewConfig()
	cfg.User = node.DBUser
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(node.Host, strconv.Itoa(node.Port))
	cfg.DBName = node.DBName
	cfg.Timeout = 6 * time.Second
	cfg.ReadTimeout = 6 * time.Second
	cfg.WriteTimeout = 6 * time.Second
	cfg.AllowNativePasswords = true
	cfg.TLSConfig = "false"
	if node.DBSSLMode == "require" {
		cfg.TLSConfig = "skip-verify"
	}
	return "mysql", cfg.FormatDSN()
}

func collectMySQLMetrics(ctx context.Context, db *sql.DB, node clusterNodeRecord) (string, error) {
	var version string
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		return "", err
	}
	connected := queryMySQLValue(ctx, db, `SHOW GLOBAL STATUS LIKE 'Threads_connected'`)
	maxConn := queryMySQLValue(ctx, db, `SHOW VARIABLES LIKE 'max_connections'`)
	uptime := queryMySQLValue(ctx, db, `SHOW GLOBAL STATUS LIKE 'Uptime'`)

	sizeSQL := `SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables`
	args := []any{}
	if node.DBName != "" {
		sizeSQL += ` WHERE table_schema = ?`
		args = append(args, node.DBName)
	} else {
		sizeSQL += ` WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')`
	}
	var size int64
	_ = db.QueryRowContext(ctx, sizeSQL, args...).Scan(&size)

	parts := []string{"MySQL " + shortVersion(version)}
	if node.DBName != "" {
		parts = append(parts, "库 "+node.DBName)
	}
	parts = append(parts,
		fmt.Sprintf("连接 %s/%s", textOrDash(connected), textOrDash(maxConn)),
		"数据 "+humanBytes(size))
	if seconds, err := strconv.ParseInt(uptime, 10, 64); err == nil && seconds > 0 {
		parts = append(parts, "运行 "+humanUptime(seconds))
	}
	return strings.Join(parts, " · "), nil
}

func queryMySQLValue(ctx context.Context, db *sql.DB, query string) string {
	var name, value string
	if err := db.QueryRowContext(ctx, query).Scan(&name, &value); err != nil {
		return ""
	}
	return value
}

func collectPostgresMetrics(ctx context.Context, db *sql.DB, node clusterNodeRecord) (string, error) {
	var version string
	if err := db.QueryRowContext(ctx, `SELECT current_setting('server_version')`).Scan(&version); err != nil {
		return "", err
	}
	var connected, maxConn int64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_stat_activity WHERE datname IS NOT NULL`).Scan(&connected)
	_ = db.QueryRowContext(ctx, `SHOW max_connections`).Scan(&maxConn)
	var size int64
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(pg_database_size(current_database()),0)`).Scan(&size)
	var uptime float64
	_ = db.QueryRowContext(ctx, `SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))`).Scan(&uptime)

	parts := []string{"PostgreSQL " + shortVersion(version)}
	if node.DBName != "" {
		parts = append(parts, "库 "+node.DBName)
	}
	parts = append(parts,
		fmt.Sprintf("连接 %d/%d", connected, maxConn),
		"数据 "+humanBytes(size))
	if uptime > 0 {
		parts = append(parts, "运行 "+humanUptime(int64(uptime)))
	}
	return strings.Join(parts, " · "), nil
}

func shortVersion(version string) string {
	fields := strings.Fields(strings.TrimSpace(version))
	if len(fields) == 0 {
		return "未知版本"
	}
	return fields[0]
}

func textOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "?"
	}
	return value
}

func humanBytes(size int64) string {
	if size <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func humanUptime(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%d 秒", seconds)
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d 小时 %d 分", hours, minutes)
	}
	return fmt.Sprintf("%d 分", minutes)
}

// dbErrorText 去掉错误中的口令并限制长度
func dbErrorText(err error, password string) string {
	text := err.Error()
	if password != "" {
		text = strings.ReplaceAll(text, password, "***")
	}
	return truncateRunes(text, 200)
}
