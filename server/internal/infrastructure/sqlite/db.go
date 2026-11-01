// Package sqlite 提供 SQLite 连接、迁移与只读连接。
// 该包是唯一允许直接持有 *sql.DB 的基础设施层实现之一。
package sqlite

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open 打开读写连接（WAL、忙等待 10s），并执行未应用的迁移。
// WAL 支持多读单写：读写池开到 4 个连接，配合 busy_timeout 提升并发读性能；
// 写事务使用 immediate 模式，避免延迟升级写锁导致的 SQLITE_BUSY。
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(NORMAL)&_pragma=cache_size(-32768)&_pragma=temp_store(MEMORY)"+
		"&_pragma=mmap_size(268435456)&_pragma=journal_size_limit(67108864)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if err := Migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	// 迁移后更新统计信息，帮助查询优化器选择新索引；失败不影响启动。
	_, _ = db.Exec(`PRAGMA optimize`)
	return db, nil
}

// OpenReadOnly 打开只读连接，专供 Agent Harness 的读工具使用，
// 从连接层面杜绝任何写操作。
func OpenReadOnly(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)&_pragma=cache_size(-16384)"+
		"&_pragma=temp_store(MEMORY)&_pragma=mmap_size(268435456)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
