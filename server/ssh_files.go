package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sftpUploadLimit  = 256 << 20 // 单文件上传上限 256MB
	sftpPreviewLimit = 256 << 10 // 在线预览/保存上限 256KB
	sftpMaxEntries   = 2000
)

// sftpConn 一次 SFTP 操作使用的连接集合
type sftpConn struct {
	client *ssh.Client
	sftp   *sftp.Client
	host   sshHost
}

func (c *sftpConn) Close() {
	if c.sftp != nil {
		_ = c.sftp.Close()
	}
	if c.client != nil {
		_ = c.client.Close()
	}
}

// openSFTP 建立一次 SSH 连接并协商 SFTP 子系统
func (a *App) openSFTP(ctx context.Context, hostID int64) (*sftpConn, error) {
	host, err := a.getSSHHost(ctx, hostID)
	if err != nil {
		return nil, errors.New("主机不存在")
	}
	client, fingerprint, err := a.dialSSHHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if host.HostKey == "" {
		if _, err := a.db.ExecContext(ctx, `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			fingerprint, fmtT(nowT()), host.ID); err != nil {
			return nil, err
		}
	}
	sc, err := sftp.NewClient(client, sftp.UseConcurrentReads(true), sftp.UseConcurrentWrites(true))
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("SFTP 子系统不可用：%w", err)
	}
	return &sftpConn{client: client, sftp: sc, host: host}, nil
}

// normalizeSFTPPath 统一为绝对路径，拒绝空值、NUL 与超长路径
func normalizeSFTPPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("路径不能为空")
	}
	if strings.ContainsRune(value, 0) || len(value) > 4096 {
		return "", errors.New("路径不合法")
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = path.Clean(value)
	if value == "." {
		value = "/"
	}
	return value, nil
}

func hostIDFromQuery(r *http.Request) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("hostId")), 10, 64)
}

// handleSFTPList 列出目录
func (a *App) handleSFTPList(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	hostID, err := hostIDFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	dir, err := normalizeSFTPPath(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()

	entries, err := conn.sftp.ReadDir(dir)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "读取目录失败："+err.Error())
		return
	}
	type item struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Dir      bool   `json:"dir"`
		Size     int64  `json:"size"`
		Mode     string `json:"mode"`
		Modified string `json:"modified"`
		Symlink  bool   `json:"symlink"`
	}
	items := make([]item, 0, len(entries))
	truncated := false
	for _, entry := range entries {
		if len(items) >= sftpMaxEntries {
			truncated = true
			break
		}
		full := path.Join(dir, entry.Name())
		isDir := entry.IsDir()
		symlink := entry.Mode()&os.ModeSymlink != 0
		if symlink {
			if info, statErr := conn.sftp.Stat(full); statErr == nil {
				isDir = info.IsDir()
			}
		}
		items = append(items, item{
			Name: entry.Name(), Path: full, Dir: isDir, Size: entry.Size(),
			Mode: entry.Mode().String(), Modified: entry.ModTime().Format(time.RFC3339), Symlink: symlink,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Dir != items[j].Dir {
			return items[i].Dir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	parent := path.Dir(dir)
	if dir == "/" {
		parent = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": dir, "parent": parent, "items": items, "truncated": truncated, "host": conn.host.Name,
	})
}

// handleSFTPDownload 下载文件
func (a *App) handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	hostID, err := hostIDFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	target, err := normalizeSFTPPath(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()

	info, err := conn.sftp.Stat(target)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	if info.IsDir() {
		writeErr(w, http.StatusBadRequest, "bad_request", "不能下载目录")
		return
	}
	file, err := conn.sftp.Open(target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "打开文件失败："+err.Error())
		return
	}
	defer file.Close()

	name := path.Base(target)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, info.ModTime(), file)
	a.audit(r, "ssh.file.download", conn.host.Name, target)
}

// handleSFTPUpload 上传文件（multipart：file + path 目录）
func (a *App) handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	hostID, err := hostIDFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, sftpUploadLimit+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "上传内容过大或格式错误")
		return
	}
	dir, err := normalizeSFTPPath(r.FormValue("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少上传文件")
		return
	}
	defer file.Close()
	name := path.Base(header.Filename)
	if name == "." || name == "/" || name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "文件名不合法")
		return
	}
	target := path.Join(dir, name)

	conn, err := a.openSFTP(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()

	if info, statErr := conn.sftp.Stat(target); statErr == nil && info.IsDir() {
		writeErr(w, http.StatusConflict, "is_dir", "同名目录已存在")
		return
	}
	tmp := fmt.Sprintf("%s.upload-%d", target, time.Now().UnixNano())
	dst, err := conn.sftp.Create(tmp)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "创建文件失败："+err.Error())
		return
	}
	written, copyErr := io.Copy(dst, file)
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		_ = conn.sftp.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入文件失败")
		return
	}
	_ = conn.sftp.Remove(target)
	if err := conn.sftp.Rename(tmp, target); err != nil {
		_ = conn.sftp.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存文件失败："+err.Error())
		return
	}
	a.audit(r, "ssh.file.upload", conn.host.Name, fmt.Sprintf("%s（%d B）", target, written))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": target, "size": written})
}

// handleSFTPMkdir 新建目录
func (a *App) handleSFTPMkdir(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	var req struct {
		HostID int64  `json:"hostId"`
		Path   string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	target, err := normalizeSFTPPath(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), req.HostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()
	if err := conn.sftp.MkdirAll(target); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "创建目录失败："+err.Error())
		return
	}
	a.audit(r, "ssh.file.mkdir", conn.host.Name, target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": target})
}

// handleSFTPRename 重命名或移动
func (a *App) handleSFTPRename(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	var req struct {
		HostID int64  `json:"hostId"`
		From   string `json:"from"`
		To     string `json:"to"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	from, err := normalizeSFTPPath(req.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	to, err := normalizeSFTPPath(req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), req.HostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()
	if err := conn.sftp.Rename(from, to); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "重命名失败："+err.Error())
		return
	}
	a.audit(r, "ssh.file.rename", conn.host.Name, from+" → "+to)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "from": from, "to": to})
}

// handleSFTPDelete 删除文件或目录
func (a *App) handleSFTPDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	hostID, err := hostIDFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	target, err := normalizeSFTPPath(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if target == "/" {
		writeErr(w, http.StatusBadRequest, "bad_request", "不允许删除根目录")
		return
	}
	recursive := strings.EqualFold(r.URL.Query().Get("recursive"), "true")
	conn, err := a.openSFTP(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()

	info, err := conn.sftp.Stat(target)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "目标不存在")
		return
	}
	if !info.IsDir() {
		if err := conn.sftp.Remove(target); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "删除失败："+err.Error())
			return
		}
	} else {
		if !recursive {
			if err := conn.sftp.RemoveDirectory(target); err != nil {
				writeErr(w, http.StatusConflict, "dir_not_empty", "目录非空，需要确认后递归删除")
				return
			}
		} else {
			paths := make([]string, 0, 64)
			walker := conn.sftp.Walk(target)
			for walker.Step() {
				if err := walker.Err(); err != nil {
					writeErr(w, http.StatusBadRequest, "bad_request", "遍历目录失败："+err.Error())
					return
				}
				paths = append(paths, walker.Path())
				if len(paths) > 5000 {
					writeErr(w, http.StatusBadRequest, "bad_request", "目录过大，请分批删除")
					return
				}
			}
			for i := len(paths) - 1; i >= 0; i-- {
				item := paths[i]
				if item == target {
					if err := conn.sftp.RemoveDirectory(item); err != nil {
						writeErr(w, http.StatusBadRequest, "bad_request", "删除目录失败："+err.Error())
						return
					}
					continue
				}
				if st, statErr := conn.sftp.Stat(item); statErr == nil && st.IsDir() {
					if err := conn.sftp.RemoveDirectory(item); err != nil {
						writeErr(w, http.StatusBadRequest, "bad_request", "删除目录失败："+err.Error())
						return
					}
				} else if err := conn.sftp.Remove(item); err != nil {
					writeErr(w, http.StatusBadRequest, "bad_request", "删除文件失败："+err.Error())
					return
				}
			}
		}
	}
	a.audit(r, "ssh.file.delete", conn.host.Name, target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": target})
}

// handleSFTPPreview 预览小文本文件
func (a *App) handleSFTPPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	hostID, err := hostIDFromQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	target, err := normalizeSFTPPath(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()

	info, err := conn.sftp.Stat(target)
	if err != nil || info.IsDir() {
		writeErr(w, http.StatusNotFound, "not_found", "文件不存在")
		return
	}
	if info.Size() > 2<<20 {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "文件过大，请下载后查看")
		return
	}
	file, err := conn.sftp.Open(target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "打开文件失败："+err.Error())
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, sftpPreviewLimit+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "读取文件失败："+err.Error())
		return
	}
	truncated := len(data) > sftpPreviewLimit
	if truncated {
		data = data[:sftpPreviewLimit]
	}
	binary := false
	for _, b := range data {
		if b == 0 {
			binary = true
			break
		}
	}
	a.audit(r, "ssh.file.read", conn.host.Name, target)
	writeJSON(w, http.StatusOK, map[string]any{
		"path": target, "binary": binary, "truncated": truncated,
		"content": string(data), "size": info.Size(), "modified": info.ModTime().Format(time.RFC3339),
	})
}

// handleSFTPSave 保存小文本文件（原子写）
func (a *App) handleSFTPSave(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	var req struct {
		HostID  int64  `json:"hostId"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if len(req.Content) > sftpPreviewLimit {
		writeErr(w, http.StatusBadRequest, "bad_request", "内容超过 256KB，请下载后编辑")
		return
	}
	target, err := normalizeSFTPPath(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	conn, err := a.openSFTP(r.Context(), req.HostID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", err.Error())
		return
	}
	defer conn.Close()
	tmp := fmt.Sprintf("%s.save-%d", target, time.Now().UnixNano())
	file, err := conn.sftp.Create(tmp)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "创建文件失败："+err.Error())
		return
	}
	if _, err := file.Write([]byte(req.Content)); err != nil {
		_ = file.Close()
		_ = conn.sftp.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入失败")
		return
	}
	if err := file.Close(); err != nil {
		_ = conn.sftp.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入失败")
		return
	}
	_ = conn.sftp.Remove(target)
	if err := conn.sftp.Rename(tmp, target); err != nil {
		_ = conn.sftp.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存失败："+err.Error())
		return
	}
	a.audit(r, "ssh.file.save", conn.host.Name, target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": target, "size": len(req.Content)})
}
