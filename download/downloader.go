// Package download 负责把抓到的资源重新取回本地。
//
// 抓包工具不能为了预览把响应体都留在内存里，因此这里采用重放请求头的方式：
// 记录下当次请求的 Header，下载时原样带上，绕过 Referer / 防盗链一类校验。
package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRetries = 3

// retryDelay 是重试间隔，以变量形式暴露便于测试缩短等待
var retryDelay = 3 * time.Second

// forbiddenHeaders 是重放时必须剔除的请求头。
// 带上它们会导致内容被压缩、长度不符或直接返回 304，拿到的文件是坏的。
var forbiddenHeaders = map[string]bool{
	"accept-encoding":    true,
	"content-length":     true,
	"transfer-encoding":  true,
	"connection":         true,
	"keep-alive":         true,
	"upgrade":            true,
	"host":               true,
	"if-none-match":      true,
	"if-modified-since":  true,
	"if-match":           true,
	"if-unmodified-since": true,
	"range":              true,
	"proxy-authorization": true,
	"proxy-connection":   true,
	// 浏览器上下文相关，重放时给的值必然不对，部分服务端会因此拒绝
	"sec-fetch-site": true,
	"sec-fetch-mode": true,
	"sec-fetch-user": true,
	"sec-fetch-dest": true,
}

// Progress 是下载进度快照
type Progress struct {
	ID         string `json:"ID"`
	FileName   string `json:"FileName"`
	Downloaded int64  `json:"Downloaded"`
	// Total 为 -1 表示服务端未告知长度
	Total int64  `json:"Total"`
	Done  bool   `json:"Done"`
	Error string `json:"Error,omitempty"`
}

// Task 描述一次下载
type Task struct {
	// ID 用于把进度事件关联回界面上的记录
	ID string
	// URL 是要下载的地址
	URL string
	// Header 是抓包时记录的原始请求头，会剔除黑名单后重放
	Header http.Header
	// Dest 是最终保存路径
	Dest string
}

// Downloader 使用调用方提供的 client，从而复用代理与超时配置。
type Downloader struct {
	client *http.Client
}

func New(client *http.Client) *Downloader {
	if client == nil {
		client = &http.Client{Timeout: 0}
	}
	return &Downloader{client: client}
}

// Do 执行下载。进度回调可能被频繁调用，实现必须是非阻塞的。
// 失败时不会留下半成品文件。
func (d *Downloader) Do(ctx context.Context, task Task, onProgress func(Progress)) error {
	if task.URL == "" {
		return errors.New("下载地址为空")
	}
	if task.Dest == "" {
		return errors.New("保存路径为空")
	}

	report := func(p Progress) {
		if onProgress != nil {
			p.ID = task.ID
			p.FileName = filepath.Base(task.Dest)
			onProgress(p)
		}
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// 用 select 而不是 Sleep，取消时能立即返回
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}

		err := d.attempt(ctx, task, report)
		if err == nil {
			return nil
		}
		// 主动取消不重试
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = err
	}
	report(Progress{Done: true, Error: lastErr.Error()})
	return fmt.Errorf("下载失败（已重试 %d 次）: %w", maxRetries, lastErr)
}

func (d *Downloader) attempt(ctx context.Context, task Task, report func(Progress)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.URL, nil)
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	applyHeaders(req, task.Header)

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("服务端返回 %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(task.Dest), 0o755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 先写临时文件，成功后再改名，避免中断时留下不完整的文件
	tmp := task.Dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}

	total := resp.ContentLength
	written, copyErr := copyWithProgress(ctx, f, resp.Body, total, report)
	closeErr := f.Close()

	if copyErr != nil {
		os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("写入文件失败: %w", closeErr)
	}
	if total > 0 && written != total {
		os.Remove(tmp)
		return fmt.Errorf("内容不完整: 已写入 %d 字节，期望 %d 字节", written, total)
	}

	if err := os.Rename(tmp, task.Dest); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("保存文件失败: %w", err)
	}

	report(Progress{Downloaded: written, Total: total, Done: true})
	return nil
}

// copyWithProgress 边拷贝边上报进度，并在每轮检查取消状态。
func copyWithProgress(ctx context.Context, dst io.Writer, src io.Reader, total int64, report func(Progress)) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	// 进度上报限流，避免高速下载时把事件通道打爆
	lastReport := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return written, fmt.Errorf("写入文件失败: %w", werr)
			}
			written += int64(n)

			if now := time.Now(); now.Sub(lastReport) >= 200*time.Millisecond {
				lastReport = now
				report(Progress{Downloaded: written, Total: total})
			}
		}
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
	}
}

// applyHeaders 重放抓包时记录的请求头，剔除会破坏下载的字段。
func applyHeaders(req *http.Request, header http.Header) {
	for k, values := range header {
		if forbiddenHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	// 明确要求不压缩，这样 ContentLength 与落盘字节数才能对得上
	req.Header.Set("Accept-Encoding", "identity")
}
