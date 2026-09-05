package download

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	// 缩短重试等待，避免失败路径的测试拖慢整个测试集
	retryDelay = 10 * time.Millisecond
}

func TestDownloadWritesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("binary-content"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "a.png")
	var last Progress
	err := New(srv.Client()).Do(context.Background(), Task{
		ID:   "1",
		URL:  srv.URL,
		Dest: dest,
	}, func(p Progress) { last = p })
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("读取结果失败: %v", err)
	}
	if string(got) != "binary-content" {
		t.Errorf("文件内容 = %q", got)
	}
	if !last.Done || last.Error != "" {
		t.Errorf("最后一次进度 = %+v, 期望完成且无错误", last)
	}
	if last.FileName != "a.png" {
		t.Errorf("FileName = %q, want a.png", last.FileName)
	}
}

// 重放请求头是为了绕过防盗链，但会破坏下载的头必须剔除
func TestDownloadReplaysHeadersWithoutForbidden(t *testing.T) {
	var received http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	header := http.Header{}
	header.Set("Referer", "https://example.com/page")
	header.Set("Cookie", "sid=abc")
	header.Set("User-Agent", "test-agent")
	header.Set("Accept-Encoding", "gzip, br")
	header.Set("If-None-Match", `"etag"`)
	header.Set("Sec-Fetch-Mode", "navigate")
	header.Set("Content-Length", "999")

	dest := filepath.Join(t.TempDir(), "f.bin")
	if err := New(srv.Client()).Do(context.Background(), Task{
		URL: srv.URL, Header: header, Dest: dest,
	}, nil); err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	// 防盗链相关的头必须保留
	if received.Get("Referer") != "https://example.com/page" {
		t.Errorf("Referer 丢失: %q", received.Get("Referer"))
	}
	if received.Get("Cookie") != "sid=abc" {
		t.Errorf("Cookie 丢失: %q", received.Get("Cookie"))
	}
	if received.Get("User-Agent") != "test-agent" {
		t.Errorf("User-Agent 丢失: %q", received.Get("User-Agent"))
	}

	// 会导致内容被压缩或返回 304 的头必须被替换/剔除
	if got := received.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", got)
	}
	for _, name := range []string{"If-None-Match", "Sec-Fetch-Mode"} {
		if received.Get(name) != "" {
			t.Errorf("%s 应被剔除, 得到 %q", name, received.Get(name))
		}
	}
}

// 失败时不能留下半成品文件，否则用户会以为下载成功了
func TestDownloadFailureLeavesNoFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "x.bin")
	err := New(srv.Client()).Do(context.Background(), Task{URL: srv.URL, Dest: dest}, nil)
	if err == nil {
		t.Fatal("404 应返回错误")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("错误信息应包含状态码, 得到 %v", err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("失败后目录应为空, 残留 %v", names)
	}
}

func TestDownloadCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// 慢速返回，给取消留出时间窗口
		for i := 0; i < 100; i++ {
			w.Write(make([]byte, 10000))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	dest := filepath.Join(dir, "big.bin")

	done := make(chan error, 1)
	go func() {
		done <- New(srv.Client()).Do(ctx, Task{URL: srv.URL, Dest: dest}, nil)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消后应返回错误")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后未及时返回")
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("取消后不应留下文件, 残留 %d 个", len(entries))
	}
}

func TestDownloadRejectsEmptyInput(t *testing.T) {
	d := New(nil)
	if err := d.Do(context.Background(), Task{Dest: "x"}, nil); err == nil {
		t.Error("空地址应返回错误")
	}
	if err := d.Do(context.Background(), Task{URL: "http://a"}, nil); err == nil {
		t.Error("空保存路径应返回错误")
	}
}
