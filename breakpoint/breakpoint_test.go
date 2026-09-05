package breakpoint

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
)

func enabledConfig() models.BreakpointConfig {
	cfg := models.DefaultBreakpointConfig()
	cfg.Enabled = true
	cfg.OnRequest = true
	cfg.OnResponse = true
	cfg.TimeoutSeconds = 5
	return cfg
}

// 关闭状态下必须完全不拦截，否则默认配置就会把网络挂住
func TestDisabledDoesNotIntercept(t *testing.T) {
	m := New(nil)

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	if action := m.InterceptRequest(req, "1"); action != models.BreakpointResume {
		t.Errorf("关闭时应直接放行, 得到 %s", action)
	}
	if m.PendingCount() != 0 {
		t.Error("关闭时不应产生待处理项")
	}
}

func TestResolveResume(t *testing.T) {
	m := New(nil)
	if err := m.Load(enabledConfig()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptRequest(req, "42") }()

	waitPending(t, m, 1)
	if err := m.Resolve(models.BreakpointResolution{ID: "42", Action: models.BreakpointResume}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	select {
	case action := <-done:
		if action != models.BreakpointResume {
			t.Errorf("action = %s, want resume", action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("放行后请求未及时继续")
	}
	if m.PendingCount() != 0 {
		t.Error("处理后待处理项应清空")
	}
}

func TestResolveModifyRequest(t *testing.T) {
	m := New(nil)
	m.Load(enabledConfig())

	req := httptest.NewRequest(http.MethodPost, "http://a.com/old", strings.NewReader("orig"))
	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptRequest(req, "7") }()

	waitPending(t, m, 1)
	header := http.Header{}
	header.Set("X-Injected", "1")
	m.Resolve(models.BreakpointResolution{
		ID:     "7",
		Action: models.BreakpointModify,
		Method: http.MethodPut,
		URL:    "http://a.com/new",
		Header: header,
		Body:   "changed",
	})

	if action := <-done; action != models.BreakpointModify {
		t.Fatalf("action = %s", action)
	}
	if req.Method != http.MethodPut {
		t.Errorf("Method = %s", req.Method)
	}
	if req.URL.String() != "http://a.com/new" {
		t.Errorf("URL = %s", req.URL.String())
	}
	if req.Header.Get("X-Injected") != "1" {
		t.Errorf("请求头未被替换")
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "changed" {
		t.Errorf("Body = %q", body)
	}
	// 长度不同步会让连接挂死
	if req.ContentLength != int64(len("changed")) {
		t.Errorf("ContentLength = %d", req.ContentLength)
	}
}

func TestResolveAbort(t *testing.T) {
	m := New(nil)
	m.Load(enabledConfig())

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptRequest(req, "9") }()

	waitPending(t, m, 1)
	m.Resolve(models.BreakpointResolution{ID: "9", Action: models.BreakpointAbort})

	if action := <-done; action != models.BreakpointAbort {
		t.Errorf("action = %s, want abort", action)
	}
}

// 超时兜底：无人处理时必须自动放行，否则连接被永久挂死
func TestTimeoutAutoResumes(t *testing.T) {
	m := New(nil)
	cfg := enabledConfig()
	cfg.TimeoutSeconds = 1
	m.Load(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	start := time.Now()
	action := m.InterceptRequest(req, "t1")

	if action != models.BreakpointResume {
		t.Errorf("超时应自动放行, 得到 %s", action)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("超时过早触发: %v", elapsed)
	}
	if m.PendingCount() != 0 {
		t.Error("超时后待处理项应清空")
	}
}

// 代理停止时必须放行所有挂住的请求，否则 goroutine 泄漏
func TestReleaseAll(t *testing.T) {
	m := New(nil)
	m.Load(enabledConfig())

	const n = 3
	done := make(chan models.BreakpointAction, n)
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		req := httptest.NewRequest(http.MethodGet, "http://a.com/"+id, nil)
		go func() { done <- m.InterceptRequest(req, id) }()
	}
	waitPending(t, m, n)

	m.ReleaseAll()
	for i := 0; i < n; i++ {
		select {
		case action := <-done:
			if action != models.BreakpointResume {
				t.Errorf("action = %s, want resume", action)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("ReleaseAll 后仍有请求被挂住")
		}
	}
	if m.PendingCount() != 0 {
		t.Error("ReleaseAll 后待处理项应清空")
	}
}

// 关掉开关也要把已挂住的请求放掉，否则它们要等到超时
func TestDisablingReleasesPending(t *testing.T) {
	m := New(nil)
	m.Load(enabledConfig())

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptRequest(req, "z") }()
	waitPending(t, m, 1)

	cfg := enabledConfig()
	cfg.Enabled = false
	m.Load(cfg)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("关闭断点后请求仍被挂住")
	}
}

func TestURLAndMethodFilter(t *testing.T) {
	m := New(nil)
	cfg := enabledConfig()
	cfg.URLRegex = "a\\.com/api"
	cfg.Method = "post"
	m.Load(cfg)

	// URL 不匹配，应直接放行且不入队
	miss := httptest.NewRequest(http.MethodPost, "http://a.com/other", nil)
	if action := m.InterceptRequest(miss, "m1"); action != models.BreakpointResume {
		t.Errorf("不匹配应直接放行, 得到 %s", action)
	}
	// 方法不匹配
	miss2 := httptest.NewRequest(http.MethodGet, "http://a.com/api", nil)
	if action := m.InterceptRequest(miss2, "m2"); action != models.BreakpointResume {
		t.Errorf("方法不匹配应直接放行, 得到 %s", action)
	}
	if m.PendingCount() != 0 {
		t.Error("不匹配的请求不应入队")
	}
}

func TestPhaseSwitches(t *testing.T) {
	m := New(nil)
	cfg := enabledConfig()
	cfg.OnRequest = false
	cfg.OnResponse = true
	m.Load(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	if action := m.InterceptRequest(req, "p1"); action != models.BreakpointResume {
		t.Errorf("关闭请求阶段后不应拦截, 得到 %s", action)
	}
}

func TestLoadRejectsInvalidRegex(t *testing.T) {
	m := New(nil)
	cfg := enabledConfig()
	cfg.URLRegex = "["
	if err := m.Load(cfg); err == nil {
		t.Error("非法正则应返回错误")
	}
	if m.Config().Enabled {
		t.Error("加载失败时不应改变原配置")
	}
}

// 超时填 0 会让请求永久挂住，必须被纠正
func TestLoadNormalizesTimeout(t *testing.T) {
	m := New(nil)
	cfg := enabledConfig()
	cfg.TimeoutSeconds = 0
	m.Load(cfg)
	if got := m.Config().TimeoutSeconds; got != models.DefaultBreakpointConfig().TimeoutSeconds {
		t.Errorf("TimeoutSeconds = %d, 应回退到默认值", got)
	}

	cfg.TimeoutSeconds = 99999
	m.Load(cfg)
	if got := m.Config().TimeoutSeconds; got != maxTimeoutSeconds {
		t.Errorf("TimeoutSeconds = %d, 应被限制到上限", got)
	}
}

func TestResolveUnknownID(t *testing.T) {
	m := New(nil)
	if err := m.Resolve(models.BreakpointResolution{ID: "nope"}); err == nil {
		t.Error("未知 ID 应返回错误")
	}
}

// 二进制正文不应塞进编辑框
func TestBinaryBodyIsNotEditable(t *testing.T) {
	m := New(nil)
	m.Load(enabledConfig())

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"image/png"}},
		Body:       io.NopCloser(strings.NewReader("\x89PNG....")),
		Request:    httptest.NewRequest(http.MethodGet, "http://a.com/a.png", nil),
	}

	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptResponse(resp, "b1") }()
	waitPending(t, m, 1)

	hits := m.Pending()
	if len(hits) != 1 {
		t.Fatalf("待处理数 = %d", len(hits))
	}
	if !hits[0].BodyBinary {
		t.Error("二进制响应应标记 BodyBinary")
	}
	if !strings.HasPrefix(hits[0].Body, "[binary data]") {
		t.Errorf("Body = %q", hits[0].Body)
	}
	m.ReleaseAll()
	<-done
}

func TestNotifyIsCalled(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })
	m.Load(enabledConfig())

	req := httptest.NewRequest(http.MethodGet, "http://a.com/x", nil)
	done := make(chan models.BreakpointAction, 1)
	go func() { done <- m.InterceptRequest(req, "n1") }()
	waitPending(t, m, 1)

	m.Resolve(models.BreakpointResolution{ID: "n1", Action: models.BreakpointResume})
	<-done

	// 入队与处理各应通知一次
	if got := calls.Load(); got < 2 {
		t.Errorf("notify 调用次数 = %d, want >= 2", got)
	}
}

// waitPending 等待待处理数达到期望值
func waitPending(t *testing.T, m *Manager, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.PendingCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待待处理数 %d 超时，当前 %d", want, m.PendingCount())
}
