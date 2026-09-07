package throttle

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
)

func enabled(cfg models.ThrottleConfig) models.ThrottleConfig {
	cfg.Enabled = true
	return cfg
}

func TestNormalizeClampsValues(t *testing.T) {
	cfg := models.ThrottleConfig{DownKbps: -5, UpKbps: 1 << 30, LatencyMs: -1}
	cfg.Normalize()

	if cfg.DownKbps != 0 {
		t.Errorf("负带宽应归零表示不限, 得到 %d", cfg.DownKbps)
	}
	if cfg.UpKbps != 1_000_000 {
		t.Errorf("超上限应被截断, 得到 %d", cfg.UpKbps)
	}
	if cfg.LatencyMs != 0 {
		t.Errorf("负延迟应归零, 得到 %d", cfg.LatencyMs)
	}
}

// 开着开关但三项都是 0 等于没限速，不该显示成生效中
func TestEffectiveRequiresRealLimit(t *testing.T) {
	if (models.ThrottleConfig{Enabled: true}).Effective() {
		t.Error("三项都为 0 时不该算生效")
	}
	if (models.ThrottleConfig{DownKbps: 100}).Effective() {
		t.Error("开关关闭时不该算生效")
	}
	if !(models.ThrottleConfig{Enabled: true, LatencyMs: 1}).Effective() {
		t.Error("只设延迟也算生效")
	}
}

// 101 之后 Body 是双向帧流，包一层只读限速器会让 WebSocket 直接不可用
func TestApplyResponseSkipsSwitchingProtocols(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{DownKbps: 8}))

	body := io.NopCloser(strings.NewReader("frames"))
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Body:       body,
		Request:    httptest.NewRequest("GET", "https://example.com/ws", nil),
	}
	l.ApplyResponse(resp)

	if resp.Body != body {
		t.Error("101 响应的 Body 不该被包装")
	}
}

func TestApplyResponseWrapsWhenLimited(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{DownKbps: 8}))

	body := io.NopCloser(strings.NewReader("hello"))
	resp := &http.Response{
		StatusCode: 200,
		Body:       body,
		Request:    httptest.NewRequest("GET", "https://example.com/a", nil),
	}
	l.ApplyResponse(resp)

	if resp.Body == body {
		t.Error("限速开启时应包装 Body")
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "hello" {
		t.Errorf("包装后内容应不变, 得到 %q", got)
	}
}

func TestApplyResponseRespectsURLRegex(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{DownKbps: 8, URLRegex: `/slow/`}))

	miss := io.NopCloser(strings.NewReader("x"))
	resp := &http.Response{
		StatusCode: 200,
		Body:       miss,
		Request:    httptest.NewRequest("GET", "https://example.com/fast/a", nil),
	}
	l.ApplyResponse(resp)
	if resp.Body != miss {
		t.Error("URL 不匹配时不该限速")
	}

	hit := io.NopCloser(strings.NewReader("x"))
	resp2 := &http.Response{
		StatusCode: 200,
		Body:       hit,
		Request:    httptest.NewRequest("GET", "https://example.com/slow/a", nil),
	}
	l.ApplyResponse(resp2)
	if resp2.Body == hit {
		t.Error("URL 匹配时应限速")
	}
}

func TestApplyResponseNoopWhenDisabled(t *testing.T) {
	l := New(models.ThrottleConfig{DownKbps: 8}) // Enabled 为 false

	body := io.NopCloser(strings.NewReader("x"))
	resp := &http.Response{
		StatusCode: 200,
		Body:       body,
		Request:    httptest.NewRequest("GET", "https://example.com/a", nil),
	}
	l.ApplyResponse(resp)
	if resp.Body != body {
		t.Error("未启用时不该包装 Body")
	}
}

func TestApplyRequestAddsLatency(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{LatencyMs: 60}))
	req := httptest.NewRequest("GET", "https://example.com/a", nil)

	start := time.Now()
	l.ApplyRequest(req)
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("应至少等待约 60ms, 实际 %v", elapsed)
	}
}

// 客户端断开后不该干等满整个延迟才收尾
func TestApplyRequestStopsOnCancel(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{LatencyMs: 5000}))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "https://example.com/a", nil).WithContext(ctx)
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	l.ApplyRequest(req)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("取消后应立即返回, 实际等了 %v", elapsed)
	}
}

func TestLoadRejectsInvalidRegexAndKeepsOldConfig(t *testing.T) {
	l := New(enabled(models.ThrottleConfig{DownKbps: 100}))

	if err := l.Load(enabled(models.ThrottleConfig{DownKbps: 200, URLRegex: "(["})); err == nil {
		t.Fatal("非法正则应返回错误")
	}
	if got := l.Config().DownKbps; got != 100 {
		t.Errorf("解析失败后旧配置应保留, 得到 %d", got)
	}
}

func TestBucketReserveWaitsOnlyAfterExhausted(t *testing.T) {
	// 1000 B/s，桶初始满（容量等于 1 秒的量）
	b := newBucket(1000)
	if b == nil {
		t.Fatal("正数速率应创建出桶")
	}

	if d := b.reserve(500); d != 0 {
		t.Errorf("额度充足时不该等待, 得到 %v", d)
	}
	// 再取 1000 会超出剩余的 500，缺口 500 字节 → 约 0.5 秒
	d := b.reserve(1000)
	if d < 400*time.Millisecond || d > 600*time.Millisecond {
		t.Errorf("等待时长 = %v, 期望约 500ms", d)
	}
}

func TestNewBucketNilWhenUnlimited(t *testing.T) {
	if newBucket(0) != nil {
		t.Error("速率为 0 表示不限，应返回 nil")
	}
}

// 分片是为了让每次等待约 100ms：一次读太多会攒成长卡顿，
// 也会让客户端断开后迟迟无法收尾
func TestBucketChunkSizeBounded(t *testing.T) {
	slow := newBucket(100) // 100 B/s → 10 字节，会被抬到下限
	if slow.chunk != minChunk {
		t.Errorf("低速率下 chunk = %d, want %d", slow.chunk, minChunk)
	}

	fast := newBucket(100 << 20) // 极高速率 → 会被压到上限
	if fast.chunk != maxChunk {
		t.Errorf("高速率下 chunk = %d, want %d", fast.chunk, maxChunk)
	}

	mid := newBucket(50 << 10) // 50KB/s → 约 5KB
	if mid.chunk <= minChunk || mid.chunk >= maxChunk {
		t.Errorf("中等速率下 chunk 应落在上下限之间, 得到 %d", mid.chunk)
	}
}

// 单次读取不能超过分片上限，否则等待会集中成一次长卡顿
func TestLimitedReaderCapsReadSize(t *testing.T) {
	b := newBucket(100) // chunk 会被抬到 minChunk
	r := wrap(io.NopCloser(strings.NewReader(strings.Repeat("x", 4096))), b)

	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if n > b.chunk {
		t.Errorf("单次读取 %d 字节, 超过分片上限 %d", n, b.chunk)
	}
}

func TestKbpsToBytes(t *testing.T) {
	if got := kbpsToBytes(8); got != 1000 {
		t.Errorf("8 kbps = %v B/s, want 1000", got)
	}
	if got := kbpsToBytes(0); got != 0 {
		t.Errorf("0 表示不限, 得到 %v", got)
	}
}
