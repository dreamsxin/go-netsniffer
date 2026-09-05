package handler

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/klauspost/compress/zstd"
)

type recordSink struct {
	mu      sync.Mutex
	packets []*models.Packet
	limit   int64
}

func (s *recordSink) Emit(p *models.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, p)
}

func (s *recordSink) MaxBodySize() int64 { return s.limit }

func (s *recordSink) all() []*models.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*models.Packet(nil), s.packets...)
}

func newSink() *recordSink { return &recordSink{limit: 1 << 20} }

func TestReadAndReplaceBodyRestoresFullContent(t *testing.T) {
	var body io.ReadCloser = io.NopCloser(strings.NewReader("hello world"))

	data, truncated, err := readAndReplaceBody(&body, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Error("超过上限时应标记为截断")
	}
	if string(data) != "hello" {
		t.Errorf("记录内容 = %q, want %q", data, "hello")
	}

	// 被抓包的一方必须仍能读到完整内容
	rest, _ := io.ReadAll(body)
	if string(rest) != "hello world" {
		t.Errorf("body 未被完整还原, 得到 %q", rest)
	}
}

func TestDecodeBody(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("gzip payload"))
	zw.Close()

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("new zstd writer: %v", err)
	}
	zstdData := enc.EncodeAll([]byte("zstd payload"), nil)
	enc.Close()

	cases := []struct {
		encoding string
		raw      []byte
		want     string
	}{
		{"", []byte("plain"), "plain"},
		{"gzip", gz.Bytes(), "gzip payload"},
		{" GZIP ", gz.Bytes(), "gzip payload"},
		{"zstd", zstdData, "zstd payload"},
	}

	for _, c := range cases {
		got, err := decodeBody(c.encoding, c.raw)
		if err != nil {
			t.Errorf("decodeBody(%q) error: %v", c.encoding, err)
			continue
		}
		if got != c.want {
			t.Errorf("decodeBody(%q) = %q, want %q", c.encoding, got, c.want)
		}
	}
}

func TestDecodeBodyReturnsErrorOnBrokenData(t *testing.T) {
	if _, err := decodeBody("gzip", []byte("not gzip")); err == nil {
		t.Error("损坏的 gzip 数据应返回错误而不是 panic")
	}
}

func TestIsTextual(t *testing.T) {
	textual := []string{"text/html", "application/json", "application/xml", "application/javascript"}
	for _, ct := range textual {
		if !isTextual(ct) {
			t.Errorf("isTextual(%q) = false, want true", ct)
		}
	}
	binary := []string{"", "image/png", "video/mp4", "application/octet-stream"}
	for _, ct := range binary {
		if isTextual(ct) {
			t.Errorf("isTextual(%q) = true, want false", ct)
		}
	}
}

func TestResponseSkipsBinaryBody(t *testing.T) {
	sink := newSink()
	logger := NewRequestLogger(sink)

	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        http.Header{"Content-Type": []string{"image/png"}},
		Body:          io.NopCloser(bytes.NewReader([]byte{0x89, 0x50, 0x4e, 0x47})),
		ContentLength: 4,
		Request:       httptest.NewRequest(http.MethodGet, "http://example.com/a.png", nil),
	}

	logger.Response(resp, "7", 120*time.Millisecond)

	packets := sink.all()
	if len(packets) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(packets))
	}
	got := packets[0].HTTP
	if !strings.HasPrefix(got.Body, "[binary data]") {
		t.Errorf("二进制响应不应读取正文, 得到 %q", got.Body)
	}
	if got.ID != "7" {
		t.Errorf("ID = %q, want %q", got.ID, "7")
	}
	if got.Duration != 120 {
		t.Errorf("Duration = %d, want 120", got.Duration)
	}
}

// 上游失败时代理可能给出没有 Request 的响应，此时不能崩溃
func TestResponseWithoutRequest(t *testing.T) {
	sink := newSink()
	logger := NewRequestLogger(sink)

	logger.Response(&http.Response{StatusCode: 502, Header: http.Header{}}, "1", 0)

	if len(sink.all()) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(sink.all()))
	}
}

func TestRequestKeepsBodyReadable(t *testing.T) {
	sink := newSink()
	logger := NewRequestLogger(sink)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")

	logger.Request(req, "42")

	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"a":1}` {
		t.Errorf("请求体未被还原, 得到 %q", body)
	}
	got := sink.all()[0].HTTP
	if got.Body != `{"a":1}` {
		t.Errorf("记录的请求体 = %q", got.Body)
	}
	if got.ID != "42" {
		t.Errorf("ID = %q, want %q", got.ID, "42")
	}
	if got.HTTPPacketType != models.HTTPPacketType_REQUEST {
		t.Errorf("HTTPPacketType = %d", got.HTTPPacketType)
	}
}

// 请求与响应必须能通过同一个 ID 配对
func TestRequestAndResponseSharePairingID(t *testing.T) {
	sink := newSink()
	logger := NewRequestLogger(sink)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	logger.Request(req, "99")
	logger.Response(&http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Request:    req,
	}, "99", 5*time.Millisecond)

	packets := sink.all()
	if len(packets) != 2 {
		t.Fatalf("期望 2 条记录，得到 %d", len(packets))
	}
	if packets[0].HTTP.ID != packets[1].HTTP.ID {
		t.Errorf("请求与响应 ID 不一致: %q / %q", packets[0].HTTP.ID, packets[1].HTTP.ID)
	}
}

func TestTunnelRecord(t *testing.T) {
	sink := newSink()
	logger := NewRequestLogger(sink)

	logger.Tunnel("weixin.qq.com:443", "3")

	packets := sink.all()
	if len(packets) != 1 {
		t.Fatalf("期望 1 条记录，得到 %d", len(packets))
	}
	got := packets[0].HTTP
	if got.HTTPPacketType != models.HTTPPacketType_TUNNEL {
		t.Errorf("HTTPPacketType = %d, want TUNNEL", got.HTTPPacketType)
	}
	if got.Host != "weixin.qq.com:443" {
		t.Errorf("Host = %q", got.Host)
	}
}
