package handler

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/klauspost/compress/zstd"
)

type recordSink struct {
	packets []*models.Packet
	limit   int64
}

func (s *recordSink) Emit(p *models.Packet) { s.packets = append(s.packets, p) }
func (s *recordSink) MaxBodySize() int64    { return s.limit }

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

func TestModifyResponseSkipsBinaryBody(t *testing.T) {
	sink := &recordSink{limit: 1 << 20}
	logger := NewRequestLogger(sink)

	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        http.Header{"Content-Type": []string{"image/png"}},
		Body:          io.NopCloser(bytes.NewReader([]byte{0x89, 0x50, 0x4e, 0x47})),
		ContentLength: 4,
		Request:       httptest.NewRequest(http.MethodGet, "http://example.com/a.png", nil),
	}

	if err := logger.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse error: %v", err)
	}
	if len(sink.packets) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(sink.packets))
	}
	if !strings.HasPrefix(sink.packets[0].HTTP.Body, "[binary data]") {
		t.Errorf("二进制响应不应读取正文, 得到 %q", sink.packets[0].HTTP.Body)
	}
}

// martian 在上游失败时可能给出没有 Request 的响应，此时不能崩溃
func TestModifyResponseWithoutRequest(t *testing.T) {
	sink := &recordSink{limit: 1 << 20}
	logger := NewRequestLogger(sink)

	resp := &http.Response{
		StatusCode: 502,
		Header:     http.Header{},
	}
	if err := logger.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse error: %v", err)
	}
	if len(sink.packets) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(sink.packets))
	}
}

func TestModifyRequestKeepsBodyReadable(t *testing.T) {
	sink := &recordSink{limit: 1 << 20}
	logger := NewRequestLogger(sink)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")

	if err := logger.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"a":1}` {
		t.Errorf("请求体未被还原, 得到 %q", body)
	}
	if sink.packets[0].HTTP.Body != `{"a":1}` {
		t.Errorf("记录的请求体 = %q", sink.packets[0].HTTP.Body)
	}
}
