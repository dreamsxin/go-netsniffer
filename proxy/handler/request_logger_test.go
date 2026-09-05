package handler

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/google/martian/v3"
	"github.com/klauspost/compress/zstd"
)

type recordSink struct {
	mu      sync.Mutex
	packets []*models.Packet
	limit   int64
	mitm    bool
}

func (s *recordSink) Emit(p *models.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, p)
}
func (s *recordSink) MaxBodySize() int64 { return s.limit }
func (s *recordSink) ShouldMITM(string) bool {
	return s.mitm
}
func (s *recordSink) all() []*models.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*models.Packet(nil), s.packets...)
}

func newLogger(sink Sink) *RequestLogger {
	return NewRequestLogger(context.Background(), sink)
}

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
	logger := newLogger(sink)

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
	packets := sink.all()
	if len(packets) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(packets))
	}
	if !strings.HasPrefix(packets[0].HTTP.Body, "[binary data]") {
		t.Errorf("二进制响应不应读取正文, 得到 %q", packets[0].HTTP.Body)
	}
}

// martian 在上游失败时可能给出没有 Request 的响应，此时不能崩溃
func TestModifyResponseWithoutRequest(t *testing.T) {
	sink := &recordSink{limit: 1 << 20}
	logger := newLogger(sink)

	resp := &http.Response{
		StatusCode: 502,
		Header:     http.Header{},
	}
	if err := logger.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse error: %v", err)
	}
	if len(sink.all()) != 1 {
		t.Fatalf("期望投递 1 个报文，得到 %d", len(sink.all()))
	}
}

func TestModifyRequestKeepsBodyReadable(t *testing.T) {
	sink := &recordSink{limit: 1 << 20}
	logger := newLogger(sink)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")

	if err := logger.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"a":1}` {
		t.Errorf("请求体未被还原, 得到 %q", body)
	}
	if sink.all()[0].HTTP.Body != `{"a":1}` {
		t.Errorf("记录的请求体 = %q", sink.all()[0].HTTP.Body)
	}
}

// 命中解密规则时不应接管连接，交由 martian 走 MITM
func TestHandleConnectMITMAllowed(t *testing.T) {
	sink := &recordSink{limit: 1 << 20, mitm: true}
	logger := newLogger(sink)

	req := httptest.NewRequest(http.MethodConnect, "//example.com:443", nil)
	if hijacked := logger.handleConnect(req); hijacked {
		t.Error("命中解密规则时不应接管连接")
	}
	if len(sink.all()) != 0 {
		t.Error("解密路径不应产生隧道记录")
	}
}

// 未命中解密规则时接管连接并做裸转发，数据必须原样通过
func TestHandleConnectTunnelsWhenNotMITM(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	// 不用 httptest.NewRequest：它对非绝对 URL 会把 Host 置为 example.com，
	// 会导致隧道真的连到外网
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: echo.Addr().String()},
		Host:   echo.Addr().String(),
		Header: make(http.Header),
	}
	brw := bufio.NewReadWriter(bufio.NewReader(proxySide), bufio.NewWriter(proxySide))
	_, remove, err := martian.TestContext(req, proxySide, brw)
	if err != nil {
		t.Fatalf("构造 martian 上下文失败: %v", err)
	}
	defer remove()

	sink := &recordSink{limit: 1 << 20, mitm: false}
	logger := newLogger(sink)

	done := make(chan bool, 1)
	go func() { done <- logger.handleConnect(req) }()

	clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(clientSide)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT 响应 = %q, 期望 200", status)
	}
	// 跳过空行
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("读取响应结束行失败: %v", err)
	}

	if _, err := clientSide.Write([]byte("ping\n")); err != nil {
		t.Fatalf("写入隧道失败: %v", err)
	}
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if got != "ping\n" {
		t.Errorf("隧道回显 = %q, want %q", got, "ping\n")
	}

	clientSide.Close()
	if hijacked := <-done; !hijacked {
		t.Error("未命中解密规则时应接管连接")
	}

	packets := sink.all()
	if len(packets) != 1 || packets[0].HTTP.HTTPPacketType != models.HTTPPacketType_TUNNEL {
		t.Errorf("应产生一条隧道记录, 得到 %+v", packets)
	}
}

