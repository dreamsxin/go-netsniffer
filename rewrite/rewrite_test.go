package rewrite

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
)

func newRequest(method, url string, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	return httptest.NewRequest(method, url, r)
}

func TestApplyRequestSetAndRemoveHeaders(t *testing.T) {
	s := New(`[{
		"Enabled": true,
		"Name": "改 UA",
		"Phase": "request",
		"SetHeaders": {"User-Agent": "custom-agent"},
		"RemoveHeaders": ["If-None-Match"]
	}]`)

	req := newRequest(http.MethodGet, "http://a.com/x", "")
	req.Header.Set("User-Agent", "original")
	req.Header.Set("If-None-Match", `"etag"`)

	applied := s.ApplyRequest(req)
	if len(applied) != 1 || applied[0] != "改 UA" {
		t.Fatalf("命中规则 = %v, want [改 UA]", applied)
	}
	if got := req.Header.Get("User-Agent"); got != "custom-agent" {
		t.Errorf("User-Agent = %q", got)
	}
	if got := req.Header.Get("If-None-Match"); got != "" {
		t.Errorf("If-None-Match 应被删除, 得到 %q", got)
	}
}

// 停用的规则不能生效，否则"临时关掉"就没有意义
func TestDisabledRuleIsIgnored(t *testing.T) {
	s := New(`[{"Enabled": false, "Name": "x", "SetHeaders": {"X-Test": "1"}}]`)

	req := newRequest(http.MethodGet, "http://a.com/", "")
	if applied := s.ApplyRequest(req); len(applied) != 0 {
		t.Errorf("停用规则不应命中, 得到 %v", applied)
	}
	if req.Header.Get("X-Test") != "" {
		t.Error("停用规则不应改动请求头")
	}
	if s.Enabled() {
		t.Error("没有启用的规则时 Enabled 应为 false")
	}
}

func TestURLRegexAndMethodFilter(t *testing.T) {
	s := New(`[{
		"Enabled": true,
		"Name": "只改特定接口的 POST",
		"Phase": "request",
		"URLRegex": "a\\.com/api",
		"Method": "post",
		"SetHeaders": {"X-Hit": "1"}
	}]`)

	// URL 与方法都匹配
	hit := newRequest(http.MethodPost, "http://a.com/api/create", "")
	if applied := s.ApplyRequest(hit); len(applied) != 1 {
		t.Errorf("应命中, 得到 %v", applied)
	}

	// 方法不匹配（大小写不敏感对比，这里用 GET）
	missMethod := newRequest(http.MethodGet, "http://a.com/api/create", "")
	if applied := s.ApplyRequest(missMethod); len(applied) != 0 {
		t.Errorf("方法不匹配不应命中, 得到 %v", applied)
	}

	// URL 不匹配
	missURL := newRequest(http.MethodPost, "http://a.com/other", "")
	if applied := s.ApplyRequest(missURL); len(applied) != 0 {
		t.Errorf("URL 不匹配不应命中, 得到 %v", applied)
	}
}

// request 阶段的规则不能作用到响应上
func TestPhaseIsolation(t *testing.T) {
	s := New(`[{"Enabled": true, "Name": "req", "Phase": "request", "SetHeaders": {"X-Req": "1"}}]`)

	resp := &http.Response{Header: http.Header{}}
	if applied := s.ApplyResponse(resp); len(applied) != 0 {
		t.Errorf("request 阶段规则不应作用于响应, 得到 %v", applied)
	}
	if resp.Header.Get("X-Req") != "" {
		t.Error("响应头被 request 阶段规则改动了")
	}
}

func TestApplyResponseStatusAndBody(t *testing.T) {
	s := New(`[{
		"Enabled": true,
		"Name": "改状态码与正文",
		"Phase": "response",
		"StatusCode": 500,
		"Replacements": [{"From": "\"code\":0", "To": "\"code\":1"}]
	}]`)

	body := `{"code":0,"msg":"ok"}`
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Length", "21")

	if applied := s.ApplyResponse(resp); len(applied) != 1 {
		t.Fatalf("应命中一条规则, 得到 %v", applied)
	}
	if resp.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", resp.StatusCode)
	}
	if resp.Status != "500 Internal Server Error" {
		t.Errorf("Status = %q", resp.Status)
	}

	got, _ := io.ReadAll(resp.Body)
	want := `{"code":1,"msg":"ok"}`
	if string(got) != want {
		t.Errorf("正文 = %q, want %q", got, want)
	}
	// 长度必须同步，不一致会让连接挂死
	if resp.ContentLength != int64(len(want)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(want))
	}
	if resp.Header.Get("Content-Length") != "21" {
		t.Errorf("Content-Length 头 = %q, want 21", resp.Header.Get("Content-Length"))
	}
}

// 压缩过的正文要先解压再替换，并去掉 Content-Encoding
func TestApplyResponseDecompressesBeforeReplace(t *testing.T) {
	s := New(`[{
		"Enabled": true,
		"Name": "替换压缩正文",
		"Phase": "response",
		"Replacements": [{"From": "hello", "To": "world"}]
	}]`)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("say hello"))
	zw.Close()

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Encoding": []string{"gzip"}},
		Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
	}

	if applied := s.ApplyResponse(resp); len(applied) != 1 {
		t.Fatalf("应命中一条规则, 得到 %v", applied)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("解压后 Content-Encoding 应被删除, 得到 %q", got)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "say world" {
		t.Errorf("正文 = %q, want %q", got, "say world")
	}
}

func TestApplyRequestBodyReplacement(t *testing.T) {
	s := New(`[{
		"Enabled": true,
		"Name": "改请求体",
		"Phase": "request",
		"Replacements": [{"From": "old", "To": "new"}]
	}]`)

	req := newRequest(http.MethodPost, "http://a.com/x", `{"v":"old"}`)
	if applied := s.ApplyRequest(req); len(applied) != 1 {
		t.Fatalf("应命中一条规则, 得到 %v", applied)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != `{"v":"new"}` {
		t.Errorf("请求体 = %q", got)
	}
	if req.ContentLength != int64(len(`{"v":"new"}`)) {
		t.Errorf("ContentLength = %d", req.ContentLength)
	}
}

// 解析失败时必须保留上一次生效的规则，并把原因暴露出来
func TestLoadKeepsPreviousRulesOnError(t *testing.T) {
	s := New(`[{"Enabled": true, "Name": "ok", "SetHeaders": {"X-A": "1"}}]`)

	if err := s.Load("not json"); err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
	if s.ParseError() == "" {
		t.Error("ParseError 应记录失败原因")
	}

	req := newRequest(http.MethodGet, "http://a.com/", "")
	if applied := s.ApplyRequest(req); len(applied) != 1 {
		t.Errorf("解析失败后旧规则应继续生效, 得到 %v", applied)
	}
}

func TestLoadRejectsInvalidRegex(t *testing.T) {
	s := New("")
	if err := s.Load(`[{"Enabled": true, "Name": "bad", "URLRegex": "["}]`); err == nil {
		t.Error("非法正则应返回错误")
	}
}

// 空配置等于不改包，属于正常状态而不是错误
func TestLoadEmptyIsNotError(t *testing.T) {
	s := New(`[{"Enabled": true, "Name": "x", "SetHeaders": {"X": "1"}}]`)
	if err := s.Load("   "); err != nil {
		t.Errorf("空配置不应报错: %v", err)
	}
	if s.Enabled() {
		t.Error("空配置后不应还有生效规则")
	}
	if s.ParseError() != "" {
		t.Errorf("空配置不应留下错误: %q", s.ParseError())
	}
}

func TestDefaultRulesAreValidAndDisabled(t *testing.T) {
	s := New(models.DefaultRewriteRules)
	if s.ParseError() != "" {
		t.Errorf("默认示例规则应能正常解析: %s", s.ParseError())
	}
	// 默认全部停用，避免用户一启动就意外改动流量
	if s.Enabled() {
		t.Error("默认示例规则应全部处于停用状态")
	}
}
