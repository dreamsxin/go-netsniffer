package replay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newTestClient 让请求经过一个充当"代理"的测试服务器，
// 以此验证重放确实是通过代理发出的
func newTestClient(t *testing.T, proxy *httptest.Server) *Client {
	t.Helper()
	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("解析代理地址失败: %v", err)
	}
	return newWithProxy(u)
}

func TestSendGoesThroughProxy(t *testing.T) {
	var gotURL string
	var gotMethod string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 走代理时请求行携带绝对 URL
		gotURL = r.URL.String()
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer proxy.Close()

	res, err := newTestClient(t, proxy).Send(context.Background(), Request{
		Method: http.MethodGet,
		URL:    "http://example.com/api?a=1",
	})
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s", gotMethod)
	}
	if gotURL != "http://example.com/api?a=1" {
		t.Errorf("代理收到的 URL = %q", gotURL)
	}
}

func TestSendReplaysBodyAndHeaders(t *testing.T) {
	var gotBody string
	var gotHeader http.Header
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotHeader = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
	}))
	defer proxy.Close()

	header := http.Header{}
	header.Set("X-Token", "abc")
	header.Set("Content-Type", "application/json")
	// 这些头必须由 net/http 自己重算，照抄会让请求不合法
	header.Set("Content-Length", "999")
	header.Set("Connection", "close")

	res, err := newTestClient(t, proxy).Send(context.Background(), Request{
		Method: http.MethodPost,
		URL:    "http://example.com/create",
		Header: header,
		Body:   `{"a":1}`,
	})
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want 201", res.StatusCode)
	}
	if gotBody != `{"a":1}` {
		t.Errorf("body = %q", gotBody)
	}
	if gotHeader.Get("X-Token") != "abc" {
		t.Errorf("自定义头丢失: %q", gotHeader.Get("X-Token"))
	}
	if gotHeader.Get("Content-Length") == "999" {
		t.Error("Content-Length 应由 net/http 重算，不能照抄原值")
	}
}

// 重放要如实反映这一个请求的结果，不能自动跟随跳转
func TestSendDoesNotFollowRedirect(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://example.com/other")
		w.WriteHeader(http.StatusFound)
	}))
	defer proxy.Close()

	res, err := newTestClient(t, proxy).Send(context.Background(), Request{
		URL: "http://example.com/start",
	})
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if res.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302", res.StatusCode)
	}
}

func TestSendRejectsEmptyURL(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer proxy.Close()

	if _, err := newTestClient(t, proxy).Send(context.Background(), Request{}); err == nil {
		t.Error("空地址应返回错误")
	}
}

func TestNewValidatesPort(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Error("端口 0 应返回错误")
	}
	if _, err := New(70000); err == nil {
		t.Error("越界端口应返回错误")
	}
	if _, err := New(9000); err != nil {
		t.Errorf("合法端口不应报错: %v", err)
	}
}
