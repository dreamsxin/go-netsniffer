package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
)

type record struct {
	kind     string
	id       string
	host     string
	duration time.Duration
}

type recordHandler struct {
	mu      sync.Mutex
	records []record
}

func (h *recordHandler) Request(req *http.Request, id string, rewritten []string) {
	h.add(record{kind: "request", id: id, host: req.Host})
}

func (h *recordHandler) Response(resp *http.Response, id string, d time.Duration, rewritten []string) {
	h.add(record{kind: "response", id: id, duration: d})
}

func (h *recordHandler) Tunnel(host, id string) {
	h.add(record{kind: "tunnel", id: id, host: host})
}

func (h *recordHandler) add(r record) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
}

func (h *recordHandler) all() []record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]record(nil), h.records...)
}

type fixedRules bool

func (r fixedRules) ShouldMITM(string) bool { return bool(r) }

// noRewrite 在不关心改包的测试里占位
type noRewrite struct{}

func (noRewrite) ApplyRequest(*http.Request) []string  { return nil }
func (noRewrite) ApplyResponse(*http.Response) []string { return nil }

// localMapper 模拟 Map Local：短路返回本地内容，请求不发到线上
type localMapper struct{ body string }

func (m localMapper) Apply(req *http.Request) (*http.Response, []string) {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(m.body)),
		ContentLength: int64(len(m.body)),
	}, []string{"映射/local"}
}

// remoteMapper 模拟 Map Remote：把请求改指到另一个地址
type remoteMapper struct{ host string }

func (m remoteMapper) Apply(req *http.Request) (*http.Response, []string) {
	req.URL.Scheme = "http"
	req.URL.Host = m.host
	return nil, []string{"映射/remote"}
}

// useTempCert 把证书路径指向临时目录并生成一份可用的根证书
func useTempCert(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	crt := filepath.Join(dir, "rootcrt.pem")
	key := filepath.Join(dir, "rootkey.pem")

	oldCrt, oldKey := crtPath, keyPath
	crtPath = func() string { return crt }
	keyPath = func() string { return key }
	t.Cleanup(func() { crtPath, keyPath = oldCrt, oldKey })

	if err := cert.GenerateCA("Test CA", crt, key, time.Hour); err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
}

// startProxy 在随机端口上启动代理并返回其地址
func startProxy(t *testing.T, h Handler, rules Rules) string {
	return startProxyWithHooks(t, Hooks{Handler: h, Rules: rules, Rewriter: noRewrite{}})
}

func startProxyWithHooks(t *testing.T, hooks Hooks) string {
	t.Helper()

	srv, err := New("Test CA", hooks, Options{})
	if err != nil {
		t.Fatalf("创建代理失败: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	go srv.Serve(l)
	t.Cleanup(func() {
		srv.Close()
		l.Close()
	})
	return l.Addr().String()
}

func TestNewRequiresCert(t *testing.T) {
	dir := t.TempDir()
	oldCrt, oldKey := crtPath, keyPath
	crtPath = func() string { return filepath.Join(dir, "missing.pem") }
	keyPath = func() string { return filepath.Join(dir, "missing.key") }
	defer func() { crtPath, keyPath = oldCrt, oldKey }()

	if _, err := New("Test CA", Hooks{Handler: &recordHandler{}, Rules: fixedRules(true), Rewriter: noRewrite{}}, Options{}); err == nil {
		t.Error("证书缺失时应返回错误")
	}
}

func TestCertExists(t *testing.T) {
	useTempCert(t)
	if !CertExists() {
		t.Error("生成证书后 CertExists 应为 true")
	}
}

// 明文 HTTP 请求应被完整记录，且请求与响应共用同一个配对 ID
func TestProxyRecordsHTTPRoundTrip(t *testing.T) {
	useTempCert(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "hello")
	}))
	defer origin.Close()

	h := &recordHandler{}
	addr := startProxy(t, h, fixedRules(true))

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Errorf("响应体 = %q, want %q", body, "hello")
	}

	records := h.all()
	var req, res *record
	for i := range records {
		switch records[i].kind {
		case "request":
			req = &records[i]
		case "response":
			res = &records[i]
		}
	}
	if req == nil || res == nil {
		t.Fatalf("请求与响应都应被记录, 得到 %+v", records)
	}
	if req.id != res.id || req.id == "" {
		t.Errorf("配对 ID 不一致: %q / %q", req.id, res.id)
	}
}

// 未命中解密规则的 CONNECT 应原样转发，并产生一条隧道记录
func TestProxyTunnelsWhenRuleDenies(t *testing.T) {
	useTempCert(t)

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

	h := &recordHandler{}
	addr := startProxy(t, h, fixedRules(false))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	target := echo.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT 响应 = %q, 期望 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读取响应头失败: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("写入隧道失败: %v", err)
	}
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if got != "ping\n" {
		t.Errorf("隧道回显 = %q, want %q", got, "ping\n")
	}

	var tunnels int
	for _, r := range h.all() {
		if r.kind == "tunnel" {
			tunnels++
		}
	}
	if tunnels != 1 {
		t.Errorf("应产生 1 条隧道记录, 得到 %d", tunnels)
	}
}

func TestUpstreamProxyRejectsSelf(t *testing.T) {
	useTempCert(t)

	_, err := New("Test CA", Hooks{Handler: &recordHandler{}, Rules: fixedRules(true), Rewriter: noRewrite{}}, Options{
		UpstreamProxy: "http://127.0.0.1:9000",
		ListenPort:    9000,
	})
	if err == nil {
		t.Error("上游代理指向自身端口时应返回错误")
	}
}

func TestUpstreamProxyRejectsInvalidAddress(t *testing.T) {
	useTempCert(t)

	if _, err := New("Test CA", Hooks{Handler: &recordHandler{}, Rules: fixedRules(true), Rewriter: noRewrite{}}, Options{
		UpstreamProxy: "not-a-url",
	}); err == nil {
		t.Error("非法上游代理地址应返回错误")
	}
}

// Map Local 命中时请求不该发到线上，但响应仍要被记录下来。
// 后者依赖 goproxy 对短路响应也会走响应处理链，值得用测试锁住。
func TestMapLocalShortCircuitsAndStillRecords(t *testing.T) {
	useTempCert(t)

	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "来自线上")
	}))
	defer origin.Close()

	h := &recordHandler{}
	addr := startProxyWithHooks(t, Hooks{
		Handler: h, Rules: fixedRules(true), Rewriter: noRewrite{},
		Mapper: localMapper{body: "来自本地"},
	})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "来自本地" {
		t.Errorf("响应体 = %q, want %q", body, "来自本地")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("Map Local 命中时不该访问线上, 实际访问 %d 次", n)
	}

	var hasRequest, hasResponse bool
	for _, r := range h.all() {
		switch r.kind {
		case "request":
			hasRequest = true
		case "response":
			hasResponse = true
		}
	}
	if !hasRequest || !hasResponse {
		t.Errorf("请求与响应都应被记录, 得到 %+v", h.all())
	}
}

// Map Remote 应把请求转到新目标，客户端不知情
func TestMapRemoteRedirectsToNewTarget(t *testing.T) {
	useTempCert(t)

	var mappedHits, originHits atomic.Int64
	mapped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mappedHits.Add(1)
		fmt.Fprint(w, "来自映射目标")
	}))
	defer mapped.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		fmt.Fprint(w, "来自原始目标")
	}))
	defer origin.Close()

	mappedURL, _ := url.Parse(mapped.URL)
	addr := startProxyWithHooks(t, Hooks{
		Handler: &recordHandler{}, Rules: fixedRules(true), Rewriter: noRewrite{},
		Mapper: remoteMapper{host: mappedURL.Host},
	})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "来自映射目标" {
		t.Errorf("响应体 = %q", body)
	}
	if mappedHits.Load() != 1 || originHits.Load() != 0 {
		t.Errorf("映射目标应被访问 1 次、原目标 0 次, 实际 %d / %d",
			mappedHits.Load(), originHits.Load())
	}
}
