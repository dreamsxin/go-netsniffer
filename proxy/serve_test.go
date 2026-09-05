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

func (h *recordHandler) Request(req *http.Request, id string) {
	h.add(record{kind: "request", id: id, host: req.Host})
}

func (h *recordHandler) Response(resp *http.Response, id string, d time.Duration) {
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
	t.Helper()

	srv, err := New("Test CA", h, rules, Options{})
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

	if _, err := New("Test CA", &recordHandler{}, fixedRules(true), Options{}); err == nil {
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

	_, err := New("Test CA", &recordHandler{}, fixedRules(true), Options{
		UpstreamProxy: "http://127.0.0.1:9000",
		ListenPort:    9000,
	})
	if err == nil {
		t.Error("上游代理指向自身端口时应返回错误")
	}
}

func TestUpstreamProxyRejectsInvalidAddress(t *testing.T) {
	useTempCert(t)

	if _, err := New("Test CA", &recordHandler{}, fixedRules(true), Options{
		UpstreamProxy: "not-a-url",
	}); err == nil {
		t.Error("非法上游代理地址应返回错误")
	}
}
