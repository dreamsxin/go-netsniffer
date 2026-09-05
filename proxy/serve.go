package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/dreamsxin/go-netsniffer/paths"
	"github.com/elazarl/goproxy"
)

// Handler 接收代理观察到的流量。实现必须是非阻塞的，
// 任何耗时操作都会直接拖慢被代理的请求。
type Handler interface {
	// Request 记录一个请求，id 用于与响应配对，rewritten 是命中的改包规则名
	Request(req *http.Request, id string, rewritten []string)
	// Response 记录一个响应及其往返耗时
	Response(resp *http.Response, id string, duration time.Duration, rewritten []string)
	// Tunnel 记录一个按规则未解密、仅做转发的连接
	Tunnel(host, id string)
}

// Rules 决定某个域名的 HTTPS 是否需要解密。
type Rules interface {
	ShouldMITM(host string) bool
}

// Rewriter 按规则改写请求与响应，返回命中的规则名。
// 改写发生在记录之前，因此列表里看到的就是真正发到线上的内容。
type Rewriter interface {
	ApplyRequest(req *http.Request) []string
	ApplyResponse(resp *http.Response) []string
}

// WSObserver 观察 WebSocket 帧。
//
// goproxy 检测到 101 后会把 resp.Body 断言成 io.ReadWriter 直接对拷，
// 中间没有回调，因此唯一的注入点是在响应处理阶段替换 resp.Body。
type WSObserver interface {
	// WrapWebSocket 按需替换 101 响应的 Body 以旁路解析帧
	WrapWebSocket(resp *http.Response, id string)
}

// Breaker 是断点。Intercept 会阻塞当前连接的 goroutine 直到界面处理或超时，
// 返回 abort 时调用方应直接返回错误响应而不继续转发。
type Breaker interface {
	InterceptRequest(req *http.Request, id string) models.BreakpointAction
	InterceptResponse(resp *http.Response, id string) models.BreakpointAction
	// ReleaseAll 在代理停止时放行所有等待中的请求，避免 goroutine 泄漏
	ReleaseAll()
}

// Options 控制代理的网络行为，零值表示使用默认值。
type Options struct {
	// 上游代理地址，形如 http://127.0.0.1:7890，留空表示直连
	UpstreamProxy string
	// 本地监听端口，用于识别并拒绝把自己设置为上游代理
	ListenPort int
	// AllowHTTP2 允许与客户端协商 HTTP/2，关闭时统一降级为 HTTP/1.1
	AllowHTTP2 bool
}

// NewDownloadClient 构造一个与代理共享网络配置的 http.Client，
// 供下载资源时使用，从而复用上游代理与超时设置。
func NewDownloadClient(upstreamProxy string) *http.Client {
	tr := newTransport()
	if upstreamProxy != "" {
		if u, err := url.Parse(upstreamProxy); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	// 不设整体超时：大文件下载可能持续很久，取消由 context 负责
	return &http.Client{Transport: tr}
}

const (
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 30 * time.Second
	responseHeadTimeout = 60 * time.Second
	idleConnTimeout     = 30 * time.Second
	readHeaderTimeout   = 30 * time.Second
	// 根证书要手工安装到系统，有效期给足 10 年，避免用户每年重装一次
	certValidity = 10 * 365 * 24 * time.Hour
)

// 证书路径以变量形式暴露，便于测试替换为临时目录
var (
	keyPath = paths.KeyFile
	crtPath = paths.CertFile
)

// CertExists 判断根证书与私钥是否都已生成，供界面展示状态。
func CertExists() bool {
	if _, err := os.Stat(crtPath()); err != nil {
		return false
	}
	_, err := os.Stat(keyPath())
	return err == nil
}

// Server 把 goproxy 与承载它的 http.Server 组合起来，
// 并跟踪未解密的隧道连接，以便停止服务时能一并断开。
type Server struct {
	proxy   *goproxy.ProxyHttpServer
	http    *http.Server
	breaker Breaker

	mu      sync.Mutex
	closed  bool
	tunnels map[net.Conn]struct{}
}

func New(authorityName string, h Handler, rules Rules, rewriter Rewriter, breaker Breaker, ws WSObserver, opts Options) (*Server, error) {
	ca, err := loadCA()
	if err != nil {
		return nil, err
	}

	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	gp.Tr = newTransport()
	gp.AllowHTTP2 = opts.AllowHTTP2
	// 缓存按域名签发的证书，否则每个新域名都要做一次 RSA 签名
	gp.CertStore = &certCache{}

	s := &Server{
		proxy:   gp,
		breaker: breaker,
		tunnels: make(map[net.Conn]struct{}),
	}
	s.http = &http.Server{
		Handler:           gp,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	if err := s.setUpstream(opts); err != nil {
		return nil, err
	}

	tlsConfig := goproxy.TLSConfigFromCA(ca)
	mitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}

	// goproxy 原生支持在 CONNECT 阶段决定是否解密：
	// 命中规则的走 MITM，其余原样转发，避免破坏做了证书固定的客户端。
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if rules.ShouldMITM(host) {
			return mitm, host
		}
		h.Tunnel(host, sessionID(ctx))
		return &goproxy.ConnectAction{Action: goproxy.ConnectAccept}, host
	})

	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		// 先改写再记录，列表里看到的就是真正发到线上的内容
		var rewritten []string
		if rewriter != nil {
			rewritten = rewriter.ApplyRequest(req)
		}

		// 断点在改写之后：界面上看到并可编辑的是改写后的内容
		if breaker != nil {
			if breaker.InterceptRequest(req, sessionID(ctx)) == models.BreakpointAbort {
				h.Request(req, sessionID(ctx), rewritten)
				return req, abortResponse(req, "请求已被断点中止")
			}
		}

		h.Request(req, sessionID(ctx), rewritten)
		return req, nil
	})

	gp.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		var duration time.Duration
		if start, ok := ctx.UserData.(time.Time); ok {
			duration = time.Since(start)
		}
		var rewritten []string
		if rewriter != nil {
			rewritten = rewriter.ApplyResponse(resp)
		}

		if breaker != nil {
			if breaker.InterceptResponse(resp, sessionID(ctx)) == models.BreakpointAbort {
				h.Response(resp, sessionID(ctx), duration, rewritten)
				var req *http.Request
				if resp != nil {
					req = resp.Request
				}
				return abortResponse(req, "响应已被断点中止")
			}
		}

		h.Response(resp, sessionID(ctx), duration, rewritten)

		// 记录之后再包装 Body：101 响应之后才是帧流，
		// 包装必须发生在 goproxy 断言 io.ReadWriter 之前
		if ws != nil {
			ws.WrapWebSocket(resp, sessionID(ctx))
		}
		return resp
	})

	return s, nil
}

// abortResponse 构造断点中止时返回给客户端的响应。
// 用 502 而不是伪造成功，避免客户端把中止误当成正常结果。
func abortResponse(req *http.Request, reason string) *http.Response {
	body := reason
	return &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// sessionID 用 goproxy 的会话号把请求与响应关联起来。
func sessionID(ctx *goproxy.ProxyCtx) string {
	if ctx == nil {
		return ""
	}
	return strconv.FormatInt(ctx.Session, 10)
}

func (s *Server) Serve(l net.Listener) error {
	return s.http.Serve(l)
}

// Close 关闭监听与所有在途连接，包括被 goproxy 劫持的隧道连接。
// http.Server.Close 不会处理已劫持的连接，所以隧道要自己跟踪并关闭。
func (s *Server) Close() error {
	// 先放行被断点挂住的请求，否则它们会阻塞到超时才退出
	if s.breaker != nil {
		s.breaker.ReleaseAll()
	}

	s.mu.Lock()
	s.closed = true
	tunnels := make([]net.Conn, 0, len(s.tunnels))
	for c := range s.tunnels {
		tunnels = append(tunnels, c)
	}
	s.tunnels = make(map[net.Conn]struct{})
	s.mu.Unlock()

	err := s.http.Close()
	for _, c := range tunnels {
		c.Close()
	}
	return err
}

func (s *Server) trackTunnel(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.tunnels[c] = struct{}{}
	return true
}

func (s *Server) untrackTunnel(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, c)
}

// trackedConn 在关闭时把自己从隧道集合里摘掉，避免集合无限增长。
type trackedConn struct {
	net.Conn
	srv  *Server
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.srv.untrackTunnel(c.Conn) })
	return c.Conn.Close()
}

func (s *Server) setUpstream(opts Options) error {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	base := func(network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}

	if opts.UpstreamProxy != "" {
		u, err := url.Parse(opts.UpstreamProxy)
		if err != nil {
			return fmt.Errorf("上游代理地址无效: %w", err)
		}
		if u.Host == "" {
			return errors.New("上游代理地址无效: 缺少主机与端口")
		}
		// 上游代理指向自身会导致请求无限自环
		if opts.ListenPort > 0 {
			if _, port, err := net.SplitHostPort(u.Host); err == nil &&
				port == strconv.Itoa(opts.ListenPort) {
				return errors.New("上游代理不能指向本程序自身的监听端口")
			}
		}
		s.proxy.Tr.Proxy = http.ProxyURL(u)
		base = s.proxy.NewConnectDialToProxy(opts.UpstreamProxy)
	}

	s.proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		c, err := base(network, addr)
		if err != nil {
			return nil, err
		}
		if !s.trackTunnel(c) {
			c.Close()
			return nil, errors.New("代理服务已停止")
		}
		return &trackedConn{Conn: c, srv: s}, nil
	}
	return nil
}

func newTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// MITM 代理不校验上游证书，否则证书链有瑕疵的站点会整体不可访问
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeadTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   8,
	}
}

// certCache 实现 goproxy.CertStorage，按域名缓存已签发的证书。
type certCache struct {
	m sync.Map
}

func (c *certCache) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	if v, ok := c.m.Load(hostname); ok {
		return v.(*tls.Certificate), nil
	}
	crt, err := gen()
	if err != nil {
		return nil, err
	}
	actual, _ := c.m.LoadOrStore(hostname, crt)
	return actual.(*tls.Certificate), nil
}

func loadCA() (*tls.Certificate, error) {
	if _, err := os.Stat(crtPath()); err != nil {
		return nil, errors.New("根证书不存在，请先生成并安装证书")
	}

	ca, err := tls.LoadX509KeyPair(crtPath(), keyPath())
	if err != nil {
		return nil, fmt.Errorf("证书加载失败，请重新生成证书: %w", err)
	}
	if len(ca.Certificate) == 0 {
		return nil, errors.New("证书加载失败: 内容为空，请重新生成证书")
	}

	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("证书解析失败: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("根证书已于 %s 过期，请重新生成并安装证书",
			leaf.NotAfter.Format(time.DateOnly))
	}
	ca.Leaf = leaf
	return &ca, nil
}

func GenerateCert(authorityName string) error {
	return cert.GenerateCA(authorityName, crtPath(), keyPath(), certValidity)
}

// InstallCert 安装根证书，返回实际写入的存储范围（machine 或 user）。
func InstallCert(authorityName string) (string, error) {
	if _, err := os.Stat(crtPath()); err != nil {
		return "", errors.New("根证书不存在，请先生成证书")
	}
	return cert.InstallCert(crtPath())
}

// TrustedScopes 返回根证书当前被系统信任的存储范围。
func TrustedScopes(authorityName string) []string {
	return cert.TrustedScopes(authorityName)
}

// CertPath 返回根证书路径，供界面提示用户手工导入。
func CertPath() string { return crtPath() }

// CertNotAfter 返回根证书的有效期截止日期，无法读取时返回空串。
func CertNotAfter() string {
	ca, err := loadCA()
	if err != nil || ca.Leaf == nil {
		return ""
	}
	return ca.Leaf.NotAfter.Format(time.DateOnly)
}

func UninstallCert(authorityName string) error {
	return cert.UninstallCert(authorityName)
}
