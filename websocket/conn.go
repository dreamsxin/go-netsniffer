package websocket

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/dreamsxin/go-netsniffer/models"
)

// IsHandshake 判断该响应是否是成功的 WebSocket 握手。
func IsHandshake(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return false
	}
	return headerContains(resp.Header, "Connection", "Upgrade") &&
		headerContains(resp.Header, "Upgrade", "websocket")
}

func headerContains(header http.Header, name, value string) bool {
	for _, v := range header.Values(name) {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

// HasDeflateExtension 判断握手是否协商了 permessage-deflate。
// 协商后载荷是 deflate 流，需要跨帧维护上下文才能解开，目前只做标记。
func HasDeflateExtension(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	for _, v := range resp.Header.Values("Sec-WebSocket-Extensions") {
		if strings.Contains(strings.ToLower(v), "permessage-deflate") {
			return true
		}
	}
	return false
}

// Conn 包裹 101 响应的 Body，在转发路径上旁路解析双向帧。
//
// goproxy 检测到 101 后会把 resp.Body 断言成 io.ReadWriter 直接对拷
// （见 goproxy 的 http.go 与 https.go），中间没有任何回调。
// 因此这里通过替换 resp.Body 注入：字节原样透传，只额外喂给解析器。
type Conn struct {
	inner io.ReadWriteCloser
	// recv 与 send 各自维护解析状态，两个方向的帧流是独立的
	recv *Parser
	send *Parser
	// mu 只保护解析器：Read 与 Write 由 goproxy 的两个 goroutine 并发调用
	mu sync.Mutex
}

// Wrap 用 Conn 替换 resp.Body。
// body 必须同时可读可写（101 响应的 Body 满足这一点），否则返回原值不做包装。
func Wrap(body io.ReadCloser, connID, url string, maxCapture int, emit func(models.WSFrame)) io.ReadCloser {
	rw, ok := body.(io.ReadWriteCloser)
	if !ok {
		// 拿不到写端就无法转发客户端数据，此时绝不能替换 Body
		return body
	}

	decorate := func(f models.WSFrame) {
		f.ConnID, f.URL = connID, url
		emit(f)
	}
	return &Conn{
		inner: rw,
		recv:  NewParser(models.WSDirectionRecv, maxCapture, decorate),
		send:  NewParser(models.WSDirectionSend, maxCapture, decorate),
	}
}

// Read 是服务端 -> 客户端方向。
// 先转发再解析，解析器出问题也不会影响已经返回的数据。
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.recv.Feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

// Write 是客户端 -> 服务端方向。
func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.inner.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.send.Feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *Conn) Close() error { return c.inner.Close() }
