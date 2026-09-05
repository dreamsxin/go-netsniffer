package handler

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/google/martian/v3"
)

const tunnelDialTimeout = 30 * time.Second

// handleConnect 处理 CONNECT 请求。
//
// martian 的 MITM 是全局开关（proxy.go 中只判断 p.mitm != nil），
// 无法按域名区分。但它在 MITM 之前会先调用请求修改器，并检查会话是否被劫持，
// 因此这里对不需要解密的域名接管连接、做裸 TCP 转发，实现按规则解密。
//
// 返回 true 表示连接已被接管，调用方不应再做其他处理。
func (r *RequestLogger) handleConnect(req *http.Request) bool {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" || r.sink.ShouldMITM(host) {
		return false
	}

	mctx := martian.NewContext(req)
	if mctx == nil {
		// 拿不到会话就无法接管，退回默认的解密流程
		return false
	}
	conn, brw, err := mctx.Session().Hijack()
	if err != nil {
		log.Println("接管 CONNECT 连接失败:", err)
		return false
	}
	defer conn.Close()

	r.sink.Emit(&models.Packet{
		PacketType: models.PacketType_HTTP,
		HTTP: models.HTTPPacket{
			ID:             mctx.ID(),
			HTTPPacketType: models.HTTPPacketType_TUNNEL,
			Date:           time.Now().Format(time.DateTime),
			Method:         req.Method,
			Host:           host,
			URL:            host,
			Body:           "[tunnel] 按规则未解密，仅转发",
		},
	})

	target, err := net.DialTimeout("tcp", withDefaultPort(host, "443"), tunnelDialTimeout)
	if err != nil {
		fmt.Fprintf(brw, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		brw.Flush()
		return true
	}
	defer target.Close()

	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return true
	}
	if err := brw.Flush(); err != nil {
		return true
	}

	pipe(r.ctx, conn, target, brw.Reader)
	return true
}

// pipe 在客户端与目标之间双向转发，任意一端结束或 ctx 取消时关闭双方，
// 确保两个方向的拷贝都能返回，不会残留 goroutine。
func pipe(ctx context.Context, client net.Conn, target net.Conn, clientReader io.Reader) {
	var once sync.Once
	done := make(chan struct{})
	stop := func() {
		once.Do(func() {
			client.Close()
			target.Close()
		})
	}

	// 代理停止时主动断开长连接隧道
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()

	go func() {
		// 从 bufio.Reader 读，客户端可能已有数据被缓冲
		io.Copy(target, clientReader)
		stop()
	}()

	io.Copy(client, target)
	stop()
	close(done)
}

// withDefaultPort 补全缺省端口。CONNECT 的目标通常已带端口，但不保证。
func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}
