// Package replay 重新发送已抓取的请求，用于验证接口行为或改包调试。
//
// 请求特意通过本机代理发出，这样重放的请求与响应会走一遍正常的抓取流程，
// 直接出现在界面列表里；否则用户看不到重放结果。
package replay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hopByHopHeaders 是重放时必须去掉的头。
// 长度与连接管理由 net/http 自己处理，照抄原值会导致请求不合法。
var hopByHopHeaders = map[string]bool{
	"content-length":    true,
	"connection":        true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"upgrade":           true,
	"host":              true,
	"proxy-connection":  true,
}

// Request 是一次重放的内容，可以是原记录也可以是用户改过的版本。
type Request struct {
	Method string
	URL    string
	Header http.Header
	Body   string
}

// Result 是重放得到的结果概要，详细内容由抓取流程记录到列表里。
type Result struct {
	StatusCode int
	Status     string
	Duration   time.Duration
}

// Client 通过指定的本机代理端口发送请求。
type Client struct {
	client *http.Client
}

// New 构造一个经由本机代理发送的客户端。
func New(proxyPort int) (*Client, error) {
	if proxyPort <= 0 || proxyPort > 65535 {
		return nil, fmt.Errorf("代理端口无效: %d", proxyPort)
	}
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	if err != nil {
		return nil, err
	}
	return newWithProxy(proxyURL), nil
}

func newWithProxy(proxyURL *url.URL) *Client {
	return &Client{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				// 目标证书是本代理用自签 CA 现签的，必须跳过校验
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				TLSHandshakeTimeout: 30 * time.Second,
			},
			Timeout: 60 * time.Second,
			// 不自动跟随跳转：重放要如实反映这一个请求的结果
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Send 发送重放请求。返回结果仅用于即时反馈，
// 完整的请求与响应会由代理的抓取流程记录下来。
func (c *Client) Send(ctx context.Context, r Request) (Result, error) {
	if r.URL == "" {
		return Result{}, errors.New("重放地址为空")
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return Result{}, fmt.Errorf("构造请求失败: %w", err)
	}
	for k, values := range r.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	// 读空响应体，确保代理侧完整处理并能复用连接
	io.Copy(io.Discard, resp.Body)

	return Result{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Duration:   time.Since(start),
	}, nil
}
