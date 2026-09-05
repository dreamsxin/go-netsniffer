// Package breakpoint 实现请求/响应断点：命中后把流量挂住，等界面处理后再放行。
//
// 断点会真的阻塞被代理的连接，属于调试用途，默认关闭。
// 两条安全底线：
//   - 必须有超时兜底，否则忘了处理就等于把那条连接永久挂死；
//   - 代理停止时必须放行所有等待中的请求，否则 goroutine 会泄漏。
package breakpoint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/httpbody"
	"github.com/dreamsxin/go-netsniffer/models"
)

// maxDisplayBody 是拿给界面展示与编辑的正文上限
const maxDisplayBody = 1 << 20 // 1MB

// 超时秒数的合理区间，避免填 0 变成永久挂住
const (
	minTimeoutSeconds = 1
	maxTimeoutSeconds = 600
)

type waiter struct {
	ch  chan models.BreakpointResolution
	hit models.BreakpointHit
	// deadline 用于界面展示剩余时间
	deadline time.Time
}

// Manager 管理断点配置与待处理队列，并发安全。
type Manager struct {
	mu      sync.RWMutex
	cfg     models.BreakpointConfig
	urlRe   *regexp.Regexp
	waiters map[string]*waiter

	// notify 在待处理队列变化时被调用，由上层推送给界面
	notify func()
}

func New(notify func()) *Manager {
	if notify == nil {
		notify = func() {}
	}
	return &Manager{
		cfg:     models.DefaultBreakpointConfig(),
		waiters: make(map[string]*waiter),
		notify:  notify,
	}
}

// Load 更新配置。正则非法时保留原配置。
func (m *Manager) Load(cfg models.BreakpointConfig) error {
	var re *regexp.Regexp
	if cfg.URLRegex != "" {
		compiled, err := regexp.Compile(cfg.URLRegex)
		if err != nil {
			return fmt.Errorf("断点 URLRegex 无效: %w", err)
		}
		re = compiled
	}

	// 超时必须在合理区间内，0 会让请求永久挂住
	if cfg.TimeoutSeconds < minTimeoutSeconds {
		cfg.TimeoutSeconds = models.DefaultBreakpointConfig().TimeoutSeconds
	}
	if cfg.TimeoutSeconds > maxTimeoutSeconds {
		cfg.TimeoutSeconds = maxTimeoutSeconds
	}

	m.mu.Lock()
	m.cfg, m.urlRe = cfg, re
	m.mu.Unlock()

	// 关掉开关时把已经挂住的请求放掉，否则它们要等到超时
	if !cfg.Enabled {
		m.ReleaseAll()
	}
	return nil
}

func (m *Manager) Config() models.BreakpointConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Pending 返回当前待处理的断点，按命中时间排序无关紧要，界面自行展示。
func (m *Manager) Pending() []models.BreakpointHit {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]models.BreakpointHit, 0, len(m.waiters))
	for _, w := range m.waiters {
		hit := w.hit
		if remain := time.Until(w.deadline); remain > 0 {
			hit.DeadlineSeconds = int(remain.Seconds())
		}
		out = append(out, hit)
	}
	return out
}

// PendingCount 供状态展示
func (m *Manager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.waiters)
}

// Resolve 处理一个断点。取出 waiter 与发送分离在锁内外，
// 保证同一个 waiter 只会被发送一次，不会出现第二次发送阻塞。
func (m *Manager) Resolve(res models.BreakpointResolution) error {
	m.mu.Lock()
	w, ok := m.waiters[res.ID]
	if ok {
		delete(m.waiters, res.ID)
	}
	m.mu.Unlock()

	if !ok {
		return errors.New("该断点已被处理或已超时放行")
	}
	w.ch <- res
	m.notify()
	return nil
}

// ReleaseAll 放行所有等待中的请求，用于关闭断点或停止代理。
func (m *Manager) ReleaseAll() {
	m.mu.Lock()
	pending := make([]*waiter, 0, len(m.waiters))
	for id, w := range m.waiters {
		pending = append(pending, w)
		delete(m.waiters, id)
	}
	m.mu.Unlock()

	for _, w := range pending {
		w.ch <- models.BreakpointResolution{ID: w.hit.ID, Action: models.BreakpointResume}
	}
	if len(pending) > 0 {
		m.notify()
	}
}

// shouldBreak 判断是否需要拦截。开关关闭时连匹配都不做。
func (m *Manager) shouldBreak(phase models.BreakpointPhase, method, url string) (time.Duration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.cfg.Enabled {
		return 0, false
	}
	switch phase {
	case models.BreakpointPhaseRequest:
		if !m.cfg.OnRequest {
			return 0, false
		}
	case models.BreakpointPhaseResponse:
		if !m.cfg.OnResponse {
			return 0, false
		}
	}
	if m.cfg.Method != "" && !strings.EqualFold(m.cfg.Method, method) {
		return 0, false
	}
	if m.urlRe != nil && !m.urlRe.MatchString(url) {
		return 0, false
	}
	return time.Duration(m.cfg.TimeoutSeconds) * time.Second, true
}

// wait 挂住当前 goroutine 直到界面处理或超时。
func (m *Manager) wait(hit models.BreakpointHit, timeout time.Duration) models.BreakpointResolution {
	w := &waiter{
		ch:       make(chan models.BreakpointResolution, 1),
		hit:      hit,
		deadline: time.Now().Add(timeout),
	}

	m.mu.Lock()
	m.waiters[hit.ID] = w
	m.mu.Unlock()
	m.notify()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-w.ch:
		return res
	case <-timer.C:
		// 超时兜底：自动放行，并从队列摘掉。
		// 若此刻 Resolve 已经取走了 waiter，就以它的结果为准
		m.mu.Lock()
		cur, still := m.waiters[hit.ID]
		if still && cur == w {
			delete(m.waiters, hit.ID)
		}
		m.mu.Unlock()

		if still && cur == w {
			m.notify()
			return models.BreakpointResolution{ID: hit.ID, Action: models.BreakpointResume}
		}
		return <-w.ch
	}
}

// InterceptRequest 在请求阶段拦截。返回的动作为 abort 时调用方应直接返回错误响应。
func (m *Manager) InterceptRequest(req *http.Request, id string) models.BreakpointAction {
	if req == nil || req.URL == nil {
		return models.BreakpointResume
	}
	timeout, ok := m.shouldBreak(models.BreakpointPhaseRequest, req.Method, req.URL.String())
	if !ok {
		return models.BreakpointResume
	}

	body, binary := readBodyForDisplay(&req.Body, req.Header.Get("Content-Type"), "")
	hit := models.BreakpointHit{
		ID:         id,
		Phase:      models.BreakpointPhaseRequest,
		Date:       time.Now().Format(time.DateTime),
		Method:     req.Method,
		URL:        req.URL.String(),
		Header:     req.Header.Clone(),
		Body:       body,
		BodyBinary: binary,
	}

	res := m.wait(hit, timeout)
	if res.Action == models.BreakpointModify {
		applyToRequest(req, res)
	}
	return res.Action
}

// InterceptResponse 在响应阶段拦截。
func (m *Manager) InterceptResponse(resp *http.Response, id string) models.BreakpointAction {
	if resp == nil {
		return models.BreakpointResume
	}
	method, url := "", ""
	if resp.Request != nil && resp.Request.URL != nil {
		method, url = resp.Request.Method, resp.Request.URL.String()
	}
	timeout, ok := m.shouldBreak(models.BreakpointPhaseResponse, method, url)
	if !ok {
		return models.BreakpointResume
	}

	body, binary := readBodyForDisplay(&resp.Body,
		resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
	hit := models.BreakpointHit{
		ID:         id,
		Phase:      models.BreakpointPhaseResponse,
		Date:       time.Now().Format(time.DateTime),
		Method:     method,
		URL:        url,
		Header:     resp.Header.Clone(),
		Body:       body,
		BodyBinary: binary,
		StatusCode: resp.StatusCode,
	}

	res := m.wait(hit, timeout)
	if res.Action == models.BreakpointModify {
		applyToResponse(resp, res)
	}
	return res.Action
}

// readBodyForDisplay 读出正文供界面展示，并把内容装回去。
// 非文本内容不返回正文，避免把二进制塞进编辑框。
func readBodyForDisplay(body *io.ReadCloser, contentType, contentEncoding string) (string, bool) {
	if body == nil || *body == nil {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(*body, maxDisplayBody))
	(*body).Close()
	*body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return fmt.Sprintf("[read error] %s", err), true
	}
	if len(raw) == 0 {
		return "", false
	}

	kind, _ := models.ClassifyContentType(contentType, "")
	if kind != models.ResourceTypeText {
		return fmt.Sprintf("[binary data] %d bytes", len(raw)), true
	}

	decoded, err := httpbody.Decode(contentEncoding, raw)
	if err != nil {
		return fmt.Sprintf("[decode error] %s", err), true
	}
	return string(decoded), false
}

func applyToRequest(req *http.Request, res models.BreakpointResolution) {
	if res.Method != "" {
		req.Method = res.Method
	}
	if res.URL != "" {
		if u, err := req.URL.Parse(res.URL); err == nil {
			req.URL = u
			req.Host = u.Host
		}
	}
	if res.Header != nil {
		req.Header = res.Header.Clone()
	}
	// Body 为空串时视为不改动：清空正文应通过改写 Content-Length 表达
	if res.Body != "" {
		setBody(&req.Body, &req.ContentLength, req.Header, []byte(res.Body))
	}
}

func applyToResponse(resp *http.Response, res models.BreakpointResolution) {
	if res.StatusCode > 0 {
		resp.StatusCode = res.StatusCode
		resp.Status = fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	if res.Header != nil {
		resp.Header = res.Header.Clone()
	}
	if res.Body != "" {
		// 界面拿到的是解压后的文本，改完写回去必须去掉压缩标记
		resp.Header.Del("Content-Encoding")
		setBody(&resp.Body, &resp.ContentLength, resp.Header, []byte(res.Body))
	}
}

// setBody 换掉正文并同步长度，Content-Length 不一致会导致连接挂死
func setBody(body *io.ReadCloser, contentLength *int64, header http.Header, data []byte) {
	*body = io.NopCloser(bytes.NewReader(data))
	*contentLength = int64(len(data))
	header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	header.Del("Transfer-Encoding")
}
