// Package rewrite 按规则改写经过代理的请求与响应。
//
// 规则以 JSON 形式保存在配置里，支持热更新。解析失败时保留上一次生效的规则，
// 并把错误暴露给界面——静默失败会让用户以为改包没生效而无从排查。
package rewrite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dreamsxin/go-netsniffer/httpbody"
	"github.com/dreamsxin/go-netsniffer/models"
)

// maxRewriteBody 是参与正文替换的上限。
// 改包需要把整个正文读进内存，没有上限会被大文件打爆。
const maxRewriteBody = 8 << 20 // 8MB

type compiled struct {
	rule  models.RewriteRule
	urlRe *regexp.Regexp
}

// Set 是一组已编译的改包规则，并发读安全。
type Set struct {
	mu    sync.RWMutex
	rules []compiled
	text  string
	// parseErr 记录上一次解析失败的原因，空表示正常
	parseErr string
}

func New(jsonText string) *Set {
	s := &Set{}
	s.Load(jsonText)
	return s
}

// Load 解析并替换规则。返回错误时旧规则继续生效。
func (s *Set) Load(jsonText string) error {
	trimmed := strings.TrimSpace(jsonText)

	// 空配置等于不改包，属于正常状态而不是错误
	if trimmed == "" {
		s.mu.Lock()
		s.rules, s.text, s.parseErr = nil, jsonText, ""
		s.mu.Unlock()
		return nil
	}

	var raw []models.RewriteRule
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		err = fmt.Errorf("改包规则不是合法 JSON: %w", err)
		s.setParseErr(err.Error())
		return err
	}

	rules := make([]compiled, 0, len(raw))
	for i, r := range raw {
		if !r.Enabled {
			continue
		}
		c := compiled{rule: r}
		if r.URLRegex != "" {
			re, err := regexp.Compile(r.URLRegex)
			if err != nil {
				err = fmt.Errorf("第 %d 条规则(%s)的 URLRegex 无效: %w", i+1, r.Name, err)
				s.setParseErr(err.Error())
				return err
			}
			c.urlRe = re
		}
		rules = append(rules, c)
	}

	s.mu.Lock()
	s.rules, s.text, s.parseErr = rules, jsonText, ""
	s.mu.Unlock()
	return nil
}

func (s *Set) setParseErr(msg string) {
	s.mu.Lock()
	s.parseErr = msg
	s.mu.Unlock()
}

// ParseError 返回上一次解析失败的原因，供界面提示
func (s *Set) ParseError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.parseErr
}

// Enabled 返回是否有生效中的规则
func (s *Set) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules) > 0
}

// RuleCount 返回生效中的规则条数，供界面反馈
func (s *Set) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

func (s *Set) match(phase models.RewritePhase, method, url string) []compiled {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []compiled
	for _, c := range s.rules {
		// Phase 留空按 request 处理，避免误伤响应
		p := c.rule.Phase
		if p == "" {
			p = models.RewritePhaseRequest
		}
		if p != phase {
			continue
		}
		if c.rule.Method != "" && !strings.EqualFold(c.rule.Method, method) {
			continue
		}
		if c.urlRe != nil && !c.urlRe.MatchString(url) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ApplyRequest 改写请求，返回命中的规则名，供界面标注该条记录被改过。
func (s *Set) ApplyRequest(req *http.Request) []string {
	if req == nil || req.URL == nil {
		return nil
	}
	matched := s.match(models.RewritePhaseRequest, req.Method, req.URL.String())
	if len(matched) == 0 {
		return nil
	}

	var applied []string
	var replacements []models.Replacement
	for _, c := range matched {
		applyHeaders(req.Header, c.rule)
		// Host 头要同步改到 req.Host，否则 net/http 会用原值
		if v, ok := lookupHeader(c.rule.SetHeaders, "Host"); ok {
			req.Host = v
		}
		replacements = append(replacements, c.rule.Replacements...)
		applied = append(applied, c.rule.Name)
	}

	if len(replacements) > 0 {
		replaceRequestBody(req, replacements)
	}
	return applied
}

// ApplyResponse 改写响应，返回命中的规则名。
func (s *Set) ApplyResponse(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	method, url := "", ""
	if resp.Request != nil && resp.Request.URL != nil {
		method, url = resp.Request.Method, resp.Request.URL.String()
	}
	matched := s.match(models.RewritePhaseResponse, method, url)
	if len(matched) == 0 {
		return nil
	}

	var applied []string
	var replacements []models.Replacement
	for _, c := range matched {
		applyHeaders(resp.Header, c.rule)
		if c.rule.StatusCode > 0 {
			resp.StatusCode = c.rule.StatusCode
			resp.Status = fmt.Sprintf("%d %s", c.rule.StatusCode,
				http.StatusText(c.rule.StatusCode))
		}
		replacements = append(replacements, c.rule.Replacements...)
		applied = append(applied, c.rule.Name)
	}

	if len(replacements) > 0 {
		replaceResponseBody(resp, replacements)
	}
	return applied
}

func applyHeaders(h http.Header, rule models.RewriteRule) {
	for name, value := range rule.SetHeaders {
		h.Set(name, value)
	}
	for _, name := range rule.RemoveHeaders {
		h.Del(name)
	}
}

func lookupHeader(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func replaceRequestBody(req *http.Request, replacements []models.Replacement) {
	if req.Body == nil {
		return
	}
	raw, err := readLimited(req.Body)
	req.Body.Close()
	if err != nil {
		// 读失败时不能把 body 丢掉，原样还回去
		req.Body = io.NopCloser(bytes.NewReader(raw))
		return
	}
	out := applyReplacements(raw, replacements)
	setBody(&req.Body, &req.ContentLength, req.Header, out)
}

func replaceResponseBody(resp *http.Response, replacements []models.Replacement) {
	if resp.Body == nil {
		return
	}
	raw, err := readLimited(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return
	}

	// 压缩过的正文直接做字符串替换毫无意义，先解压，
	// 然后去掉 Content-Encoding，让下游按明文处理
	encoding := resp.Header.Get("Content-Encoding")
	if httpbody.IsCompressed(encoding) {
		decoded, err := httpbody.Decode(encoding, raw)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			return
		}
		raw = decoded
		resp.Header.Del("Content-Encoding")
	}

	out := applyReplacements(raw, replacements)
	setBody(&resp.Body, &resp.ContentLength, resp.Header, out)
}

// setBody 换掉正文并同步长度，Content-Length 不一致会导致连接挂死
func setBody(body *io.ReadCloser, contentLength *int64, header http.Header, data []byte) {
	*body = io.NopCloser(bytes.NewReader(data))
	*contentLength = int64(len(data))
	header.Set("Content-Length", strconv.Itoa(len(data)))
	// 长度已明确，分块传输标记必须去掉
	header.Del("Transfer-Encoding")
}

func applyReplacements(raw []byte, replacements []models.Replacement) []byte {
	out := raw
	for _, r := range replacements {
		if r.From == "" {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(r.From), []byte(r.To))
	}
	return out
}

func readLimited(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxRewriteBody))
}
