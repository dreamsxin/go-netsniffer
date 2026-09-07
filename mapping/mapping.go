// Package mapping 实现 Map Local 与 Map Remote。
//
// 与 rewrite 的分工：rewrite 在真实往返的基础上做局部修改，
// mapping 改变的是请求去哪里（remote）、响应从哪来（local）。
//
// 规则以 JSON 形式保存在配置里，支持热更新。解析失败时保留上一次生效的规则，
// 并把错误暴露给界面——静默失败会让用户以为映射没生效而无从排查。
package mapping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dreamsxin/go-netsniffer/models"
)

// maxLocalFile 是 Map Local 单个文件的上限。
// 文件要整份读进内存再交给客户端，没有上限会被大文件打爆。
const maxLocalFile = 64 << 20 // 64MB

type compiled struct {
	rule  models.MapRule
	urlRe *regexp.Regexp
	// target 是 remote 规则解析好的目标，local 规则为 nil
	target *url.URL
}

// Set 是一组已编译的映射规则，并发读安全。
type Set struct {
	mu       sync.RWMutex
	rules    []compiled
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

	// 空配置等于不做映射，属于正常状态而不是错误
	if trimmed == "" {
		s.mu.Lock()
		s.rules, s.parseErr = nil, ""
		s.mu.Unlock()
		return nil
	}

	var raw []models.MapRule
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		err = fmt.Errorf("映射规则不是合法 JSON: %w", err)
		s.setParseErr(err.Error())
		return err
	}

	rules := make([]compiled, 0, len(raw))
	for i, r := range raw {
		if !r.Enabled {
			continue
		}
		c, err := compileRule(i, r)
		if err != nil {
			s.setParseErr(err.Error())
			return err
		}
		rules = append(rules, c)
	}

	s.mu.Lock()
	s.rules, s.parseErr = rules, ""
	s.mu.Unlock()
	return nil
}

func compileRule(index int, r models.MapRule) (compiled, error) {
	label := fmt.Sprintf("第 %d 条规则(%s)", index+1, r.Name)
	c := compiled{rule: r}

	if r.URLRegex != "" {
		re, err := regexp.Compile(r.URLRegex)
		if err != nil {
			return c, fmt.Errorf("%s的 URLRegex 无效: %w", label, err)
		}
		c.urlRe = re
	}

	switch r.Kind {
	case models.MapKindLocal:
		if r.File == "" {
			return c, fmt.Errorf("%s是 local，必须填 File", label)
		}
	case models.MapKindRemote:
		t, err := parseTarget(r.To)
		if err != nil {
			return c, fmt.Errorf("%s的 To 无效: %w", label, err)
		}
		c.target = t
	default:
		return c, fmt.Errorf("%s的 Kind 只能是 local 或 remote，得到 %q", label, r.Kind)
	}

	// 匹配条件全空会命中所有流量，这对映射几乎肯定是误配
	if c.urlRe == nil && r.Method == "" {
		return c, fmt.Errorf("%s没有任何匹配条件，会作用于所有流量，请至少填 URLRegex 或 Method", label)
	}
	return c, nil
}

func parseTarget(to string) (*url.URL, error) {
	if strings.TrimSpace(to) == "" {
		return nil, fmt.Errorf("不能为空")
	}
	u, err := url.Parse(to)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("协议只能是 http 或 https，得到 %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("缺少主机与端口")
	}
	return u, nil
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

// RuleCount 返回生效中的规则条数，供界面反馈
func (s *Set) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// Apply 对请求施加映射。
//
// 只有第一条命中的规则生效：连着应用多条映射（先转到 A 再转到 B）
// 没有可理解的语义，也很难排查。
//
// 返回非 nil 响应表示这次请求不再发到线上（Map Local），
// 调用方应把它直接返回给客户端。
func (s *Set) Apply(req *http.Request) (*http.Response, []string) {
	if req == nil || req.URL == nil {
		return nil, nil
	}

	c, ok := s.match(req.Method, req.URL.String())
	if !ok {
		return nil, nil
	}
	applied := []string{ruleLabel(c.rule)}

	if c.rule.Kind == models.MapKindRemote {
		applyRemote(req, c)
		return nil, applied
	}
	return localResponse(req, c.rule), applied
}

func (s *Set) match(method, rawURL string) (compiled, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.rules {
		if c.rule.Method != "" && !strings.EqualFold(c.rule.Method, method) {
			continue
		}
		if c.urlRe != nil && !c.urlRe.MatchString(rawURL) {
			continue
		}
		return c, true
	}
	return compiled{}, false
}

func ruleLabel(r models.MapRule) string {
	name := r.Name
	if name == "" {
		name = string(r.Kind)
	}
	// 加前缀是因为映射与改包共用界面上同一个"被规则改动"标注，
	// 不区分的话用户看不出这条记录到底被谁动了
	return "映射/" + name
}

// applyRemote 改写请求的目标地址。
//
// 默认不动 Host 头：把线上域名指向本地服务时，
// 对端往往要靠原 Host 做虚拟主机匹配。
func applyRemote(req *http.Request, c compiled) {
	req.URL.Scheme = c.target.Scheme
	req.URL.Host = c.target.Host

	if prefix := strings.TrimSuffix(c.target.Path, "/"); prefix != "" {
		req.URL.Path = prefix + req.URL.Path
	}
	if c.rule.RewriteHost {
		req.Host = c.target.Host
	}
}

// localResponse 用本地文件构造响应。
//
// 文件读不到时返回 502 并说明原因，而不是放行到线上：
// 静默放行会让用户以为规则没匹配，反而更难查。
func localResponse(req *http.Request, r models.MapRule) *http.Response {
	data, err := readFile(r.File)
	if err != nil {
		return textResponse(req, http.StatusBadGateway,
			fmt.Sprintf("Map Local 规则 %q 读取文件失败: %s", ruleLabel(r), err))
	}

	status := r.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}

	header := http.Header{}
	header.Set("Content-Type", contentTypeFor(r))
	header.Set("Content-Length", strconv.Itoa(len(data)))
	for name, value := range r.Headers {
		header.Set(name, value)
	}

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s 是目录，不是文件", path)
	}
	if info.Size() > maxLocalFile {
		return nil, fmt.Errorf("文件超过 %d MB 上限", maxLocalFile>>20)
	}
	return io.ReadAll(io.LimitReader(f, maxLocalFile))
}

func contentTypeFor(r models.MapRule) string {
	if r.ContentType != "" {
		return r.ContentType
	}
	if t := mime.TypeByExtension(filepath.Ext(r.File)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func textResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}
