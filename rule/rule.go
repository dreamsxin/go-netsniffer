// Package rule 按域名决定 HTTPS 连接是否解密。
//
// 全量解密会让做了证书固定的客户端直接握手失败，用户感知是"开了抓包就上不了网"。
// 规则语法类似 gitignore，按行书写，顺序遍历、后者覆盖前者：
//
//	*                 匹配全部域名
//	example.com       精确匹配
//	*.example.com     匹配该域名及其所有子域
//	!ad.example.com   否定，命中则不解密
//	# 注释
//
// 例如 "*" 加 "!weixin.qq.com" 表示除微信外全部解密。
package rule

import (
	"strings"
	"sync"
)

type item struct {
	domain     string
	isAll      bool
	isWildcard bool
	isNeg      bool
}

// Set 是一组已解析的规则，并发读安全。
type Set struct {
	mu    sync.RWMutex
	items []item
	text  string
}

// New 解析规则文本。语法错误的行被忽略，不会导致解析失败。
func New(text string) *Set {
	s := &Set{}
	s.Load(text)
	return s
}

// Load 重新加载规则，用于配置热更新。
func (s *Set) Load(text string) {
	items := parse(text)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = items
	s.text = text
}

// Text 返回当前生效的规则原文。
func (s *Set) Text() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.text
}

func parse(text string) []item {
	var items []item
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		it := item{}
		if strings.HasPrefix(line, "!") {
			it.isNeg = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}

		switch {
		case line == "*":
			it.isAll = true
		case strings.HasPrefix(line, "*."):
			it.isWildcard = true
			it.domain = normalizeHost(strings.TrimPrefix(line, "*."))
		default:
			it.domain = normalizeHost(line)
		}

		if !it.isAll && it.domain == "" {
			continue
		}
		items = append(items, it)
	}
	return items
}

// ShouldMITM 判断给定 host 是否需要解密。host 可带端口。
// 没有任何规则时返回 false —— 宁可少抓，也不要把用户的网络弄坏。
func (s *Set) ShouldMITM(host string) bool {
	h := normalizeHost(host)

	s.mu.RLock()
	defer s.mu.RUnlock()

	decrypt := false
	for _, it := range s.items {
		switch {
		case it.isAll:
			decrypt = !it.isNeg
		case it.isWildcard:
			if h == it.domain || strings.HasSuffix(h, "."+it.domain) {
				decrypt = !it.isNeg
			}
		default:
			if h == it.domain {
				decrypt = !it.isNeg
			}
		}
	}
	return decrypt
}

// normalizeHost 去掉端口、IPv6 方括号、尾部点，并统一小写。
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))

	// IPv6 字面量形如 [::1]:443
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 0 {
			return h[1:end]
		}
	}
	// 仅在只有一个冒号时才当作 host:port，避免误切裸 IPv6
	if strings.Count(h, ":") == 1 {
		h = h[:strings.Index(h, ":")]
	}
	return strings.TrimSuffix(h, ".")
}
