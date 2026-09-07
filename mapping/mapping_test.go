package mapping

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
)

func request(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, rawURL, nil)
}

func TestEmptyConfigIsNotAnError(t *testing.T) {
	s := New("")
	if s.ParseError() != "" {
		t.Errorf("空配置不该报错: %s", s.ParseError())
	}
	if s.RuleCount() != 0 {
		t.Errorf("规则数 = %d, want 0", s.RuleCount())
	}
}

// 默认示例必须能解析，否则用户一打开界面就看到报错
func TestDefaultRulesParse(t *testing.T) {
	s := New(models.DefaultMapRules)
	if s.ParseError() != "" {
		t.Errorf("默认规则解析失败: %s", s.ParseError())
	}
	// 示例全部 Enabled=false，不该有生效规则
	if s.RuleCount() != 0 {
		t.Errorf("示例规则应全部停用, 生效 %d 条", s.RuleCount())
	}
}

func TestRemoteRewritesTarget(t *testing.T) {
	s := New(`[{"Enabled":true,"Name":"r","Kind":"remote",
		"URLRegex":"^https://api\\.example\\.com/","To":"http://127.0.0.1:8080"}]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	req := request(t, "GET", "https://api.example.com/v1/users?p=1")
	original := req.Host

	resp, applied := s.Apply(req)
	if resp != nil {
		t.Fatal("remote 不该短路返回响应")
	}
	if len(applied) != 1 || applied[0] != "映射/r" {
		t.Errorf("命中标注 = %v", applied)
	}
	if req.URL.Scheme != "http" || req.URL.Host != "127.0.0.1:8080" {
		t.Errorf("目标 = %s://%s", req.URL.Scheme, req.URL.Host)
	}
	if req.URL.Path != "/v1/users" || req.URL.RawQuery != "p=1" {
		t.Errorf("路径与查询应保持不变: %s?%s", req.URL.Path, req.URL.RawQuery)
	}
	// 默认不改 Host：对端常靠原 Host 做虚拟主机匹配
	if req.Host != original {
		t.Errorf("Host = %q, 应保持 %q", req.Host, original)
	}
}

func TestRemoteRewriteHostAndPathPrefix(t *testing.T) {
	s := New(`[{"Enabled":true,"Kind":"remote","URLRegex":"example\\.com",
		"To":"http://127.0.0.1:8080/mock/","RewriteHost":true}]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	req := request(t, "GET", "https://example.com/api/a")
	s.Apply(req)

	if req.URL.Path != "/mock/api/a" {
		t.Errorf("路径 = %q, want /mock/api/a", req.URL.Path)
	}
	if req.Host != "127.0.0.1:8080" {
		t.Errorf("RewriteHost 为 true 时 Host 应改为目标: %q", req.Host)
	}
}

func TestLocalServesFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("写测试文件失败: %v", err)
	}

	s := New(`[{"Enabled":true,"Name":"L","Kind":"local","URLRegex":"/api/config",
		"File":` + quoteJSON(file) + `,"StatusCode":201}]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	req := request(t, "GET", "https://example.com/api/config")
	resp, applied := s.Apply(req)
	if resp == nil {
		t.Fatal("local 应短路返回响应")
	}
	if len(applied) != 1 || applied[0] != "映射/L" {
		t.Errorf("命中标注 = %v", applied)
	}
	if resp.StatusCode != 201 {
		t.Errorf("状态码 = %d, want 201", resp.StatusCode)
	}
	if resp.Request != req {
		t.Error("响应必须带上 Request，否则记录与导出拿不到 URL")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Errorf("正文 = %s", body)
	}
	if got := resp.Header.Get("Content-Length"); got != "11" {
		t.Errorf("Content-Length = %q, want 11", got)
	}
	// .json 后缀应被推断出来
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, 应按后缀推断为 json", ct)
	}
}

// 文件读不到时必须明确报错，静默放行到线上会让人以为规则没匹配
func TestLocalMissingFileReturns502(t *testing.T) {
	s := New(`[{"Enabled":true,"Kind":"local","URLRegex":"/api",
		"File":` + quoteJSON(filepath.Join(t.TempDir(), "nope.json")) + `}]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	resp, applied := s.Apply(request(t, "GET", "https://example.com/api"))
	if resp == nil {
		t.Fatal("应返回错误响应而不是放行")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("状态码 = %d, want 502", resp.StatusCode)
	}
	if len(applied) == 0 {
		t.Error("命中了规则就应标注，否则界面上看不出发生了什么")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "读取文件失败") {
		t.Errorf("正文应说明原因: %s", body)
	}
}

func TestOnlyFirstMatchApplies(t *testing.T) {
	s := New(`[
		{"Enabled":true,"Name":"first","Kind":"remote","URLRegex":"example\\.com","To":"http://127.0.0.1:1111"},
		{"Enabled":true,"Name":"second","Kind":"remote","URLRegex":"example\\.com","To":"http://127.0.0.1:2222"}
	]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	req := request(t, "GET", "https://example.com/a")
	_, applied := s.Apply(req)
	if len(applied) != 1 || applied[0] != "映射/first" {
		t.Errorf("只有第一条该生效, 得到 %v", applied)
	}
	if req.URL.Host != "127.0.0.1:1111" {
		t.Errorf("目标 = %s", req.URL.Host)
	}
}

func TestMethodFilter(t *testing.T) {
	s := New(`[{"Enabled":true,"Kind":"remote","Method":"POST","To":"http://127.0.0.1:8080"}]`)
	if s.ParseError() != "" {
		t.Fatalf("解析失败: %s", s.ParseError())
	}

	get := request(t, "GET", "https://example.com/a")
	if _, applied := s.Apply(get); len(applied) != 0 {
		t.Errorf("GET 不该命中只限 POST 的规则: %v", applied)
	}
	post := request(t, "POST", "https://example.com/a")
	if _, applied := s.Apply(post); len(applied) != 1 {
		t.Errorf("POST 应命中: %v", applied)
	}
}

func TestDisabledRulesIgnored(t *testing.T) {
	s := New(`[{"Enabled":false,"Kind":"remote","URLRegex":"example","To":"http://127.0.0.1:8080"}]`)
	if s.RuleCount() != 0 {
		t.Errorf("停用规则不该计入: %d", s.RuleCount())
	}
	if _, applied := s.Apply(request(t, "GET", "https://example.com/")); len(applied) != 0 {
		t.Errorf("停用规则不该命中: %v", applied)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"非法 JSON", `[{`},
		{"未知 Kind", `[{"Enabled":true,"Kind":"weird","URLRegex":"a"}]`},
		{"local 缺 File", `[{"Enabled":true,"Kind":"local","URLRegex":"a"}]`},
		{"remote 缺 To", `[{"Enabled":true,"Kind":"remote","URLRegex":"a"}]`},
		{"remote 协议非法", `[{"Enabled":true,"Kind":"remote","URLRegex":"a","To":"ftp://h"}]`},
		{"正则非法", `[{"Enabled":true,"Kind":"remote","URLRegex":"([","To":"http://h"}]`},
		{"无匹配条件", `[{"Enabled":true,"Kind":"remote","To":"http://h"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := New("").Load(c.text); err == nil {
				t.Error("应返回错误")
			}
		})
	}
}

// 解析失败时旧规则必须继续生效，否则一个笔误就让映射整体失效
func TestLoadKeepsOldRulesOnError(t *testing.T) {
	s := New(`[{"Enabled":true,"Kind":"remote","URLRegex":"example","To":"http://127.0.0.1:8080"}]`)
	if s.RuleCount() != 1 {
		t.Fatalf("初始规则数 = %d", s.RuleCount())
	}

	if err := s.Load(`[{`); err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
	if s.RuleCount() != 1 {
		t.Errorf("解析失败后旧规则应保留, 现在 %d 条", s.RuleCount())
	}
	if s.ParseError() == "" {
		t.Error("应记录解析错误供界面提示")
	}
}

// quoteJSON 把路径转成合法的 JSON 字符串字面量。
// Windows 路径含反斜杠，直接拼进 JSON 会变成转义符。
func quoteJSON(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}
