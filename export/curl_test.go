package export

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
)

func TestCurlGetOmitsMethod(t *testing.T) {
	got, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_REQUEST,
		Method:         "GET",
		URL:            "https://example.com/a?b=1",
	})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if strings.Contains(got, "-X") {
		t.Errorf("GET 且无正文时不该写 -X: %s", got)
	}
	if got != `curl 'https://example.com/a?b=1'` {
		t.Errorf("命令 = %s", got)
	}
}

func TestCurlIncludesMethodAndBody(t *testing.T) {
	got, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_REQUEST,
		Method:         "post",
		URL:            "https://example.com/api",
		Header:         http.Header{"Content-Type": {"application/json"}},
		Body:           `{"a":1}`,
	})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	for _, want := range []string{"-X POST", "-H 'Content-Type: application/json'", `--data-raw '{"a":1}'`} {
		if !strings.Contains(got, want) {
			t.Errorf("命令缺少 %s: %s", want, got)
		}
	}
}

// 正文里的单引号必须按 POSIX 规则转义，否则命令会被截断
func TestCurlEscapesSingleQuote(t *testing.T) {
	got, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_REQUEST,
		Method:         "POST",
		URL:            "https://example.com/",
		Body:           "it's",
	})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if !strings.Contains(got, `--data-raw 'it'\''s'`) {
		t.Errorf("单引号未按 POSIX 转义: %s", got)
	}
}

// 长度与连接管理由 curl 自己处理，Host 从 URL 推导
func TestCurlSkipsHopByHopHeaders(t *testing.T) {
	got, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_REQUEST,
		Method:         "GET",
		URL:            "https://example.com/",
		Header: http.Header{
			"Host":           {"example.com"},
			"Content-Length": {"7"},
			"Connection":     {"keep-alive"},
			"User-Agent":     {"probe/1.0"},
		},
	})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	for _, unwanted := range []string{"Host:", "Content-Length:", "Connection:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("命令不该包含 %s: %s", unwanted, got)
		}
	}
	if !strings.Contains(got, "-H 'User-Agent: probe/1.0'") {
		t.Errorf("普通头应保留: %s", got)
	}
}

// 响应记录只留了请求头，响应体不能被当成请求体发出去
func TestCurlUsesRequestHeaderOnResponseRecord(t *testing.T) {
	got, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_RESPONSE,
		Method:         "GET",
		URL:            "https://example.com/",
		Header:         http.Header{"Content-Type": {"text/html"}},
		RequestHeader:  http.Header{"Referer": {"https://example.com/from"}},
		Body:           "<html>响应体</html>",
	})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if !strings.Contains(got, "-H 'Referer: https://example.com/from'") {
		t.Errorf("应使用 RequestHeader: %s", got)
	}
	if strings.Contains(got, "Content-Type") {
		t.Errorf("不该带响应头: %s", got)
	}
	if strings.Contains(got, "--data-raw") {
		t.Errorf("响应体不该作为请求体: %s", got)
	}
}

func TestCurlRejectsTunnelAndEmptyURL(t *testing.T) {
	if _, err := Curl(models.HTTPPacket{URL: ""}); err == nil {
		t.Error("无 URL 时应返回错误")
	}
	if _, err := Curl(models.HTTPPacket{
		HTTPPacketType: models.HTTPPacketType_TUNNEL,
		URL:            "example.com:443",
	}); err == nil {
		t.Error("隧道记录应返回错误")
	}
}
