package export

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
)

func readHAR(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 HAR 失败: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("HAR 不是合法 JSON: %v", err)
	}
	return doc
}

func entriesOf(t *testing.T, doc map[string]any) []any {
	t.Helper()
	log, ok := doc["log"].(map[string]any)
	if !ok {
		t.Fatal("HAR 缺少 log 节点")
	}
	entries, ok := log["entries"].([]any)
	if !ok {
		t.Fatal("HAR 缺少 entries 节点")
	}
	return entries
}

func TestWriteHARPairsByID(t *testing.T) {
	packets := []models.HTTPPacket{
		{
			ID:             "1",
			HTTPPacketType: models.HTTPPacketType_REQUEST,
			Date:           "2026-09-05 10:00:00",
			Method:         "GET",
			URL:            "https://a.com/x?q=1&r=2",
			Proto:          "HTTP/1.1",
			Header:         http.Header{"Accept": []string{"*/*"}},
		},
		{
			ID:             "1",
			HTTPPacketType: models.HTTPPacketType_RESPONSE,
			Date:           "2026-09-05 10:00:01",
			StatusCode:     200,
			Status:         "200 OK",
			Proto:          "HTTP/1.1",
			ContentType:    "text/html",
			ResourceType:   models.ResourceTypeText,
			Body:           "<html></html>",
			Duration:       123,
			Header:         http.Header{"Content-Type": []string{"text/html"}},
		},
		// 隧道记录不是 HTTP 往返，不应出现在导出结果里
		{
			ID:             "2",
			HTTPPacketType: models.HTTPPacketType_TUNNEL,
			Host:           "weixin.qq.com:443",
		},
	}

	path := filepath.Join(t.TempDir(), "out.har")
	if err := WriteHAR(path, "test", packets); err != nil {
		t.Fatalf("WriteHAR 失败: %v", err)
	}

	entries := entriesOf(t, readHAR(t, path))
	if len(entries) != 1 {
		t.Fatalf("条目数 = %d, want 1", len(entries))
	}

	entry := entries[0].(map[string]any)
	if got := entry["time"].(float64); got != 123 {
		t.Errorf("time = %v, want 123", got)
	}

	req := entry["request"].(map[string]any)
	if req["method"] != "GET" {
		t.Errorf("method = %v", req["method"])
	}
	if qs := req["queryString"].([]any); len(qs) != 2 {
		t.Errorf("queryString 条数 = %d, want 2", len(qs))
	}

	resp := entry["response"].(map[string]any)
	if got := resp["status"].(float64); got != 200 {
		t.Errorf("status = %v, want 200", got)
	}
	if resp["statusText"] != "OK" {
		t.Errorf("statusText = %v, want OK", resp["statusText"])
	}
	content := resp["content"].(map[string]any)
	if content["text"] != "<html></html>" {
		t.Errorf("content.text = %v", content["text"])
	}
}

// 非文本响应我们没有读取正文，不能把 [binary data] 占位串当成内容写进去
func TestWriteHARSkipsPlaceholderBody(t *testing.T) {
	packets := []models.HTTPPacket{
		{
			ID:             "1",
			HTTPPacketType: models.HTTPPacketType_RESPONSE,
			StatusCode:     200,
			ContentType:    "image/png",
			ResourceType:   models.ResourceTypeImage,
			Body:           "[binary data] image/png",
		},
	}

	path := filepath.Join(t.TempDir(), "out.har")
	if err := WriteHAR(path, "test", packets); err != nil {
		t.Fatalf("WriteHAR 失败: %v", err)
	}

	entries := entriesOf(t, readHAR(t, path))
	if len(entries) != 1 {
		t.Fatalf("条目数 = %d, want 1", len(entries))
	}
	content := entries[0].(map[string]any)["response"].(map[string]any)["content"].(map[string]any)
	if _, ok := content["text"]; ok {
		t.Errorf("占位串不应写入 content.text, 得到 %v", content["text"])
	}
}

// 只有响应没有请求时，用响应里保留的请求头补齐
func TestWriteHARUsesRetainedRequestHeader(t *testing.T) {
	packets := []models.HTTPPacket{
		{
			ID:             "9",
			HTTPPacketType: models.HTTPPacketType_RESPONSE,
			Method:         "GET",
			URL:            "https://a.com/v.mp4",
			StatusCode:     200,
			RequestHeader:  http.Header{"Referer": []string{"https://a.com/"}},
		},
	}

	path := filepath.Join(t.TempDir(), "out.har")
	if err := WriteHAR(path, "test", packets); err != nil {
		t.Fatalf("WriteHAR 失败: %v", err)
	}

	entries := entriesOf(t, readHAR(t, path))
	req := entries[0].(map[string]any)["request"].(map[string]any)
	headers := req["headers"].([]any)
	found := false
	for _, h := range headers {
		hh := h.(map[string]any)
		if hh["name"] == "Referer" && hh["value"] == "https://a.com/" {
			found = true
		}
	}
	if !found {
		t.Errorf("应使用响应里保留的请求头, 得到 %v", headers)
	}
}

func TestWriteHAREmptyPacketsProducesEmptyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.har")
	if err := WriteHAR(path, "test", nil); err != nil {
		t.Fatalf("WriteHAR 失败: %v", err)
	}
	if entries := entriesOf(t, readHAR(t, path)); len(entries) != 0 {
		t.Errorf("条目数 = %d, want 0", len(entries))
	}
}
