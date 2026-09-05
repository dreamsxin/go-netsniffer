// Package export 把抓到的记录导出为其他工具能读的标准格式。
package export

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
)

// HAR 1.2 的最小可用结构。
// 只填 Chrome DevTools 与 Charles 实际会读的字段，其余给出规范要求的占位值。
type har struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            int64       `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}

type harTimings struct {
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harNameValue `json:"cookies"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	Cookies     []harNameValue `json:"cookies"`
	Content     harContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

// WriteHAR 把记录按 ID 配对成 HAR 条目并写入文件。
// 隧道记录不是 HTTP 往返，会被跳过。
func WriteHAR(path, creatorVersion string, packets []models.HTTPPacket) error {
	doc := har{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{Name: "Go NetSniffer", Version: creatorVersion},
			Entries: buildEntries(packets),
		},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	// 先写临时文件再改名，中断时不会留下损坏的 HAR
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func buildEntries(packets []models.HTTPPacket) []harEntry {
	requests := make(map[string]models.HTTPPacket)
	// 按 ID 收集响应，保持它们在输入中的先后顺序
	var order []string
	responses := make(map[string]models.HTTPPacket)

	for _, p := range packets {
		switch p.HTTPPacketType {
		case models.HTTPPacketType_REQUEST:
			if p.ID != "" {
				requests[p.ID] = p
			}
		case models.HTTPPacketType_RESPONSE:
			if p.ID == "" {
				continue
			}
			if _, seen := responses[p.ID]; !seen {
				order = append(order, p.ID)
			}
			responses[p.ID] = p
		}
	}

	entries := make([]harEntry, 0, len(order))
	for _, id := range order {
		resp := responses[id]
		req, hasReq := requests[id]
		if !hasReq {
			// 只有响应也能导出，请求侧用响应里保留的信息补齐
			req = models.HTTPPacket{
				Method: resp.Method,
				URL:    resp.URL,
				Proto:  resp.Proto,
				Header: resp.RequestHeader,
			}
		}
		entries = append(entries, buildEntry(req, resp))
	}
	return entries
}

func buildEntry(req, resp models.HTTPPacket) harEntry {
	entry := harEntry{
		StartedDateTime: isoTime(req.Date),
		Time:            resp.Duration,
		Request: harRequest{
			Method:      orDefault(req.Method, http.MethodGet),
			URL:         req.URL,
			HTTPVersion: orDefault(req.Proto, "HTTP/1.1"),
			Headers:     toNameValues(req.Header),
			QueryString: queryString(req.URL),
			Cookies:     []harNameValue{},
			HeadersSize: -1,
			BodySize:    req.ContentLength,
		},
		Response: harResponse{
			Status:      resp.StatusCode,
			StatusText:  statusText(resp.Status),
			HTTPVersion: orDefault(resp.Proto, "HTTP/1.1"),
			Headers:     toNameValues(resp.Header),
			Cookies:     []harNameValue{},
			Content: harContent{
				Size:     resp.ContentLength,
				MimeType: resp.ContentType,
			},
			RedirectURL: resp.Header.Get("Location"),
			HeadersSize: -1,
			BodySize:    resp.ContentLength,
		},
		// 只记录了总耗时，按规范用 -1 表示该分段未知
		Timings: harTimings{Send: -1, Wait: -1, Receive: resp.Duration},
	}

	// 非文本内容我们没有读取正文，不能把占位串当成真实数据写进去
	if resp.ResourceType == models.ResourceTypeText && !isPlaceholder(resp.Body) {
		entry.Response.Content.Text = resp.Body
	}
	if req.Body != "" && !isPlaceholder(req.Body) {
		entry.Request.PostData = &harPostData{
			MimeType: req.ContentType,
			Text:     req.Body,
		}
	}
	return entry
}

// isPlaceholder 判断 Body 是否是我们写入的占位说明而非真实内容
func isPlaceholder(body string) bool {
	return body == "" ||
		strings.HasPrefix(body, "[no data]") ||
		strings.HasPrefix(body, "[binary data]") ||
		strings.HasPrefix(body, "[read error]") ||
		strings.HasPrefix(body, "[decode error]") ||
		strings.HasPrefix(body, "[tunnel]")
}

func toNameValues(h http.Header) []harNameValue {
	out := make([]harNameValue, 0, len(h))
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	// 排序保证导出结果可复现
	sort.Strings(names)
	for _, name := range names {
		for _, v := range h[name] {
			out = append(out, harNameValue{Name: name, Value: v})
		}
	}
	return out
}

func queryString(rawURL string) []harNameValue {
	out := []harNameValue{}
	i := strings.Index(rawURL, "?")
	if i < 0 {
		return out
	}
	query := rawURL[i+1:]
	if j := strings.Index(query, "#"); j >= 0 {
		query = query[:j]
	}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		out = append(out, harNameValue{Name: name, Value: value})
	}
	return out
}

// isoTime 把记录里的本地时间字符串转成 HAR 要求的 ISO8601
func isoTime(date string) string {
	t, err := time.ParseInLocation(time.DateTime, date, time.Local)
	if err != nil {
		return time.Time{}.Format(time.RFC3339Nano)
	}
	return t.Format(time.RFC3339Nano)
}

// statusText 从 "200 OK" 中取出 "OK"
func statusText(status string) string {
	_, text, found := strings.Cut(status, " ")
	if !found {
		return status
	}
	return text
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
