package handler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dreamsxin/go-netsniffer/httpbody"
	"github.com/dreamsxin/go-netsniffer/models"
)

// Sink 接收抓取到的报文。由调用方负责过滤、限流与投递，
// handler 不直接持有 channel，避免关闭 channel 后写入导致 panic。
type Sink interface {
	// Emit 投递一个报文，实现必须是非阻塞的
	Emit(*models.Packet)
	// MaxBodySize 返回单个报文最多记录的 Body 字节数
	MaxBodySize() int64
}

// RequestLogger 把代理观察到的请求与响应转换成报文投递给 Sink。
// 所有方法都不返回错误：记录失败不能影响被代理的流量。
type RequestLogger struct {
	sink Sink
}

func NewRequestLogger(sink Sink) *RequestLogger {
	return &RequestLogger{sink: sink}
}

// Request 记录一个请求。id 用于与响应配对，rewritten 是命中的改包规则名。
func (r *RequestLogger) Request(req *http.Request, id string, rewritten []string) {
	if req == nil || req.URL == nil {
		return
	}

	var data models.Packet
	data.PacketType = models.PacketType_HTTP
	data.HTTP.ID = id
	data.HTTP.Rewritten = rewritten
	data.HTTP.HTTPPacketType = models.HTTPPacketType_REQUEST
	data.HTTP.Date = time.Now().Format(time.DateTime)
	data.HTTP.Proto = req.Proto
	data.HTTP.ProtoMajor = req.ProtoMajor
	data.HTTP.ProtoMinor = req.ProtoMinor
	data.HTTP.Method = req.Method
	data.HTTP.Host = req.Host
	data.HTTP.Path = req.URL.Path
	data.HTTP.URL = req.URL.String()
	data.HTTP.Header = req.Header
	data.HTTP.ContentLength = req.ContentLength
	data.HTTP.ContentType = req.Header.Get("Content-Type")

	if req.Body == nil || req.ContentLength == 0 {
		data.HTTP.Body = "[no data]"
	} else {
		body, truncated, err := readAndReplaceBody(&req.Body, r.maxBodySize())
		if err != nil {
			data.HTTP.Body = fmt.Sprintf("[read error] %s", err)
		} else {
			data.HTTP.Body = string(body)
			data.HTTP.BodyTruncated = truncated
		}
	}

	r.sink.Emit(&data)
}

// Response 记录一个响应及其往返耗时，rewritten 是命中的改包规则名。
func (r *RequestLogger) Response(resp *http.Response, id string, duration time.Duration, rewritten []string) {
	if resp == nil {
		return
	}

	var data models.Packet
	data.PacketType = models.PacketType_HTTP
	data.HTTP.ID = id
	data.HTTP.Rewritten = rewritten
	data.HTTP.HTTPPacketType = models.HTTPPacketType_RESPONSE
	data.HTTP.Date = time.Now().Format(time.DateTime)
	data.HTTP.Proto = resp.Proto
	data.HTTP.ProtoMajor = resp.ProtoMajor
	data.HTTP.ProtoMinor = resp.ProtoMinor
	data.HTTP.Header = resp.Header
	data.HTTP.Status = resp.Status
	data.HTTP.StatusCode = resp.StatusCode
	data.HTTP.ContentType = resp.Header.Get("Content-Type")
	data.HTTP.ContentLength = resp.ContentLength
	data.HTTP.Duration = duration.Milliseconds()

	// 上游失败时代理可能给出没有 Request 的响应
	if resp.Request != nil && resp.Request.URL != nil {
		data.HTTP.Method = resp.Request.Method
		data.HTTP.Host = resp.Request.Host
		data.HTTP.Path = resp.Request.URL.Path
		data.HTTP.URL = resp.Request.URL.String()
		// 保留请求头，下载时原样重放以绕过 Referer / 防盗链校验，
		// 这样不必把响应体缓存在内存里
		data.HTTP.RequestHeader = resp.Request.Header
	}

	data.HTTP.ResourceType, data.HTTP.Suffix = models.ClassifyContentType(
		data.HTTP.ContentType, data.HTTP.URL)

	contentType := data.HTTP.ContentType
	switch {
	case resp.Body == nil || resp.ContentLength == 0:
		data.HTTP.Body = "[no data]"
	case data.HTTP.ResourceType != models.ResourceTypeText:
		// 非文本内容不读取正文，避免把大文件读进内存；
		// 需要查看时由界面走下载流程重新取一次
		data.HTTP.Body = "[binary data] " + contentType
	default:
		body, truncated, err := readAndReplaceBody(&resp.Body, r.maxBodySize())
		if err != nil {
			data.HTTP.Body = fmt.Sprintf("[read error] %s", err)
			break
		}
		text, err := decodeBody(resp.Header.Get("Content-Encoding"), body)
		if err != nil {
			// 截断过的压缩数据必然解压失败，属于预期情况
			data.HTTP.Body = fmt.Sprintf("[decode error] %s", err)
			break
		}
		data.HTTP.Body = text
		data.HTTP.BodyTruncated = truncated
	}

	r.sink.Emit(&data)
}

// Tunnel 记录一个按规则未解密、仅做转发的连接。
// 没有这条记录，用户会不清楚某个域名为何不出现在列表里。
func (r *RequestLogger) Tunnel(host, id string) {
	r.sink.Emit(&models.Packet{
		PacketType: models.PacketType_HTTP,
		HTTP: models.HTTPPacket{
			ID:             id,
			HTTPPacketType: models.HTTPPacketType_TUNNEL,
			Date:           time.Now().Format(time.DateTime),
			Method:         http.MethodConnect,
			Host:           host,
			URL:            host,
			Body:           "[tunnel] 按规则未解密，仅转发",
		},
	})
}

func (r *RequestLogger) maxBodySize() int64 {
	if n := r.sink.MaxBodySize(); n > 0 {
		return n
	}
	return 1 << 20
}

// readAndReplaceBody 最多读取 limit 字节用于展示，并把完整内容重新装回 body，
// 保证被抓包的请求/响应对客户端依然是完整的。
func readAndReplaceBody(body *io.ReadCloser, limit int64) (data []byte, truncated bool, err error) {
	raw, err := io.ReadAll(*body)
	(*body).Close()
	*body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > limit {
		return raw[:limit], true, nil
	}
	return raw, false, nil
}

func decodeBody(contentEncoding string, raw []byte) (string, error) {
	out, err := httpbody.Decode(contentEncoding, raw)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
