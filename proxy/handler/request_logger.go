package handler

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"


	"github.com/andybalholm/brotli"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/klauspost/compress/zstd"
)

// Sink 接收抓取到的报文。由调用方负责过滤、限流与投递，
// handler 不直接持有 channel，避免关闭 channel 后写入导致 panic。
type Sink interface {
	// Emit 投递一个报文，实现必须是非阻塞的
	Emit(*models.Packet)
	// MaxBodySize 返回单个报文最多记录的 Body 字节数
	MaxBodySize() int64
}

// RequestLogger 记录经过代理的请求与响应
type RequestLogger struct {
	sink Sink
}

func NewRequestLogger(sink Sink) *RequestLogger {
	return &RequestLogger{sink: sink}
}

// ModifyRequest 读取请求信息。
// 任何错误都只影响记录本身，不能中断请求，否则用户的网络会因抓包失败而不可用。
func (r *RequestLogger) ModifyRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return nil
	}

	var data models.Packet
	data.PacketType = models.PacketType_HTTP
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
			data.HTTP.Body = decorate(string(body), truncated)
		}
	}

	r.sink.Emit(&data)
	return nil
}

// ModifyResponse 读取响应信息，同样不因记录失败而中断响应。
func (r *RequestLogger) ModifyResponse(resp *http.Response) error {
	if resp == nil {
		return nil
	}

	var data models.Packet
	data.PacketType = models.PacketType_HTTP
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

	// martian 在部分错误路径下会构造没有 Request 的响应
	if resp.Request != nil && resp.Request.URL != nil {
		data.HTTP.Method = resp.Request.Method
		data.HTTP.Host = resp.Request.Host
		data.HTTP.Path = resp.Request.URL.Path
		data.HTTP.URL = resp.Request.URL.String()
	}

	contentType := data.HTTP.ContentType
	switch {
	case resp.Body == nil || resp.ContentLength == 0:
		data.HTTP.Body = "[no data]"
	case !isTextual(contentType):
		// 二进制内容不读取正文，避免把大文件读进内存
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
		data.HTTP.Body = decorate(text, truncated)
	}

	r.sink.Emit(&data)
	return nil
}

func (r *RequestLogger) maxBodySize() int64 {
	if n := r.sink.MaxBodySize(); n > 0 {
		return n
	}
	return 1 << 20
}

func isTextual(contentType string) bool {
	if contentType == "" {
		return false
	}
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "x-www-form-urlencoded")
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

// zstd 解码器可复用且并发安全，避免每个响应都新建一次
var zstdDecoder, _ = zstd.NewReader(nil)

func decodeBody(contentEncoding string, raw []byte) (string, error) {
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "zstd":
		if zstdDecoder == nil {
			return "", errors.New("zstd 解码器不可用")
		}
		out, err := zstdDecoder.DecodeAll(raw, nil)
		if err != nil {
			return "", err
		}
		return string(out), nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return "", err
		}
		return string(out), nil
	case "br":
		out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return "", err
		}
		return string(out), nil
	default:
		return string(raw), nil
	}
}

func decorate(body string, truncated bool) string {
	if truncated {
		return body + "\n...[truncated]"
	}
	return body
}
