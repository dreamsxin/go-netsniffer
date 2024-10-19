package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/valyala/gozstd"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const authorityName string = "Local Proxy Authority"

// RequestLogger is a RequestModifier logs all request url
type RequestLogger struct {
	ctx      context.Context
	sendChan chan<- *models.Packet
}

func NewRequestLogger(ctx context.Context, sendChan chan<- *models.Packet) *RequestLogger {
	return &RequestLogger{ctx: ctx, sendChan: sendChan}
}

var regex *regexp.Regexp
var regexRawData *regexp.Regexp

func init() {

	regexPattern := `^.*\.(jpg|png|gif|js|css|ico|svg)$`
	regex = regexp.MustCompile(regexPattern)

	regexPattern = "window.rawData={(.*?)};"
	regexRawData = regexp.MustCompile(regexPattern)
}

// 从请求中获取 cookie
func (r *RequestLogger) ModifyRequest(req *http.Request) error {

	var data models.Packet
	data.PacketType = models.REQUEST
	data.Date = time.Now().Format(time.DateTime)
	data.Proto = req.Proto
	data.ProtoMajor = req.ProtoMajor
	data.ProtoMinor = req.ProtoMinor
	data.Method = req.Method
	data.Host = req.Host
	data.Path = req.URL.Path
	data.URL = req.URL.String()
	data.Header = req.Header
	data.ContentLength = req.ContentLength
	log.Println("ModifyRequest", data.URL)
	if data.ContentLength == 0 {
		data.Body = "[no data]"
		runtime.EventsEmit(r.ctx, "Packet", data)
		return nil
	}
	rb, _ := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewBuffer(rb))
	data.Body = string(rb)

	r.sendChan <- &data
	return nil
}

// 从返回中获取 cookie
func (r *RequestLogger) ModifyResponse(resp *http.Response) error {
	var data models.Packet
	data.PacketType = models.RESPONSE
	data.Date = time.Now().Format(time.DateTime)
	data.Proto = resp.Proto
	data.ProtoMajor = resp.ProtoMajor
	data.ProtoMinor = resp.ProtoMinor
	data.Method = resp.Request.Method
	data.Host = resp.Request.Host
	data.Path = resp.Request.URL.Path
	data.URL = resp.Request.URL.String()
	data.Header = resp.Header
	data.Status = resp.Status
	data.StatusCode = resp.StatusCode
	data.ContentType = resp.Header.Get("Content-Type")
	data.ContentLength = resp.ContentLength

	if data.ContentLength == 0 {
		data.Body = "[no data]"
		runtime.EventsEmit(r.ctx, "Packet", data)
		return nil
	}
	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")
	log.Println("ModifyResponse", contentType, contentEncoding, data.URL)
	if contentType == "" || (!strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "json")) {
		data.Body = "[binary data]" + contentType
		runtime.EventsEmit(r.ctx, "Packet", data)
		return nil
	}

	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(rb))

	switch contentEncoding {
	case "zstd":
		decompressdata, err := gozstd.Decompress(nil, rb)
		if err != nil {
			data.Body = err.Error()
		} else {
			data.Body = string(decompressdata)
		}
	case "gzip":
		// 解压gzip数据
		r, err := gzip.NewReader(bytes.NewReader(rb))
		if err != nil {
			data.Body = err.Error()
		} else {
			defer r.Close()

			// 读取解压后的数据
			unzippedData, err := io.ReadAll(r)
			if err != nil {
				data.Body = err.Error()
			} else {
				data.Body = string(unzippedData)
			}
		}
	case "br":
		r := brotli.NewReader(bytes.NewReader(rb))

		// 读取解压后的数据
		unzippedData, err := io.ReadAll(r)
		if err != nil {
			data.Body = err.Error()
		} else {
			data.Body = string(unzippedData)
		}

	default:
		data.Body = string(rb)
	}

	r.sendChan <- &data
	return nil
}
