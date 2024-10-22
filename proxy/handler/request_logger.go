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
	log.Println("ModifyRequest", data.HTTP.URL)
	if data.HTTP.ContentLength == 0 {
		data.HTTP.Body = "[no data]"
	} else {
		rb, _ := io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewBuffer(rb))
		data.HTTP.Body = string(rb)
	}

	r.sendChan <- &data
	return nil
}

// 从返回中获取 cookie
func (r *RequestLogger) ModifyResponse(resp *http.Response) error {
	var data models.Packet
	data.PacketType = models.PacketType_HTTP
	data.HTTP.HTTPPacketType = models.HTTPPacketType_RESPONSE
	data.HTTP.Date = time.Now().Format(time.DateTime)
	data.HTTP.Proto = resp.Proto
	data.HTTP.ProtoMajor = resp.ProtoMajor
	data.HTTP.ProtoMinor = resp.ProtoMinor
	data.HTTP.Method = resp.Request.Method
	data.HTTP.Host = resp.Request.Host
	data.HTTP.Path = resp.Request.URL.Path
	data.HTTP.URL = resp.Request.URL.String()
	data.HTTP.Header = resp.Header
	data.HTTP.Status = resp.Status
	data.HTTP.StatusCode = resp.StatusCode
	data.HTTP.ContentType = resp.Header.Get("Content-Type")
	data.HTTP.ContentLength = resp.ContentLength

	if data.HTTP.ContentLength == 0 {
		data.HTTP.Body = "[no data]"
	} else {
		contentType := resp.Header.Get("Content-Type")
		contentEncoding := resp.Header.Get("Content-Encoding")
		log.Println("ModifyResponse", contentType, contentEncoding, data.HTTP.URL)
		if contentType == "" || (!strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "json")) {
			data.HTTP.Body = "[binary data]" + contentType
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
				data.HTTP.Body = err.Error()
			} else {
				data.HTTP.Body = string(decompressdata)
			}
		case "gzip":
			// 解压gzip数据
			r, err := gzip.NewReader(bytes.NewReader(rb))
			if err != nil {
				data.HTTP.Body = err.Error()
			} else {
				defer r.Close()

				// 读取解压后的数据
				unzippedData, err := io.ReadAll(r)
				if err != nil {
					data.HTTP.Body = err.Error()
				} else {
					data.HTTP.Body = string(unzippedData)
				}
			}
		case "br":
			r := brotli.NewReader(bytes.NewReader(rb))

			// 读取解压后的数据
			unzippedData, err := io.ReadAll(r)
			if err != nil {
				data.HTTP.Body = err.Error()
			} else {
				data.HTTP.Body = string(unzippedData)
			}

		default:
			data.HTTP.Body = string(rb)
		}
	}

	r.sendChan <- &data
	return nil
}
