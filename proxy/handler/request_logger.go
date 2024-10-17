package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const authorityName string = "Local Proxy Authority"

// RequestLogger is a RequestModifier logs all request url
type RequestLogger struct {
	ctx context.Context
}

func NewRequestLogger(ctx context.Context) *RequestLogger {
	return &RequestLogger{ctx: ctx}
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

	if req.Method == "OPTIONS" || req.Method == "CONNECT" {
		return nil
	}
	var data models.Packet
	data.PacketType = models.REQUEST
	data.Date = time.Now()
	data.Proto = req.Proto
	data.ProtoMajor = req.ProtoMajor
	data.ProtoMinor = req.ProtoMinor
	data.Method = req.Method
	data.Host = req.Host
	data.URL = req.URL.String()
	data.Header = req.Header
	log.Println("ModifyRequest", data.URL)

	rb, _ := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewBuffer(rb))
	data.Body = string(rb)
	runtime.EventsEmit(r.ctx, "Packet", data)
	return nil
}

// 从返回中获取 cookie
func (r *RequestLogger) ModifyResponse(resp *http.Response) error {
	if resp.Request.Method == "OPTIONS" || resp.Request.Method == "CONNECT" {
		return nil
	}
	var data models.Packet
	data.PacketType = models.RESPONSE
	data.Date = time.Now()
	data.Proto = resp.Proto
	data.ProtoMajor = resp.ProtoMajor
	data.ProtoMinor = resp.ProtoMinor
	data.Method = resp.Request.Method
	data.Host = resp.Request.Host
	data.URL = resp.Request.URL.String()
	data.Header = resp.Header
	data.ContentLength = resp.ContentLength

	log.Println("ModifyResponse", data.URL)

	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(rb))

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		// 解压gzip数据
		r, err := gzip.NewReader(bytes.NewBuffer(rb))
		if err != nil {
			panic(err)
		}
		defer r.Close()

		// 读取解压后的数据
		unzippedData, err := io.ReadAll(r)
		if err != nil {
			data.Body = err.Error()
		} else {
			data.Body = string(unzippedData)
		}
	case "br":
		r := brotli.NewReader(bytes.NewBuffer(rb))

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

	runtime.EventsEmit(r.ctx, "Packet", data)
	return nil
}
