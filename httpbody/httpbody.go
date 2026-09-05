// Package httpbody 提供响应正文的解压能力，供抓取与改包共用。
package httpbody

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// zstd 解码器可复用且并发安全，避免每个响应都新建一次
var zstdDecoder, _ = zstd.NewReader(nil)

// IsCompressed 判断该 Content-Encoding 是否是我们能处理的压缩格式。
func IsCompressed(contentEncoding string) bool {
	switch normalize(contentEncoding) {
	case "gzip", "br", "zstd":
		return true
	}
	return false
}

// Decode 按 Content-Encoding 解压正文。未压缩或无法识别的编码原样返回。
func Decode(contentEncoding string, raw []byte) ([]byte, error) {
	switch normalize(contentEncoding) {
	case "zstd":
		if zstdDecoder == nil {
			return nil, errors.New("zstd 解码器不可用")
		}
		return zstdDecoder.DecodeAll(raw, nil)
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
	default:
		return raw, nil
	}
}

func normalize(contentEncoding string) string {
	return strings.ToLower(strings.TrimSpace(contentEncoding))
}
