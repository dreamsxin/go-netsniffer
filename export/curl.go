package export

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/dreamsxin/go-netsniffer/models"
)

// curlSkipHeaders 是生成 curl 命令时要去掉的头。
// 长度与连接管理由 curl 自己处理，Host 从 URL 推导，
// 照抄原值只会让命令更长且可能不合法。
var curlSkipHeaders = map[string]bool{
	"content-length":    true,
	"connection":        true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"upgrade":           true,
	"host":              true,
	"proxy-connection":  true,
}

// Curl 把一条抓包记录转成可直接执行的 curl 命令。
//
// 采用 POSIX（bash）引号规则，这是"复制为 cURL"的通行约定。
// PowerShell 的单引号转义与 POSIX 不兼容（'' 而非 '\''），
// 在 PowerShell 里粘贴含单引号的正文会出错，此时请用 bash / WSL / Git Bash。
func Curl(packet models.HTTPPacket) (string, error) {
	if packet.URL == "" {
		return "", errors.New("该记录没有 URL，无法生成 curl 命令")
	}
	if packet.HTTPPacketType == models.HTTPPacketType_TUNNEL {
		return "", errors.New("隧道记录不是 HTTP 往返，无法生成 curl 命令")
	}

	// 请求记录带完整的请求头与请求体；
	// 响应记录只保留了请求头，请求体没有留存
	header := packet.Header
	body := packet.Body
	if packet.HTTPPacketType == models.HTTPPacketType_RESPONSE {
		header = packet.RequestHeader
		body = ""
	}

	method := strings.ToUpper(packet.Method)
	if method == "" {
		method = http.MethodGet
	}

	var b strings.Builder
	b.WriteString("curl")
	// GET 是 curl 的默认方法，无正文时写 -X GET 是噪音
	if !(method == http.MethodGet && body == "") {
		fmt.Fprintf(&b, " -X %s", method)
	}
	b.WriteString(" ")
	b.WriteString(shellQuote(packet.URL))

	for _, name := range sortedHeaderNames(header) {
		if curlSkipHeaders[strings.ToLower(name)] {
			continue
		}
		for _, value := range header[name] {
			fmt.Fprintf(&b, " -H %s", shellQuote(name+": "+value))
		}
	}

	if body != "" {
		// --data-raw 不对 @ 做特殊处理，避免正文以 @ 开头时被当成文件名
		fmt.Fprintf(&b, " --data-raw %s", shellQuote(body))
	}
	return b.String(), nil
}

func sortedHeaderNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// shellQuote 按 POSIX 规则加单引号。
// 单引号内除了 ' 本身没有任何转义，因此闭合后拼一个转义的引号再重开。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
