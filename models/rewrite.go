package models

// RewritePhase 指明规则作用在请求还是响应上
type RewritePhase string

const (
	RewritePhaseRequest  RewritePhase = "request"
	RewritePhaseResponse RewritePhase = "response"
)

// Replacement 是一次正文字符串替换
type Replacement struct {
	From string `json:"From"`
	To   string `json:"To"`
}

// RewriteRule 描述一条改包规则。
//
// 匹配条件全部为空表示匹配所有流量，因此新增规则时务必至少填一个条件，
// 否则会影响到全部请求。
type RewriteRule struct {
	// Enabled 为 false 时规则被忽略，便于临时停用而不必删除
	Enabled bool `json:"Enabled"`
	// Name 仅用于界面展示与日志
	Name string `json:"Name"`
	// Phase 为 request 或 response，留空按 request 处理
	Phase RewritePhase `json:"Phase"`
	// URLRegex 是作用于完整 URL 的正则，留空表示不限制
	URLRegex string `json:"URLRegex,omitempty"`
	// Method 限定请求方法，留空表示不限制
	Method string `json:"Method,omitempty"`

	// SetHeaders 设置或覆盖头
	SetHeaders map[string]string `json:"SetHeaders,omitempty"`
	// RemoveHeaders 删除指定的头
	RemoveHeaders []string `json:"RemoveHeaders,omitempty"`
	// Replacements 对正文做字符串替换。
	// 压缩过的响应会先解压再替换，并去掉 Content-Encoding。
	Replacements []Replacement `json:"Replacements,omitempty"`
	// StatusCode 改写响应状态码，0 表示不改。仅对 response 阶段有效
	StatusCode int `json:"StatusCode,omitempty"`
}

// DefaultRewriteRules 是写进配置的示例，默认全部停用，
// 让用户看到可用字段而不会意外改动流量。
const DefaultRewriteRules = `[
  {
    "Enabled": false,
    "Name": "示例：改写 User-Agent",
    "Phase": "request",
    "URLRegex": "",
    "SetHeaders": { "User-Agent": "go-netsniffer" }
  },
  {
    "Enabled": false,
    "Name": "示例：强制不走缓存",
    "Phase": "request",
    "RemoveHeaders": ["If-None-Match", "If-Modified-Since"]
  },
  {
    "Enabled": false,
    "Name": "示例：替换响应正文并模拟 500",
    "Phase": "response",
    "URLRegex": "example\\.com/api",
    "StatusCode": 500,
    "Replacements": [{ "From": "\"code\":0", "To": "\"code\":1" }]
  }
]`
