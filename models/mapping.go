package models

// MapKind 是映射规则的类型。
type MapKind string

const (
	// MapKindLocal 用本地文件充当响应，请求不会发到线上
	MapKindLocal MapKind = "local"
	// MapKindRemote 把请求转发到另一个地址，客户端不知情
	MapKindRemote MapKind = "remote"
)

// MapRule 是一条映射规则。
//
// 与改包规则的区别：改包是在真实往返的基础上做局部修改，
// 映射改变的是请求去哪里、响应从哪来。
type MapRule struct {
	Enabled bool    `json:"Enabled"`
	Name    string  `json:"Name,omitempty"`
	Kind    MapKind `json:"Kind"`

	// URLRegex 匹配完整 URL，留空不限制
	URLRegex string `json:"URLRegex,omitempty"`
	// Method 限定方法，留空不限制
	Method string `json:"Method,omitempty"`

	// File 是 local 用的本地文件路径。每次请求都重新读取，
	// 因此改完文件立即生效，不需要重启服务
	File string `json:"File,omitempty"`
	// StatusCode 是 local 返回的状态码，留空按 200
	StatusCode int `json:"StatusCode,omitempty"`
	// ContentType 留空时按文件后缀推断，推断不出用 application/octet-stream
	ContentType string `json:"ContentType,omitempty"`
	// Headers 是 local 响应上额外设置的头
	Headers map[string]string `json:"Headers,omitempty"`

	// To 是 remote 的目标地址，形如 http://127.0.0.1:8080。
	// 带路径时该路径会作为前缀拼在原路径之前
	To string `json:"To,omitempty"`
	// RewriteHost 把 Host 头也改成目标地址。
	// 默认不改：把线上域名指向本地服务时，通常正是要让对端看到原域名
	RewriteHost bool `json:"RewriteHost,omitempty"`
}

// DefaultMapRules 是写进配置的示例，默认全部停用，
// 让用户看到可用字段而不会意外改动流量。
const DefaultMapRules = `[
  {
    "Enabled": false,
    "Name": "示例：用本地文件顶替接口响应",
    "Kind": "local",
    "URLRegex": "example\\.com/api/config",
    "File": "D:\\mock\\config.json",
    "StatusCode": 200,
    "ContentType": "application/json; charset=utf-8"
  },
  {
    "Enabled": false,
    "Name": "示例：把线上域名指向本地服务",
    "Kind": "remote",
    "URLRegex": "^https://api\\.example\\.com/",
    "To": "http://127.0.0.1:8080",
    "RewriteHost": false
  }
]`
