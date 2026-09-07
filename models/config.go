package models

// DefaultRule 默认解密全部域名，并排除已知会做证书固定的域名。
// 这些域名一旦被解密，对应客户端会直接握手失败，表现为无法联网。
const DefaultRule = `# 语法：* 全部匹配，*.a.com 匹配域名及子域，!前缀 表示排除，# 为注释
# 顺序生效，后面的规则覆盖前面的
*
!*.weixin.qq.com
!*.wechat.com
!*.icloud.com
!*.apple.com
!*.windowsupdate.com
`


type HTTP struct {
	Status        int // 0 未启动 1 启动中 2 已启动
	Port          int
	AutoProxy     bool
	SaveLogFile   bool
	Filter        bool
	FilterHost    string
	ResourceTypes []string
	// 单个报文最多记录的 Body 字节数，超出部分截断，避免大响应打爆内存与前端
	MaxBodySize int64
	// 上游代理，形如 http://127.0.0.1:7890，留空表示直连
	UpstreamProxy string
	// Rule 决定哪些域名的 HTTPS 需要解密，语法见 rule 包。
	// 对做了证书固定的客户端必须排除，否则它们会直接握手失败。
	Rule string
	// AllowHTTP2 允许与客户端协商 HTTP/2。关闭时所有连接被降级为 HTTP/1.1，
	// 与真实环境有差异；开启后个别站点可能出现兼容问题，因此默认关闭。
	AllowHTTP2 bool
	// DownloadDir 是下载资源的默认保存目录，留空表示每次询问
	DownloadDir string
	// RewriteRules 是改包规则的 JSON 文本，见 RewriteRule。
	// 用文本保存是为了让用户能整段复制粘贴与版本管理。
	RewriteRules string
	// MapRules 是 Map Local / Map Remote 规则的 JSON 文本，见 MapRule
	MapRules string
	// Breakpoint 是断点配置。断点会真的把请求挂住，默认关闭。
	Breakpoint BreakpointConfig
	// WebSocket 控制是否解析 WebSocket 帧，默认关闭
	WebSocket WebSocketConfig
}

type IP struct {
	Status  int    // 0 未启动 1 启动中 2 已启动
	Device  string // 网络设备的名称，如eth0,也可以填充pcap.FindAllDevs()返回的设备的Name
	Snaplen int32  // 每个数据包读取的最大长度，如果设置成1024，那么每次读取的数据包最大长度为1024字节
	Promisc bool   // 是否将网口设置为混杂模式，如果设置成true，那么网卡会将所有的数据包都抓到
	Timeout int64  // 设置抓到包返回的超时时间，单位为毫秒
	Filter  string
	// SavePcapFile 抓包时同步写入 pcap 文件，可直接用 Wireshark 打开。
	// 采用流式写入，不占用额外内存。
	SavePcapFile bool
	// TCPStream 控制是否把报文重组成 TCP 流，默认关闭
	TCPStream TCPStreamConfig
}

type Config struct {
	HTTP HTTP
	IP   IP
}

// AppStatus 是界面需要的运行状态汇总。
// 状态由后端推送而不是前端轮询：代理可能自己异常停止，
// 只在按钮点击后刷新会让界面显示与实际不符。
type AppStatus struct {
	// HTTPStatus 与 IPStatus 取值同 HTTP.Status：0 未启动 1 启动中 2 已启动
	HTTPStatus int `json:"HTTPStatus"`
	IPStatus   int `json:"IPStatus"`
	// Port 是代理实际监听的端口
	Port int `json:"Port"`
	// AutoProxy 表示是否由本程序接管了系统代理
	AutoProxy bool `json:"AutoProxy"`
	// Cert 是根证书的真实状态
	Cert CertStatus `json:"Cert"`
	// RewriteRuleCount 是生效中的改包规则条数
	RewriteRuleCount int `json:"RewriteRuleCount"`
	// MapRuleCount 是生效中的映射规则条数。命中的请求不按原地址发出，
	// 开着忘了关很容易让人误判接口行为，因此界面要一直显示
	MapRuleCount int `json:"MapRuleCount"`
	// BreakpointEnabled 与 PendingBreakpoints 用于提醒用户断点正开着、有请求被挂住
	BreakpointEnabled  bool `json:"BreakpointEnabled"`
	PendingBreakpoints int  `json:"PendingBreakpoints"`
}

// CertStatus 描述根证书的真实状态，供界面给出准确提示。
// 只判断文件是否存在会误导用户：文件在不等于系统已经信任它。
type CertStatus struct {
	// Generated 表示证书与私钥文件都已生成
	Generated bool `json:"Generated"`
	// TrustedScopes 是已信任该证书的存储范围，可能包含 "machine" 与 "user"
	TrustedScopes []string `json:"TrustedScopes"`
	// CertPath 是根证书路径，Firefox 等自带证书库的程序需要手工导入它
	CertPath string `json:"CertPath"`
	// NotAfter 是证书有效期截止日期，空表示未生成或无法解析
	NotAfter string `json:"NotAfter"`
}

// DefaultConfig 返回一份完整的默认配置，作为配置文件缺失或字段缺省时的基准。
func DefaultConfig() Config {
	return Config{
		HTTP: HTTP{
			Port:        9000,
			AutoProxy:   true,
			SaveLogFile: false,
			MaxBodySize: 1 << 20, // 1MB
			Rule:         DefaultRule,
			RewriteRules: DefaultRewriteRules,
			MapRules:     DefaultMapRules,
			Breakpoint:   DefaultBreakpointConfig(),
			WebSocket:    DefaultWebSocketConfig(),
		},
		IP: IP{
			Snaplen: 1600, // 覆盖标准以太网帧的完整长度
			Promisc: true,
			Timeout: 1000,
			Filter:  "tcp and port 80",
			TCPStream: DefaultTCPStreamConfig(),
		},
	}
}

// Normalize 修正非法或缺省的字段，保证运行期取到的值总是可用的。
func (c *Config) Normalize() {
	d := DefaultConfig()

	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		c.HTTP.Port = d.HTTP.Port
	}
	if c.HTTP.MaxBodySize <= 0 {
		c.HTTP.MaxBodySize = d.HTTP.MaxBodySize
	}
	c.HTTP.WebSocket.Normalize()
	c.IP.TCPStream.Normalize()
	if c.IP.Snaplen <= 0 {
		c.IP.Snaplen = d.IP.Snaplen
	}
	if c.IP.Timeout <= 0 {
		c.IP.Timeout = d.IP.Timeout
	}
	// 运行状态不持久化，每次启动都从未运行开始
	c.HTTP.Status = 0
	c.IP.Status = 0
}
