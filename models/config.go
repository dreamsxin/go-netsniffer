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
}

type IP struct {
	Status  int    // 0 未启动 1 启动中 2 已启动
	Device  string // 网络设备的名称，如eth0,也可以填充pcap.FindAllDevs()返回的设备的Name
	Snaplen int32  // 每个数据包读取的最大长度，如果设置成1024，那么每次读取的数据包最大长度为1024字节
	Promisc bool   // 是否将网口设置为混杂模式，如果设置成true，那么网卡会将所有的数据包都抓到
	Timeout int64  // 设置抓到包返回的超时时间，单位为毫秒
	Filter  string
}

type Config struct {
	HTTP HTTP
	IP   IP
}

// DefaultConfig 返回一份完整的默认配置，作为配置文件缺失或字段缺省时的基准。
func DefaultConfig() Config {
	return Config{
		HTTP: HTTP{
			Port:        9000,
			AutoProxy:   true,
			SaveLogFile: false,
			MaxBodySize: 1 << 20, // 1MB
			Rule:        DefaultRule,
		},
		IP: IP{
			Snaplen: 1600, // 覆盖标准以太网帧的完整长度
			Promisc: true,
			Timeout: 1000,
			Filter:  "tcp and port 80",
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
