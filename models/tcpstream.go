package models

// TCPStreamSummary 是流列表里的一行。
// 只带元信息不带载荷：流是长期存在且持续变化的，
// 把载荷一起推给界面会让每次刷新都传输几百 KB。
type TCPStreamSummary struct {
	// ID 形如 1.2.3.4:1234-5.6.7.8:80，方向按首个报文判定
	ID string `json:"ID"`
	// Date 是首次看到该流的时间，Updated 是最后一次有数据的时间
	Date    string `json:"Date"`
	Updated string `json:"Updated"`

	ClientAddr string `json:"ClientAddr"`
	ServerAddr string `json:"ServerAddr"`
	// ClientBytes 与 ServerBytes 是重组出的总字节数，不受留存上限影响
	ClientBytes int64 `json:"ClientBytes"`
	ServerBytes int64 `json:"ServerBytes"`
	// MissingBytes 是重组时被跳过的字节数，非 0 说明有丢包，
	// 此时载荷内容不连续，不能当作完整流看
	MissingBytes int64 `json:"MissingBytes"`
	// Closed 表示已看到 FIN/RST 或因空闲被回收
	Closed bool `json:"Closed"`
}

// TCPStreamDetail 是"跟随流"视图的内容，按需单条获取。
type TCPStreamDetail struct {
	TCPStreamSummary
	ClientPayload []byte `json:"ClientPayload,omitempty"`
	ServerPayload []byte `json:"ServerPayload,omitempty"`
	// Truncated 表示对应方向只留存了前一段
	ClientTruncated bool `json:"ClientTruncated,omitempty"`
	ServerTruncated bool `json:"ServerTruncated,omitempty"`
}

// TCPStreamConfig 控制 TCP 流重组。
//
// 重组需要为每条连接维护缓冲与乱序页，属于调试用途，默认关闭。
type TCPStreamConfig struct {
	Enabled bool `json:"Enabled"`
	// MaxStreamBytes 是单向最多留存的字节数，超出部分不进内存
	MaxStreamBytes int `json:"MaxStreamBytes"`
	// MaxStreams 是最多同时跟踪的流数，超出后不再新建，
	// 避免扫描类流量把内存吃光
	MaxStreams int `json:"MaxStreams"`
	// IdleSeconds 是空闲多久后关闭并冲刷该流
	IdleSeconds int `json:"IdleSeconds"`
}

func DefaultTCPStreamConfig() TCPStreamConfig {
	return TCPStreamConfig{
		Enabled:        false,
		MaxStreamBytes: 64 << 10, // 64KB
		MaxStreams:     256,
		IdleSeconds:    60,
	}
}

// Normalize 修正非法值
func (c *TCPStreamConfig) Normalize() {
	d := DefaultTCPStreamConfig()
	if c.MaxStreamBytes <= 0 || c.MaxStreamBytes > 4<<20 {
		c.MaxStreamBytes = d.MaxStreamBytes
	}
	if c.MaxStreams <= 0 || c.MaxStreams > 4096 {
		c.MaxStreams = d.MaxStreams
	}
	if c.IdleSeconds <= 0 || c.IdleSeconds > 3600 {
		c.IdleSeconds = d.IdleSeconds
	}
}
