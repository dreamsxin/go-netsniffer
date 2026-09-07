package models

// ThrottleConfig 是弱网模拟配置。
//
// 用来复现慢网络下的表现：加载顺序、超时处理、进度条、骨架屏，
// 这些问题在本机千兆环境下基本看不出来。
type ThrottleConfig struct {
	Enabled bool `json:"Enabled"`
	// DownKbps 下行带宽上限（kbit/s），<=0 表示不限
	DownKbps int `json:"DownKbps"`
	// UpKbps 上行带宽上限（kbit/s），<=0 表示不限
	UpKbps int `json:"UpKbps"`
	// LatencyMs 每个请求额外增加的延迟（毫秒），用来模拟高 RTT
	LatencyMs int `json:"LatencyMs"`
	// URLRegex 限定生效范围，留空表示对全部流量生效
	URLRegex string `json:"URLRegex,omitempty"`
}

// 带宽与延迟的上限。限得太死会让请求看起来像挂死，
// 因此给出明确边界而不是任由用户填出无法使用的值。
const (
	maxThrottleKbps  = 1_000_000 // 1 Gbps
	maxThrottleDelay = 60_000    // 60 秒
)

func DefaultThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		Enabled: false,
		// 默认值对应常见的 3G 环境，开启后就能直接看到效果，
		// 不必先去猜该填多少
		DownKbps:  400,
		UpKbps:    400,
		LatencyMs: 200,
	}
}

// Normalize 把越界值收回可用范围。负数按"不限"处理，因此只截上限。
func (c *ThrottleConfig) Normalize() {
	if c.DownKbps < 0 {
		c.DownKbps = 0
	}
	if c.UpKbps < 0 {
		c.UpKbps = 0
	}
	if c.LatencyMs < 0 {
		c.LatencyMs = 0
	}
	if c.DownKbps > maxThrottleKbps {
		c.DownKbps = maxThrottleKbps
	}
	if c.UpKbps > maxThrottleKbps {
		c.UpKbps = maxThrottleKbps
	}
	if c.LatencyMs > maxThrottleDelay {
		c.LatencyMs = maxThrottleDelay
	}
}

// Effective 表示配置是否真的会产生限制。
// 开了开关但三项都是 0 等于没限速，界面不该显示成生效中。
func (c ThrottleConfig) Effective() bool {
	return c.Enabled && (c.DownKbps > 0 || c.UpKbps > 0 || c.LatencyMs > 0)
}
