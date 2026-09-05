package models

// WSDirection 是帧的方向
type WSDirection string

const (
	// WSDirectionSend 客户端 -> 服务端
	WSDirectionSend WSDirection = "send"
	// WSDirectionRecv 服务端 -> 客户端
	WSDirectionRecv WSDirection = "recv"
)

// WSFrame 是一个已解析的 WebSocket 帧
type WSFrame struct {
	Date      string      `json:"Date"`
	Direction WSDirection `json:"Direction"`
	// ConnID 用于把同一条连接上的帧归到一起，取值同 HTTPPacket.ID
	ConnID string `json:"ConnID,omitempty"`
	// URL 是握手时的地址，便于区分多条连接
	URL string `json:"URL,omitempty"`

	Fin        bool   `json:"Fin"`
	Opcode     byte   `json:"Opcode"`
	OpcodeName string `json:"OpcodeName"`
	Masked     bool   `json:"Masked"`
	// Compressed 表示 RSV1 置位，即该消息载荷被 permessage-deflate 压缩。
	// 解压需要跨帧维护 deflate 上下文，目前只标记不解压
	Compressed bool `json:"Compressed"`
	// PayloadLen 是帧声明的完整载荷长度
	PayloadLen int64 `json:"PayloadLen"`
	// Payload 是留存的载荷，超过上限时只保留前一段
	Payload []byte `json:"Payload,omitempty"`
	// Truncated 表示 Payload 只是前一段
	Truncated bool `json:"Truncated,omitempty"`
}

// WebSocketConfig 控制 WebSocket 帧解析。
//
// 解析需要在转发路径上旁路观察每一个字节，属于调试用途，默认关闭。
type WebSocketConfig struct {
	Enabled bool `json:"Enabled"`
	// MaxPayloadBytes 是单帧最多留存的载荷字节数，
	// 超出部分直接丢弃不进内存，避免大帧把内存吃光
	MaxPayloadBytes int `json:"MaxPayloadBytes"`
}

func DefaultWebSocketConfig() WebSocketConfig {
	return WebSocketConfig{
		Enabled:         false,
		MaxPayloadBytes: 4 << 10, // 4KB
	}
}

// Normalize 修正非法值
func (c *WebSocketConfig) Normalize() {
	if c.MaxPayloadBytes <= 0 || c.MaxPayloadBytes > 1<<20 {
		c.MaxPayloadBytes = DefaultWebSocketConfig().MaxPayloadBytes
	}
}
