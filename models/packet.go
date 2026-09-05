package models

import (
	"net/http"
)

type PacketType int

const (
	PacketType_HTTP PacketType = iota
	PacketType_IP
)

type Packet struct {
	PacketType PacketType
	HTTP       HTTPPacket
	IP         IPPacket
}

type HTTPPacketType int

const (
	HTTPPacketType_REQUEST HTTPPacketType = iota
	HTTPPacketType_RESPONSE
	// HTTPPacketType_TUNNEL 表示按规则未解密、以隧道方式转发的 CONNECT 连接
	HTTPPacketType_TUNNEL
)

type HTTPPacket struct {
	Date string
	// ID 用于把请求与对应的响应配对，同一次往返的两条记录 ID 相同
	ID             string         `json:"ID,omitempty"`
	HTTPPacketType HTTPPacketType `json:"HTTPPacketType,omitempty"`
	Proto          string         `json:"Proto,omitempty"`      // "HTTP/1.0"
	ProtoMajor     int            `json:"ProtoMajor,omitempty"` // 1
	ProtoMinor     int            `json:"ProtoMinor,omitempty"` // 0
	Method         string         `json:"Method,omitempty"`
	Host           string         `json:"Host,omitempty"`
	Path           string         `json:"Path,omitempty"`
	URL            string         `json:"URL,omitempty"`
	Header        http.Header `json:"Header,omitempty"`
	Body          string      `json:"Body,omitempty"`
	// BodyTruncated 表示 Body 只是前 MaxBodySize 字节。
	// 重放这类请求会发出不完整的数据，必须先提醒用户。
	BodyTruncated bool   `json:"BodyTruncated,omitempty"`
	Status        string `json:"Status,omitempty"`     // e.g. "200 OK"
	StatusCode    int    `json:"StatusCode,omitempty"` // e.g. 200
	ContentType    string         `json:"ContentType,omitempty"`
	ContentLength  int64          `json:"ContentLength,omitempty"`
	// Duration 为该次往返的耗时（毫秒），只在响应记录上有值
	Duration int64 `json:"Duration,omitempty"`
	// ResourceType 是按 Content-Type 归纳的大类，界面据此选择预览方式
	ResourceType ResourceType `json:"ResourceType,omitempty"`
	// Suffix 是推断出的文件后缀，下载时用于拼文件名
	Suffix string `json:"Suffix,omitempty"`
	// RequestHeader 只在响应记录上有值。
	// 保留它是为了下载时能原样重放请求头，绕过 Referer / 防盗链校验；
	// 这样就不必把响应体缓存在内存里。
	RequestHeader http.Header `json:"RequestHeader,omitempty"`
}

// ReplayRequest 是界面提交的重放请求，允许在原记录基础上修改后再发送。
type ReplayRequest struct {
	Method string      `json:"Method"`
	URL    string      `json:"URL"`
	Header http.Header `json:"Header,omitempty"`
	Body   string      `json:"Body,omitempty"`
}

type IPPacketType int

const (
	IPPacketType_TCP IPPacketType = iota
	IPPacketType_UDP
)

type IPPacket struct {
	Date         string
	IPPacketType IPPacketType `json:"IPPacketType,omitempty"`
	IPVersion    int          `json:"IPVersion,omitempty"`
	// Ethernet
	EthernetType uint16 `json:"EthernetType,omitempty"`
	SrcMAC       string `json:"SrcMAC,omitempty"`
	DstMAC       string `json:"DstMAC,omitempty"`
	// Length 为整帧的抓取长度
	Length uint16 `json:"Length,omitempty"`
	// IPv4/IPv6
	SrcIP    string `json:"SrcIP,omitempty"`
	DstIP    string `json:"DstIP,omitempty"`
	Protocol uint8  `json:"Protocol,omitempty"`
	// TCP/UDP
	Seq     uint32 `json:"Seq,omitempty"`
	SrcPort uint16 `json:"SrcPort,omitempty"`
	DstPort uint16 `json:"DstPort,omitempty"`
	// Application
	// 各层的 Payload 是逐层嵌套的同一份数据，只保留最内层一份，
	// 否则单个报文会携带 4 份重复副本再经 base64 推送到界面。
	ApplicationLayer   string `json:"ApplicationLayer,omitempty"`
	ApplicationPayload []byte `json:"ApplicationPayload,omitempty"`
}
