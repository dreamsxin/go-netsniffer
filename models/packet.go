package models

import (
	"net/http"
	"time"
)

type PacketType int

const (
	PacketType_HTTP PacketType = iota
	PacketType_TCP  PacketType = iota
)

type Packet struct {
	PacketType PacketType
	HTTP       HTTPPacket
	TCP        TCPPacket
}

type HTTPPacketType int

const (
	HTTPPacketType_REQUEST  HTTPPacketType = iota
	HTTPPacketType_RESPONSE HTTPPacketType = iota
)

type HTTPPacket struct {
	Date           string
	DateTime       time.Time
	HTTPPacketType HTTPPacketType `json:"HTTPPacketType,omitempty"`
	Proto          string         `json:"Proto,omitempty"`      // "HTTP/1.0"
	ProtoMajor     int            `json:"ProtoMajor,omitempty"` // 1
	ProtoMinor     int            `json:"ProtoMinor,omitempty"` // 0
	Method         string         `json:"Method,omitempty"`
	Host           string         `json:"Host,omitempty"`
	Path           string         `json:"Path,omitempty"`
	URL            string         `json:"URL,omitempty"`
	Header         http.Header    `json:"Header,omitempty"`
	Body           string         `json:"Body,omitempty"`
	Status         string         `json:"Status,omitempty"`     // e.g. "200 OK"
	StatusCode     int            `json:"StatusCode,omitempty"` // e.g. 200
	ContentType    string         `json:"ContentType,omitempty"`
	ContentLength  int64          `json:"ContentLength,omitempty"`
}

type TCPPacket struct {
	Date      string
	DateTime  time.Time
	LayerType int64 `json:"LayerType,omitempty"` // layers.LayerTypeEthernet layers.LayerTypeIPv4 layers.LayerTypeTCP
	// Ethernet
	SrcMAC       []byte `json:"SrcMAC,omitempty"`
	DstMAC       []byte `json:"DstMAC,omitempty"`
	EthernetType uint16 `json:"EthernetType,omitempty"`
	Length       uint16 `json:"Length,omitempty"`
	// IPv4
	SrcIP    string `json:"SrcIP,omitempty"`
	DstIP    string `json:"DstIP,omitempty"`
	Protocol uint8  `json:"Protocol,omitempty"`
	// TCP
	SrcPort uint16 `json:"SrcPort,omitempty"`
	DstPort uint16 `json:"DstPort,omitempty"`
}
