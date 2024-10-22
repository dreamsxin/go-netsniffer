package models

import (
	"net/http"
	"time"
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

type IPPacketType int

const (
	IPPacketType_TCP IPPacketType = iota
	IPPacketType_UDP
)

type IPPacket struct {
	Date         string
	DateTime     time.Time
	IPPacketType IPPacketType `json:"IPPacketType,omitempty"`
	IPVersion    int          `json:"IPVersion,omitempty"`
	// Ethernet
	SrcMAC       string `json:"SrcMAC,omitempty"`
	DstMAC       string `json:"DstMAC,omitempty"`
	EthernetType uint16 `json:"EthernetType,omitempty"`
	Length       uint16 `json:"Length,omitempty"`
	// IPv4
	SrcIP    string `json:"SrcIP,omitempty"`
	DstIP    string `json:"DstIP,omitempty"`
	Protocol uint8  `json:"Protocol,omitempty"`
	// TCP/UDP
	SrcPort uint16 `json:"SrcPort,omitempty"`
	DstPort uint16 `json:"DstPort,omitempty"`
	// Application
	ApplicationLayer string `json:"ApplicationLayer,omitempty"`
	Payload          string `json:"Payload,omitempty"`
}
