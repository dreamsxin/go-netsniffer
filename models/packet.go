package models

import (
	"net/http"
	"time"
)

type PacketType int

const (
	REQUEST  PacketType = iota
	RESPONSE PacketType = iota
)

type Packet struct {
	PacketType    PacketType
	Date          string
	DateTime      time.Time
	Proto         string // "HTTP/1.0"
	ProtoMajor    int    // 1
	ProtoMinor    int    // 0
	Method        string
	Host          string
	Path          string
	URL           string
	Header        http.Header
	Body          string
	Status        string // e.g. "200 OK"
	StatusCode    int    // e.g. 200
	ContentType   string
	ContentLength int64
}
