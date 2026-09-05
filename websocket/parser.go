// Package websocket 解析 WebSocket 帧。
//
// goproxy 对 WebSocket 只做裸 io.Copy 转发，中间没有回调，
// 因此这里的解析器被设计成纯旁路观察者：字节原样透传，
// 解析失败也绝不影响转发，避免为了看帧把连接弄坏。
package websocket

import (
	"encoding/binary"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
)

// 帧类型
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

func opcodeName(op byte) string {
	switch op {
	case OpcodeContinuation:
		return "continuation"
	case OpcodeText:
		return "text"
	case OpcodeBinary:
		return "binary"
	case OpcodeClose:
		return "close"
	case OpcodePing:
		return "ping"
	case OpcodePong:
		return "pong"
	default:
		return "unknown"
	}
}

// maxPending 限制等待凑齐帧头时的缓冲上限。
// 帧头最长 14 字节，缓冲远超这个值说明流已经错位，直接放弃解析。
const maxPending = 64 << 10

// maxFrameLen 是认为合理的单帧载荷上限。
// RFC 6455 允许到 2^63，但真实实现不会发这么大的帧：
// 声明值超过这个上限说明流已经错位，此时"跳过声明的字节数"
// 会让我们永久丢弃后续所有数据，还不如直接放弃解析。
const maxFrameLen = 64 << 20

// Parser 增量解析单个方向的帧流。
//
// 一次 Read/Write 拿到的字节可能只是半个帧，也可能包含多个帧，
// 所以必须跨调用保持状态。
type Parser struct {
	direction models.WSDirection
	// maxCapture 是单帧最多留存的载荷字节数
	maxCapture int
	emit       func(models.WSFrame)

	buf []byte
	// skip 大于 0 时表示正在丢弃超长载荷的剩余部分，
	// 这样大帧不会把内存吃光
	skip int64
	// broken 为 true 后不再尝试解析：流已错位，继续猜只会产生垃圾
	broken bool
}

func NewParser(direction models.WSDirection, maxCapture int, emit func(models.WSFrame)) *Parser {
	if maxCapture <= 0 {
		maxCapture = 4 << 10
	}
	return &Parser{direction: direction, maxCapture: maxCapture, emit: emit}
}

// Feed 投入新到达的字节。调用方必须在转发之后调用，且不得修改 b。
func (p *Parser) Feed(b []byte) {
	if p.broken || len(b) == 0 {
		return
	}

	// 先消化正在丢弃的超长载荷
	if p.skip > 0 {
		n := int64(len(b))
		if n <= p.skip {
			p.skip -= n
			return
		}
		b = b[p.skip:]
		p.skip = 0
	}

	p.buf = append(p.buf, b...)
	for p.parseOne() {
	}

	if len(p.buf) > maxPending {
		// 缓冲远超帧头上限说明流已错位，放弃解析但不影响转发
		p.broken = true
		p.buf = nil
	}
}

// parseOne 尝试解析一个完整帧，返回是否成功消费了数据。
func (p *Parser) parseOne() bool {
	if len(p.buf) < 2 {
		return false
	}

	b0, b1 := p.buf[0], p.buf[1]
	fin := b0&0x80 != 0
	// RSV1 在协商了 permessage-deflate 时表示该消息载荷被 deflate 压缩
	compressed := b0&0x40 != 0
	opcode := b0 & 0x0F
	masked := b1&0x80 != 0

	offset := 2
	var payloadLen int64
	switch n := b1 & 0x7F; n {
	case 126:
		if len(p.buf) < offset+2 {
			return false
		}
		payloadLen = int64(binary.BigEndian.Uint16(p.buf[offset : offset+2]))
		offset += 2
	case 127:
		if len(p.buf) < offset+8 {
			return false
		}
		v := binary.BigEndian.Uint64(p.buf[offset : offset+8])
		// 最高位必须为 0，否则不是合法长度
		if v > 1<<63-1 {
			p.broken = true
			return false
		}
		payloadLen = int64(v)
		offset += 8
	default:
		payloadLen = int64(n)
	}

	var maskKey []byte
	if masked {
		if len(p.buf) < offset+4 {
			return false
		}
		maskKey = p.buf[offset : offset+4]
		offset += 4
	}

	// 声明长度明显不合理，说明流已错位。继续按它跳过会永久丢弃后续数据
	if payloadLen > maxFrameLen {
		p.broken = true
		p.buf = nil
		return false
	}


	frame := models.WSFrame{
		Date:       time.Now().Format(time.DateTime),
		Direction:  p.direction,
		Fin:        fin,
		Opcode:     opcode,
		OpcodeName: opcodeName(opcode),
		Masked:     masked,
		Compressed: compressed,
		PayloadLen: payloadLen,
	}

	// 超过留存上限的载荷只取前一段，其余直接丢弃，不进内存
	capture := payloadLen
	if capture > int64(p.maxCapture) {
		capture = int64(p.maxCapture)
		frame.Truncated = true
	}

	if int64(len(p.buf)) < int64(offset)+capture {
		// 头已完整但载荷还没到齐，等下一批字节
		return false
	}

	payload := make([]byte, capture)
	copy(payload, p.buf[offset:int64(offset)+capture])
	if masked {
		unmask(payload, maskKey, 0)
	}
	frame.Payload = payload

	consumed := int64(offset) + payloadLen
	if int64(len(p.buf)) >= consumed {
		p.buf = p.buf[consumed:]
	} else {
		// 剩余载荷还没到，记下要丢弃的字节数
		p.skip = consumed - int64(len(p.buf))
		p.buf = nil
	}

	if p.emit != nil {
		p.emit(frame)
	}
	return len(p.buf) >= 2
}

// unmask 按 RFC 6455 的规则异或还原载荷。
// offset 是该段载荷在整帧中的起始位置，用于跨段时对齐掩码下标。
func unmask(payload, key []byte, offset int) {
	if len(key) != 4 {
		return
	}
	for i := range payload {
		payload[i] ^= key[(i+offset)%4]
	}
}
