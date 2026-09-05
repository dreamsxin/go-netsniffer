package websocket

import (
	"encoding/binary"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
)

// buildFrame 按 RFC 6455 拼一个帧
func buildFrame(fin bool, opcode byte, masked bool, compressed bool, payload []byte) []byte {
	var b0 byte = opcode
	if fin {
		b0 |= 0x80
	}
	if compressed {
		b0 |= 0x40
	}

	out := []byte{b0}
	n := len(payload)
	switch {
	case n < 126:
		b1 := byte(n)
		if masked {
			b1 |= 0x80
		}
		out = append(out, b1)
	case n <= 0xFFFF:
		b1 := byte(126)
		if masked {
			b1 |= 0x80
		}
		out = append(out, b1)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(n))
		out = append(out, ext...)
	default:
		b1 := byte(127)
		if masked {
			b1 |= 0x80
		}
		out = append(out, b1)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		out = append(out, ext...)
	}

	if masked {
		key := []byte{0x11, 0x22, 0x33, 0x44}
		out = append(out, key...)
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ key[i%4]
		}
		out = append(out, masked...)
		return out
	}
	return append(out, payload...)
}

func collect() (*[]models.WSFrame, func(models.WSFrame)) {
	frames := &[]models.WSFrame{}
	return frames, func(f models.WSFrame) { *frames = append(*frames, f) }
}

func TestParseUnmaskedTextFrame(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	p.Feed(buildFrame(true, OpcodeText, false, false, []byte("hello")))

	if len(*frames) != 1 {
		t.Fatalf("帧数 = %d, want 1", len(*frames))
	}
	f := (*frames)[0]
	if f.OpcodeName != "text" || !f.Fin || f.Masked {
		t.Errorf("帧头解析错误: %+v", f)
	}
	if string(f.Payload) != "hello" {
		t.Errorf("Payload = %q", f.Payload)
	}
	if f.Direction != models.WSDirectionRecv {
		t.Errorf("Direction = %s", f.Direction)
	}
}

// 客户端发出的帧一定带掩码，必须还原
func TestParseMaskedFrameIsUnmasked(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionSend, 1024, emit)

	p.Feed(buildFrame(true, OpcodeText, true, false, []byte("masked-payload")))

	f := (*frames)[0]
	if !f.Masked {
		t.Error("应识别出掩码标记")
	}
	if string(f.Payload) != "masked-payload" {
		t.Errorf("掩码未还原: %q", f.Payload)
	}
}

// 一次 Read 可能只拿到半个帧，必须跨调用保持状态
func TestParseSplitAcrossFeeds(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	full := buildFrame(true, OpcodeText, false, false, []byte("split-me-please"))
	for i := 0; i < len(full); i++ {
		p.Feed(full[i : i+1])
	}

	if len(*frames) != 1 {
		t.Fatalf("帧数 = %d, want 1", len(*frames))
	}
	if string((*frames)[0].Payload) != "split-me-please" {
		t.Errorf("Payload = %q", (*frames)[0].Payload)
	}
}

// 一次 Read 也可能包含多个帧
func TestParseMultipleFramesInOneFeed(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	var buf []byte
	buf = append(buf, buildFrame(true, OpcodeText, false, false, []byte("one"))...)
	buf = append(buf, buildFrame(true, OpcodeBinary, false, false, []byte{1, 2, 3})...)
	buf = append(buf, buildFrame(true, OpcodePing, false, false, nil)...)
	p.Feed(buf)

	if len(*frames) != 3 {
		t.Fatalf("帧数 = %d, want 3", len(*frames))
	}
	if (*frames)[0].OpcodeName != "text" ||
		(*frames)[1].OpcodeName != "binary" ||
		(*frames)[2].OpcodeName != "ping" {
		t.Errorf("帧类型顺序错误: %v", *frames)
	}
}

func TestParseExtendedLength16(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1<<20, emit)

	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	p.Feed(buildFrame(true, OpcodeBinary, false, false, payload))

	f := (*frames)[0]
	if f.PayloadLen != 300 {
		t.Errorf("PayloadLen = %d, want 300", f.PayloadLen)
	}
	if len(f.Payload) != 300 {
		t.Errorf("留存载荷长度 = %d", len(f.Payload))
	}
}

func TestParseExtendedLength64(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1<<20, emit)

	payload := make([]byte, 70000)
	p.Feed(buildFrame(true, OpcodeBinary, false, false, payload))

	f := (*frames)[0]
	if f.PayloadLen != 70000 {
		t.Errorf("PayloadLen = %d, want 70000", f.PayloadLen)
	}
}

// 超过上限的载荷只留前一段，其余不进内存
func TestParseTruncatesLargePayload(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 16, emit)

	payload := make([]byte, 500)
	for i := range payload {
		payload[i] = 'x'
	}
	p.Feed(buildFrame(true, OpcodeBinary, false, false, payload))

	if len(*frames) != 1 {
		t.Fatalf("帧数 = %d, want 1", len(*frames))
	}
	f := (*frames)[0]
	if !f.Truncated {
		t.Error("应标记 Truncated")
	}
	if len(f.Payload) != 16 {
		t.Errorf("留存载荷长度 = %d, want 16", len(f.Payload))
	}
	if f.PayloadLen != 500 {
		t.Errorf("PayloadLen 应是完整长度, 得到 %d", f.PayloadLen)
	}
}

// 截断后剩余载荷要被正确丢弃，否则会把下一帧的头当成载荷
func TestParseResyncsAfterTruncatedPayload(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 8, emit)

	var buf []byte
	buf = append(buf, buildFrame(true, OpcodeBinary, false, false, make([]byte, 200))...)
	buf = append(buf, buildFrame(true, OpcodeText, false, false, []byte("next"))...)
	p.Feed(buf)

	if len(*frames) != 2 {
		t.Fatalf("帧数 = %d, want 2", len(*frames))
	}
	if string((*frames)[1].Payload) != "next" {
		t.Errorf("第二帧载荷 = %q, 说明丢弃逻辑没对齐", (*frames)[1].Payload)
	}
}

// 超长载荷跨多次 Feed 时同样要正确丢弃
func TestParseSkipSpansFeeds(t *testing.T) {
	frames, emit := collect()
	// 上限取 8：足以容纳第二帧的 "after"，但会截断第一帧的 100 字节
	p := NewParser(models.WSDirectionRecv, 8, emit)

	full := buildFrame(true, OpcodeBinary, false, false, make([]byte, 100))
	next := buildFrame(true, OpcodeText, false, false, []byte("after"))

	p.Feed(full[:20])
	p.Feed(full[20:])
	p.Feed(next)

	if len(*frames) != 2 {
		t.Fatalf("帧数 = %d, want 2", len(*frames))
	}
	if string((*frames)[1].Payload) != "after" {
		t.Errorf("第二帧载荷 = %q", (*frames)[1].Payload)
	}
}

func TestParseCompressedFlag(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	p.Feed(buildFrame(true, OpcodeText, false, true, []byte("compressed")))

	if !(*frames)[0].Compressed {
		t.Error("RSV1 置位应标记为 Compressed")
	}
}

func TestParseControlFrames(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	p.Feed(buildFrame(true, OpcodeClose, false, false, []byte{0x03, 0xE8}))
	p.Feed(buildFrame(true, OpcodePong, false, false, nil))

	if (*frames)[0].OpcodeName != "close" {
		t.Errorf("opcode = %s", (*frames)[0].OpcodeName)
	}
	if (*frames)[1].OpcodeName != "pong" {
		t.Errorf("opcode = %s", (*frames)[1].OpcodeName)
	}
}

func TestParseContinuationFrame(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	p.Feed(buildFrame(false, OpcodeText, false, false, []byte("part1")))
	p.Feed(buildFrame(true, OpcodeContinuation, false, false, []byte("part2")))

	if len(*frames) != 2 {
		t.Fatalf("帧数 = %d", len(*frames))
	}
	if (*frames)[0].Fin {
		t.Error("第一帧 Fin 应为 false")
	}
	if (*frames)[1].OpcodeName != "continuation" {
		t.Errorf("opcode = %s", (*frames)[1].OpcodeName)
	}
}

// 流错位后应停止解析，不能持续产生垃圾帧或无限增长缓冲
func TestParseGivesUpOnGarbage(t *testing.T) {
	_, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)

	// 声明一个巨大的载荷长度但永远不给数据，缓冲会一直等
	header := []byte{0x82, 127}
	ext := make([]byte, 8)
	binary.BigEndian.PutUint64(ext, 1<<40)
	header = append(header, ext...)
	p.Feed(header)

	// 再灌入超过缓冲上限的垃圾
	garbage := make([]byte, maxPending+1024)
	p.Feed(garbage)

	if !p.broken {
		t.Error("流错位后应放弃解析")
	}
	if p.buf != nil {
		t.Error("放弃解析后应释放缓冲")
	}
}

func TestFeedIgnoredAfterBroken(t *testing.T) {
	frames, emit := collect()
	p := NewParser(models.WSDirectionRecv, 1024, emit)
	p.broken = true

	p.Feed(buildFrame(true, OpcodeText, false, false, []byte("ignored")))
	if len(*frames) != 0 {
		t.Error("放弃解析后不应再产生帧")
	}
}
