package tcpstream

import (
	"net"
	"testing"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildPacket 造一个可被 Assemble 消费的 TCP 报文。
// toServer 为 true 表示 10.0.0.1:1234 -> 10.0.0.2:80。
func buildPacket(t *testing.T, toServer bool, seq uint32, payload string, syn, fin bool) gopacket.Packet {
	t.Helper()

	src, dst := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	srcPort, dstPort := layers.TCPPort(1234), layers.TCPPort(80)
	if !toServer {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    src,
		DstIP:    dst,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		SYN:     syn,
		FIN:     fin,
		ACK:     !syn,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("序列化报文失败: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	m := pkt.Metadata()
	m.Timestamp = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.CaptureLength = len(buf.Bytes())
	m.Length = len(buf.Bytes())
	return pkt
}

func newTracker(t *testing.T, mutate func(*models.TCPStreamConfig)) *Tracker {
	t.Helper()

	cfg := models.DefaultTCPStreamConfig()
	cfg.Enabled = true
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.Normalize()
	return New(cfg)
}

const streamID = "10.0.0.1:1234-10.0.0.2:80"

func TestReassemblesBothDirections(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	tr.Assemble(buildPacket(t, true, 1001, "GET / HTTP/1.1\r\n", false, false))
	tr.Assemble(buildPacket(t, false, 5000, "HTTP/1.1 200 OK\r\n", false, false))
	tr.FlushAll()

	detail, ok := tr.Detail(streamID)
	if !ok {
		t.Fatalf("应记录到流 %s, 现有 %+v", streamID, tr.Summaries())
	}
	if string(detail.ClientPayload) != "GET / HTTP/1.1\r\n" {
		t.Errorf("客户端载荷 = %q", detail.ClientPayload)
	}
	if string(detail.ServerPayload) != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("服务端载荷 = %q", detail.ServerPayload)
	}
	if detail.ClientBytes != 16 || detail.ServerBytes != 17 {
		t.Errorf("字节数 = %d / %d, want 16 / 17", detail.ClientBytes, detail.ServerBytes)
	}
}

// 乱序到达的报文应按序列号拼回正确顺序
func TestReordersOutOfOrderSegments(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	// 先喂后半段，再喂前半段
	tr.Assemble(buildPacket(t, true, 1004, "def", false, false))
	tr.Assemble(buildPacket(t, true, 1001, "abc", false, false))
	tr.FlushAll()

	detail, _ := tr.Detail(streamID)
	if string(detail.ClientPayload) != "abcdef" {
		t.Errorf("客户端载荷 = %q, want %q", detail.ClientPayload, "abcdef")
	}
	if detail.MissingBytes != 0 {
		t.Errorf("无丢包时 MissingBytes 应为 0, 得到 %d", detail.MissingBytes)
	}
}

// 中间段缺失时应计入 MissingBytes，提醒用户内容不连续
func TestCountsMissingBytes(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	tr.Assemble(buildPacket(t, true, 1001, "abc", false, false))
	// 跳过 1004-1006 这 3 个字节
	tr.Assemble(buildPacket(t, true, 1007, "ghi", false, false))
	tr.FlushAll()

	detail, _ := tr.Detail(streamID)
	if detail.MissingBytes != 3 {
		t.Errorf("MissingBytes = %d, want 3", detail.MissingBytes)
	}
	if string(detail.ClientPayload) != "abcghi" {
		t.Errorf("客户端载荷 = %q", detail.ClientPayload)
	}
}

// 超过留存上限的部分不进内存，但总字节数照常累计
func TestTruncatesBeyondLimit(t *testing.T) {
	tr := newTracker(t, func(c *models.TCPStreamConfig) { c.MaxStreamBytes = 4 })

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	tr.Assemble(buildPacket(t, true, 1001, "abcdefgh", false, false))
	tr.FlushAll()

	detail, _ := tr.Detail(streamID)
	if string(detail.ClientPayload) != "abcd" {
		t.Errorf("客户端载荷 = %q, want %q", detail.ClientPayload, "abcd")
	}
	if !detail.ClientTruncated {
		t.Error("超出上限应标记 ClientTruncated")
	}
	if detail.ClientBytes != 8 {
		t.Errorf("ClientBytes = %d, want 8（总量不受留存上限影响）", detail.ClientBytes)
	}
}

// 双向都看到 FIN 后流应被标记关闭。
// 服务端方向必须先有 SYN：重组器没见过某一方向的起点时无法确定序列号基准，
// 只会把 FIN 排队等待，这与真实抓包从连接中途开始时的表现一致。
func TestMarksClosedOnFin(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	tr.Assemble(buildPacket(t, false, 5000, "", true, false))
	tr.Assemble(buildPacket(t, true, 1001, "hi", false, false))
	tr.Assemble(buildPacket(t, true, 1003, "", false, true))
	tr.Assemble(buildPacket(t, false, 5001, "", false, true))

	summaries := tr.Summaries()
	if len(summaries) != 1 {
		t.Fatalf("应有 1 条流, 得到 %d", len(summaries))
	}
	if !summaries[0].Closed {
		t.Error("看到双向 FIN 后应标记 Closed")
	}
}

// 达到流数上限后不再新建，避免扫描类流量把内存吃光
func TestRespectsMaxStreams(t *testing.T) {
	tr := newTracker(t, func(c *models.TCPStreamConfig) { c.MaxStreams = 1 })

	tr.Assemble(buildPacket(t, true, 1000, "first", true, false))

	// 换一个源端口即另一条流
	other := func(seq uint32, payload string) gopacket.Packet {
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IP{10, 0, 0, 9},
			DstIP: net.IP{10, 0, 0, 2}, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: 4321, DstPort: 80, Seq: seq, SYN: true, Window: 65535}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatalf("序列化报文失败: %v", err)
		}
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	}
	tr.Assemble(other(2000, "second"))
	tr.FlushAll()

	if n := len(tr.Summaries()); n != 1 {
		t.Errorf("流数应被限制为 1, 得到 %d", n)
	}
}

// 非 TCP 报文不应产生流，也不应 panic
func TestIgnoresNonTCP(t *testing.T) {
	tr := newTracker(t, nil)

	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IP{10, 0, 0, 1},
		DstIP: net.IP{10, 0, 0, 2}, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, udp, gopacket.Payload("x")); err != nil {
		t.Fatalf("序列化报文失败: %v", err)
	}
	tr.Assemble(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default))

	if n := len(tr.Summaries()); n != 0 {
		t.Errorf("UDP 报文不应产生流, 得到 %d", n)
	}
}

func TestTakeDirtyClearsFlag(t *testing.T) {
	tr := newTracker(t, nil)

	if tr.TakeDirty() {
		t.Error("初始状态不应为脏")
	}
	tr.Assemble(buildPacket(t, true, 1000, "hi", true, false))
	tr.FlushAll()

	if !tr.TakeDirty() {
		t.Error("有新流后应为脏")
	}
	if tr.TakeDirty() {
		t.Error("TakeDirty 应清除标记")
	}
}

func TestResetClearsStreams(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "hi", true, false))
	tr.FlushAll()
	tr.Reset()

	if n := len(tr.Summaries()); n != 0 {
		t.Errorf("Reset 后应为空, 得到 %d", n)
	}
	if _, ok := tr.Detail(streamID); ok {
		t.Error("Reset 后不应还能取到明细")
	}
}

// Detail 返回的载荷必须是副本，否则后续追加会改到调用方手里的数据
func TestDetailReturnsCopy(t *testing.T) {
	tr := newTracker(t, nil)

	tr.Assemble(buildPacket(t, true, 1000, "", true, false))
	tr.Assemble(buildPacket(t, true, 1001, "abc", false, false))
	tr.FlushAll()

	detail, _ := tr.Detail(streamID)
	detail.ClientPayload[0] = 'X'

	again, _ := tr.Detail(streamID)
	if string(again.ClientPayload) != "abc" {
		t.Errorf("内部载荷被外部改动为 %q", again.ClientPayload)
	}
}

func TestNormalizeFixesInvalidConfig(t *testing.T) {
	cfg := models.TCPStreamConfig{MaxStreamBytes: -1, MaxStreams: 0, IdleSeconds: 99999}
	cfg.Normalize()

	d := models.DefaultTCPStreamConfig()
	if cfg.MaxStreamBytes != d.MaxStreamBytes || cfg.MaxStreams != d.MaxStreams || cfg.IdleSeconds != d.IdleSeconds {
		t.Errorf("非法值未被纠正: %+v", cfg)
	}
}
