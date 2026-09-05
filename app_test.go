package main

import (
	"encoding/json"
	"testing"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestMatchHTTPFilter(t *testing.T) {
	cases := []struct {
		name   string
		cfg    models.HTTP
		packet models.HTTPPacket
		want   bool
	}{
		{
			name: "无过滤条件时全部通过",
			want: true,
		},
		{
			name:   "Host 匹配",
			cfg:    models.HTTP{FilterHost: "example.com"},
			packet: models.HTTPPacket{Host: "api.example.com"},
			want:   true,
		},
		{
			name:   "Host 不匹配",
			cfg:    models.HTTP{FilterHost: "example.com"},
			packet: models.HTTPPacket{Host: "other.org"},
			want:   false,
		},
		{
			name:   "内容类型匹配且忽略大小写",
			cfg:    models.HTTP{ResourceTypes: []string{"JSON"}},
			packet: models.HTTPPacket{ContentType: "application/json; charset=utf-8"},
			want:   true,
		},
		{
			name:   "内容类型不匹配",
			cfg:    models.HTTP{ResourceTypes: []string{"json"}},
			packet: models.HTTPPacket{ContentType: "text/html"},
			want:   false,
		},
		{
			name:   "Host 与内容类型需同时满足",
			cfg:    models.HTTP{FilterHost: "example.com", ResourceTypes: []string{"json"}},
			packet: models.HTTPPacket{Host: "api.example.com", ContentType: "text/html"},
			want:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchHTTPFilter(c.cfg, c.packet); got != c.want {
				t.Errorf("matchHTTPFilter() = %v, want %v", got, c.want)
			}
		})
	}
}

// 队列满时必须丢弃而不是阻塞，否则会拖慢被代理的请求
func TestEmitDropsWhenQueueFull(t *testing.T) {
	a := &App{dataChan: make(chan *models.Packet, 1)}

	a.emit(&models.Packet{})
	a.emit(&models.Packet{})

	if got := a.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
	if len(a.dataChan) != 1 {
		t.Errorf("队列长度 = %d, want 1", len(a.dataChan))
	}
}

// buildTCPPacket 构造一个 Ethernet/IPv4/TCP 帧用于解析测试
func buildTCPPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 0, 2},
		DstIP:    []byte{93, 184, 216, 34},
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		Seq:     1000,
		Window:  1024,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("序列化数据包失败: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParsePacketExtractsFields(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	got := parsePacket(buildTCPPacket(t, payload))

	if got.SrcIP != "192.168.0.2" || got.DstIP != "93.184.216.34" {
		t.Errorf("IP = %s -> %s", got.SrcIP, got.DstIP)
	}
	if got.SrcPort != 54321 || got.DstPort != 80 {
		t.Errorf("Port = %d -> %d", got.SrcPort, got.DstPort)
	}
	if got.IPVersion != 4 || got.IPPacketType != models.IPPacketType_TCP {
		t.Errorf("IPVersion = %d, IPPacketType = %d", got.IPVersion, got.IPPacketType)
	}
	if got.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("SrcMAC = %s", got.SrcMAC)
	}
	if string(got.ApplicationPayload) != string(payload) {
		t.Errorf("ApplicationPayload = %q, want %q", got.ApplicationPayload, payload)
	}
	// 14 字节以太网头 + 20 IP + 20 TCP + payload
	if want := uint16(54 + len(payload)); got.Length != want {
		t.Errorf("Length = %d, want %d", got.Length, want)
	}
}

// 各层 Payload 是同一份数据的嵌套副本，序列化后只能出现一份，
// 否则单个报文推送到界面的体积会翻好几倍
func TestParsePacketSerializesPayloadOnce(t *testing.T) {
	payload := make([]byte, 1000)
	got := parsePacket(buildTCPPacket(t, payload))

	if len(got.ApplicationPayload) != len(payload) {
		t.Fatalf("ApplicationPayload 长度 = %d, want %d", len(got.ApplicationPayload), len(payload))
	}

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 1000 字节 base64 后约 1336 字节，再留出字段名等固定开销
	if max := 1336 + 512; len(b) > max {
		t.Errorf("序列化后 %d 字节，超过单份 payload 的预期上限 %d，可能存在重复副本", len(b), max)
	}
}


