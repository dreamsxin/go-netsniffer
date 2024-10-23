package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/events"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/google/gopacket"
	"github.com/google/martian/v3"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	//"net/http/cookiejar"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// App struct
type App struct {
	ctx       context.Context
	config    models.Config
	serve     *martian.Proxy
	lock      sync.Mutex
	dataChan  chan *models.Packet
	tcphandle *pcap.Handle
}

// NewApp creates a new App application struct
func NewApp() *App {

	a := &App{
		config: models.Config{
			HTTP: models.HTTP{
				Port:        9000,
				AutoProxy:   true,
				SaveLogFile: false,
			},
			IP: models.IP{
				Snaplen: 1024,
				Promisc: true,
				Timeout: 1000,
				Filter:  "tcp and port 80",
			},
		},
		dataChan: make(chan *models.Packet, 1000),
	}

	go a.RunLoop()
	return a
}

func (a *App) RunLoop() {

	file, err := os.OpenFile(fmt.Sprintf("log%s.txt", time.Now().Format(time.DateOnly)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// 循环读取 dataChan
	for packet := range a.dataChan {
		if packet.PacketType == models.PacketType_HTTP {
			// 处理数据
			if a.config.HTTP.FilterHost != "" {
				if !strings.Contains(packet.HTTP.Host, a.config.HTTP.FilterHost) {
					continue
				}
			}

			runtime.EventsEmit(a.ctx, "HTTPPacket", packet.HTTP)
			if a.config.HTTP.SaveLogFile {
				b, err := json.Marshal(packet.HTTP)
				if err != nil {
					log.Println("json.Marshal", err)
					continue
				}
				// 追加内容
				file.Write(b)
				file.WriteString("\n\n")
			}
		} else if packet.PacketType == models.PacketType_IP {
			runtime.EventsEmit(a.ctx, "IPPacket", packet.IP)
		} else {
			runtime.EventsEmit(a.ctx, "Packet", packet)

		}
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	b, err := os.ReadFile("config.json")
	if err != nil {
		log.Println("Read config.json", err)
		return
	}
	err = json.Unmarshal(b, &a.config)
	if err != nil {
		log.Println("Unmarshal config.json", err)
		return
	}
}

func (a *App) shutdown(ctx context.Context) {
	a.StopProxy()
	a.StopIPCapture()
	close(a.dataChan)
	a.dataChan = nil
	b, err := json.Marshal(a.config)
	if err != nil {
		log.Println("Marshal config.json", err)
		return
	}
	err = os.WriteFile("config.json", b, 0644)
	if err != nil {
		panic(err)
	}
}

func (a *App) FireEvent(code int, msg string) {

	runtime.EventsEmit(a.ctx, events.EVENT_TYPE_RESPONSE, &events.Event{Type: events.GENERAL, Code: code, Message: msg})
}

func (a *App) FireErrorEvent(code int, msg string) {
	log.Println("FireErrorEvent", code, msg)
	runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: code, Message: msg})
}

func (a *App) GetConfig() models.Config {
	return a.config
}

func (a *App) SetConfig(field string, config models.Config) {
	a.config = config
	log.Println("SetConfig", field, config)
	if field == "HTTP.AutoProxy" {
		if a.config.HTTP.AutoProxy {
			a.EnableProxy()
		} else {
			a.DisableProxy()
		}
	}
}

func (a *App) GenerateCert() *events.Event {
	err := proxy.GenerateCert(authorityName)
	log.Println("GenerateCert", err)

	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) InstallCert() *events.Event {
	err := proxy.InstallCert(authorityName)
	log.Println("InstallCert", err)
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) UninstallCert() *events.Event {
	err := proxy.UninstallCert(authorityName)
	log.Println("UninstallCert", err)
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) EnableProxy() *events.Event {
	a.config.HTTP.AutoProxy = true
	if err := proxy.EnableProxy(a.config.HTTP.Port); err != nil { // todo do after serve

		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}

	}
	return nil
}

func (a *App) DisableProxy() *events.Event {
	a.config.HTTP.AutoProxy = false
	if err := proxy.DisableProxy(); err != nil { // todo do after serve
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

// 启动代理服务
func (a *App) StartProxy() *events.Event {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.serve != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经启动"}
	}
	serve, err := proxy.New(authorityName, handler.NewRequestLogger(a.ctx, a.dataChan))

	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	} else {
		a.serve = serve
		go func() {

			// listen proxy
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.config.HTTP.Port))
			if err != nil {
				runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
				return
			}

			// serve proxy
			if a.config.HTTP.AutoProxy {
				if err := proxy.EnableProxy(a.config.HTTP.Port); err != nil { // todo do after serve

					runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
					return
				}
			}
			fmt.Printf("Proxy listening on: %s", l.Addr().String())
			if err := serve.Serve(l); err != nil {
				a.serve = nil
				a.config.HTTP.Status = 0
				l.Close()
				runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
			}
		}()
	}

	return nil //&events.Event{Type: events.NOTICE, Code: 1, Message: "代理服务正在启动中"}
}

func (a *App) StopProxy() *events.Event {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.config.HTTP.AutoProxy {
		err := proxy.DisableProxy()
		if err != nil {
			return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
		}
	}
	if a.serve != nil {
		a.config.HTTP.Status = 0
		a.serve.Close()
		a.serve = nil
	} else {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经停止"}
	}
	return nil
}

func (a *App) Test() string {
	runtime.EventsEmit(a.ctx, "Test", time.Now().String())

	return "test"
}

func (a *App) GetDevices() (data []models.Device) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		a.FireErrorEvent(2, fmt.Sprintf("获取设备失败: %s", err.Error()))
		return
	}

	for _, d := range devices {
		fmt.Println("\nName: ", d.Name)
		fmt.Println("Description: ", d.Description)
		fmt.Println("Devices addresses: ", d.Addresses)

		addresses := []models.Address{}
		for _, address := range d.Addresses {
			addresses = append(addresses, models.Address{IP: address.IP.String(), Netmask: address.Netmask.String()})
		}
		data = append(data, models.Device{Name: d.Name, Description: d.Description, Addresses: addresses})
	}
	return
}

func (a *App) StartIPCapture(device string) {
	log.Println("StartIPCapture", device)
	a.lock.Lock()
	defer a.lock.Unlock()
	a.config.IP.Device = device
	handle, err := pcap.OpenLive(a.config.IP.Device, a.config.IP.Snaplen, a.config.IP.Promisc, time.Duration(a.config.IP.Timeout)*time.Millisecond)
	if err != nil {
		a.FireErrorEvent(2, fmt.Sprintf("数据抓包开启失败: %s", err.Error()))
		return
	}
	err = handle.SetBPFFilter(a.config.IP.Filter)
	if err != nil {
		handle.Close()
		a.FireErrorEvent(2, fmt.Sprintf("数据过滤条件设置失败: %s", err.Error()))
		return
	}
	a.config.IP.Status = 1
	a.tcphandle = handle
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			// Process packet here
			data := printPacketInfo(packet)
			a.dataChan <- &models.Packet{
				PacketType: models.PacketType_IP,
				IP:         data,
			}
		}
		a.config.IP.Status = 0
	}()
}

func (a *App) StopIPCapture() *events.Event {
	log.Println("StopIPCapture")
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.tcphandle != nil {
		a.config.IP.Status = 0
		a.tcphandle.Close()
		a.tcphandle = nil
		return nil
	} else {
		return &events.Event{Type: events.ERROR, Code: 2, Message: "数据抓包已经停止"}
	}
}

func printPacketInfo(packet gopacket.Packet) models.IPPacket {

	data := models.IPPacket{}
	data.Date = time.Now().Format(time.DateTime)

	// Iterate over all layers, printing out each layer type
	fmt.Println("------------------All packet layers:---------------------")
	for _, layer := range packet.Layers() {
		fmt.Println("-------------", layer.LayerType())
		switch layer.LayerType() {
		case layers.LayerTypeEthernet:
			// Let's see if the packet is an ethernet packet
			// 判断数据包是否为以太网数据包，可解析出源mac地址、目的mac地址、以太网类型（如ip类型）等
			fmt.Println("Ethernet layer detected.")
			ethernetPacket, _ := layer.(*layers.Ethernet)
			fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
			fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
			// Ethernet type is typically IPv4 but could be ARP or other
			fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
			fmt.Println()
			data.SrcMAC = ethernetPacket.SrcMAC.String()
			data.DstMAC = ethernetPacket.DstMAC.String()
			data.EthernetType = uint16(ethernetPacket.EthernetType)
			data.EthernetPayload = ethernetPacket.Payload
			/**
				layer Contents:
						74 56 3c a3 9 6 48 73 97 61 af 74 8 0
				layer Payload:
						45 0 5 28 1 37 40 0 2c 6 11 93 2f 4c 46 af c0 a8 0 63 0 76 f7 af 92 a3 ea ec 51 9c 99 35 50 10 60 0 67 be 0 0 0 40 48 0 0 0 0 1 4d 28 50 8b 86 87 ab 7e e1 6a 53 c2 9e a0 11 c6 eb 8e 86 2a d9 87 ad f8 c 89 fc 22 5c dc 29 17 f0 fd c7 8c 4e 10 ed 8c f0 d1 e4 d4 b5 6 b4 d1 8b 28 23 84 de 31 fa 34 5e 1f 0 40 48 0 0 0 0 1 4d 29 c3 b4 62 86 16 41 e8 c2 5f 56 d1 91 26 90 79 8c f3 46 5c 5 fb c2 da 91 83 7a bc 17 a0 ba 27 e6 a2 b1 6b 41 b7 a c4 3a 38 3f db 5f 99 2a 5d b1 b8 d5 7f dc de bc b6 d2 0 40 48 0 0 0 0 1 4d 2a f b4 57 ef 84 38 19 f5 7c c 2c 30 72 d6 7 f7 fa 39 fc af a9 5a e5 4e 7 f0 30 d2 11 34 4 8b 8f b6 72 19 f6 d0 25 eb c8 d3 19 25 dd ...
				ETHERNET PACKET，共 14 个字节
						74 56 3c a3 9 6 : 接收方的 MAC 地址，6 个字节
			          48 73 97 61 af 74 : 发送方的 MAC 地址，6 个字节
			                        8 0 : 协议类型，2 个字节，下一层协议类型，如 0x0800 代表上一层是 IP 协议，0x0806 为 arp，该值在 /usr/include/net/ethernet.h 中有定义，其值为：ETHERTYPE_IP

				hw, err := net.ParseMAC("74:56:3c:a3:09:06")
				fmt.Println(hw, err)
				ByteArrTo16(hw)

				hw, err = net.ParseMAC("48:73:97:61:af:74")
				fmt.Println(hw, err)
				ByteArrTo16(hw)
			*/
		case layers.LayerTypeIPv4:
			// Let's see if the packet is IP (even though the ether type told us)
			// 判断数据包是否为IP数据包，可解析出源ip、目的ip、协议号等
			fmt.Println("IPv4 layer detected.")
			ip, _ := layer.(*layers.IPv4)
			// IP layer variables:
			// Version (Either 4 or 6)
			// IHL (IP Header Length in 32-bit words)
			// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
			// Checksum, SrcIP, DstIP
			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			fmt.Println("Protocol: ", ip.Protocol)
			fmt.Println()
			data.IPVersion = 4
			data.SrcIP = ip.SrcIP.String()
			data.DstIP = ip.DstIP.String()
			data.Protocol = uint8(ip.Protocol)
			data.IPPayload = ip.Payload
			/**
			layer Contents:
				45 0 5 28 1 37 40 0 2c 6 11 93 2f 4c 46 af c0 a8 0 63
			layer Payload:
				0 76 f7 af 92 a3 ea ec 51 9c 99 35 50 10 60 0 67 be 0 0 0 40 48 0 0 0 0 1 4d 28 50 8b 86 87 ab 7e e1 6a 53 c2 9e a0 11 c6 eb 8e 86 2a d9 87 ad f8 c 89 fc 22 5c dc 29 17 f0 fd c7 8c 4e 10 ed 8c f0 d1 e4 d4 b5 6 b4 d1 8b 28 23 84 de 31 fa 34 5e 1f 0 40 48 0 0 0 0 1 4d 29 c3 b4 62 86 16 41 e8 c2 5f 56 d1 91 26 90 79 8c f3 46 5c 5 fb c2 da 91 83 7a bc 17 a0 ba 27 e6 a2 b1 6b 41 b7 a c4 3a 38 3f db 5f 99 2a 5d b1 b8 d5 7f dc de bc b6 d2 0 40 48 0 0 0 0 1 4d 2a f b4 57 ef 84 38 19 f5 7c c 2c 30 72 d6 7 f7 fa 39 fc af a9 5a e5 4e 7 f0 30 d2 11 34 4 8b 8f b6 72 19 f6 d0 25 eb c8 d3 19 25 dd 2d b9 ce 1d 31 2e bd 94 ce 9c 32 0 40 48 0 0 0 0 1 4d ...
			IP PACKET ，共 20 个字节
				06                : 协议类型，1 是 ICMP，6 是 TCP，17 是 UDP
				11 93             : 校验和 2 字节
				2f 4c 46 af       : 发送方 IP 地址，4 个字节，十进制：47.76.70.175
				 c0 a8 0 63       : 接收方 IP 地址，4 个字节，十进制：192.168.0.99

			ip := net.ParseIP("47.76.70.175")
			fmt.Println(ip, err)
			ByteArrTo16(ip.To16())

			ip = net.ParseIP("192.168.0.99")
			fmt.Println(ip, err)
			ByteArrTo16(ip.To16())
			*/
		case layers.LayerTypeIPv6:
			fmt.Println("IPv6 layer detected.")
			ip, _ := layer.(*layers.IPv6)
			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			fmt.Println("Protocol: ", ip.NextHeader)
			fmt.Println()
			data.IPVersion = 6
			data.SrcIP = ip.SrcIP.String()
			data.DstIP = ip.DstIP.String()
			data.Protocol = uint8(ip.NextHeader)
			data.IPPayload = ip.Payload
		case layers.LayerTypeTCP:
			fmt.Println("TCP layer detected.")
			tcp, _ := layer.(*layers.TCP)
			// TCP layer variables:
			// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Println("Sequence number: ", tcp.Seq)
			fmt.Println()
			data.IPPacketType = models.IPPacketType_TCP
			data.Seq = tcp.Seq
			data.SrcPort = uint16(tcp.SrcPort)
			data.DstPort = uint16(tcp.DstPort)
			data.TCPPayload = tcp.Payload
			/**
						layer Contents:
							0 76 f7 af 92 a3 ea ec 51 9c 99 35 50 10 60 0 67 be 0 0
						layer Payload:
							0 40 48 0 0 0 0 1 4d 28 50 8b 86 87 ab 7e e1 6a 53 c2 9e a0 11 c6 eb 8e 86 2a d9 87 ad f8 c 89 fc 22 5c dc 29 17 f0 fd c7 8c 4e 10 ed 8c f0 d1 e4 d4 b5 6 b4 d1 8b 28 23 84 de 31 fa 34 5e 1f 0 40 48 0 0 0 0 1 4d 29 c3 b4 62 86 16 41 e8 c2 5f 56 d1 91 26 90 79 8c f3 46 5c 5 fb c2 da 91 83 7a bc 17 a0 ba 27 e6 a2 b1 6b 41 b7 a c4 3a 38 3f db 5f 99 2a 5d b1 b8 d5 7f dc de bc b6 d2 0 40 48 0 0 0 0 1 4d 2a f b4 57 ef 84 38 19 f5 7c c 2c 30 72 d6 7 f7 fa 39 fc af a9 5a e5 4e 7 f0 30 d2 11 34 4 8b 8f b6 72 19 f6 d0 25 eb c8 d3 19 25 dd 2d b9 ce 1d 31 2e bd 94 ce 9c 32 0 40 48 0 0 0 0 1 4d 2b b3 19 f7 b4 10 67 73 e fd ae 66 f9 2d 61 8f 39 40 db ...
			   			TCP PACKET，共 20 个字节
							 0 76             : 发送方的端口号，2 个字节，其十进制表示为：118
							f7 af             : 接收方的端口号，2 个字节，其十进制表示为：63407
							92 a3             : TCP PACKET 的窗口大小

						fmt.Printf("%x - %x", 118, 63407)
						// 假设有一个int值
						x := 63407

						// 创建一个足够大的字节切片来存储转换后的大端字节
						bytes := make([]byte, 2)

						// 将int值转换为大端字节序并放入字节切片
						binary.BigEndian.PutUint16(bytes, uint16(x))

						// 打印转换后的字节切片
						ByteArrTo16(bytes)
			*/
		case layers.LayerTypeUDP:
			fmt.Println("UDP layer detected.")
			udp, _ := layer.(*layers.UDP)
			// UDP layer variables:
			// SrcPort, DstPort, Length, Checksum
			fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
			fmt.Println()
			data.IPPacketType = models.IPPacketType_UDP
			data.SrcPort = uint16(udp.SrcPort)
			data.DstPort = uint16(udp.DstPort)
			data.UDPPayload = udp.Payload
		case layers.LayerTypeICMPv4:
			fmt.Println("ICMPv4 layer detected.")
			icmplayer := layer.(*layers.ICMPv4)                          // 将 layer 转换成ICMPv4类型
			if icmplayer.TypeCode.Type() == layers.ICMPv4TypeEchoReply { // 判断是否是ICMP ECHO REPLY 类型的报文
				fmt.Println("-----------------layer------------------")
				fmt.Println("-----LayerType", layer.LayerType())
				fmt.Printf("-----LayerContents ")
				ByteArrTo16(layer.LayerContents())
				fmt.Printf("-----LayerPayload ")
				ByteArrTo16(layer.LayerPayload()) //输出数据包的携带的data部分

				fmt.Println("-----------------icmplayer------------------")
				fmt.Printf("-----BaseLayer.Contents ")
				ByteArrTo16(icmplayer.BaseLayer.Contents)
				fmt.Printf("-----BaseLayer.Payload ")
				ByteArrTo16(icmplayer.BaseLayer.Payload)
				fmt.Println("-----TypeCode", icmplayer.TypeCode)
				fmt.Println("-----Checksum", icmplayer.Checksum)
				fmt.Println("-----Id", icmplayer.Id)
				fmt.Println("-----Seq", icmplayer.Seq)
			}
		case layers.LayerTypeARP:
			fmt.Println("ARP layer detected.")
			arplayer := layer.(*layers.ARP)
			switch arplayer.Operation {
			case layers.ARPRequest:
				fmt.Printf("%s --> %s | %s --> %s\n",
					net.HardwareAddr(arplayer.SourceHwAddress), net.HardwareAddr(arplayer.DstHwAddress),
					net.IP(arplayer.SourceProtAddress), net.IP(arplayer.DstProtAddress))
			case layers.ARPReply:
				fmt.Printf("%s <-- %s | %s <-- %s\n",
					net.HardwareAddr(arplayer.DstHwAddress), net.HardwareAddr(arplayer.SourceHwAddress),
					net.IP(arplayer.DstProtAddress), net.IP(arplayer.SourceProtAddress))
			}
		default:
			fmt.Println("other layer")
		}
		fmt.Println("layer Contents:")
		ByteArrTo16(layer.LayerContents())
		fmt.Println("layer Payload:")
		ByteArrTo16(layer.LayerPayload())
	}
	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		fmt.Println("Application layer/Payload found.")
		ByteArrTo16(applicationLayer.Payload())
		// Search for a string inside the payload
		data.ApplicationLayer = applicationLayer.LayerType().String()
		data.ApplicationPayload = applicationLayer.Payload()
		if strings.Contains(string(data.ApplicationPayload), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	// 判断layer是否存在错误
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return data
}

// 以十六进制输出字节数组
func ByteArrTo16(arr []byte) {
	for _, a := range arr {
		fmt.Printf("%x ", a)
	}
	fmt.Println()
}
