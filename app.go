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

	// Let's see if the packet is an ethernet packet
	// 判断数据包是否为以太网数据包，可解析出源mac地址、目的mac地址、以太网类型（如ip类型）等
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
		data.SrcMAC = ethernetPacket.SrcMAC.String()
		data.DstMAC = ethernetPacket.DstMAC.String()
		data.EthernetType = uint16(ethernetPacket.EthernetType)
	}
	// Let's see if the packet is IP (even though the ether type told us)
	// 判断数据包是否为IP数据包，可解析出源ip、目的ip、协议号等
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
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
	} else {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			fmt.Println("IPv6 layer detected.")
			ip, _ := ipLayer.(*layers.IPv6)
			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			fmt.Println("Protocol: ", ip.NextHeader)
			fmt.Println()
			data.IPVersion = 6
			data.SrcIP = ip.SrcIP.String()
			data.DstIP = ip.DstIP.String()
			data.Protocol = uint8(ip.NextHeader)
		}
	}
	{
		// Let's see if the packet is TCP
		// 判断数据包是否为TCP数据包，可解析源端口、目的端口、seq序列号、tcp标志位等
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("TCP layer detected.")
			tcp, _ := tcpLayer.(*layers.TCP)
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

			data.TCPPayload = string(tcpLayer.LayerPayload())
		}
	}
	{
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			fmt.Println("UDP layer detected.")
			udp, _ := udpLayer.(*layers.UDP)
			// UDP layer variables:
			// SrcPort, DstPort, Length, Checksum
			fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
			fmt.Println()
			data.IPPacketType = models.IPPacketType_UDP
			data.SrcPort = uint16(udp.SrcPort)
			data.DstPort = uint16(udp.DstPort)
		}
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())
		// Search for a string inside the payload
		data.ApplicationLayer = applicationLayer.LayerType().String()
		data.Payload = string(applicationLayer.Payload())
		if strings.Contains(data.Payload, "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
	///.......................................................
	// Check for errors
	// 判断layer是否存在错误
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return data
}
