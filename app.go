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
	"sync/atomic"
	"time"

	"github.com/dreamsxin/go-netsniffer/events"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/dreamsxin/go-netsniffer/paths"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/dreamsxin/go-netsniffer/rule"
	"github.com/google/gopacket"
	"github.com/google/martian/v3"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// 运行状态
const (
	statusStopped  = 0
	statusStarting = 1
	statusRunning  = 2
)

// App struct
type App struct {
	ctx    context.Context
	cancel context.CancelFunc

	configMu sync.RWMutex
	config   models.Config

	// rules 决定哪些域名需要解密，自身并发安全，支持热更新
	rules *rule.Set

	lock      sync.Mutex
	serve     *martian.Proxy
	listener  net.Listener
	proxyStop context.CancelFunc
	tcphandle *pcap.Handle

	dataChan chan *models.Packet
	dropped  atomic.Int64

	wg sync.WaitGroup
}

// NewApp creates a new App application struct
func NewApp() *App {
	cfg := models.DefaultConfig()
	return &App{
		config:   cfg,
		rules:    rule.New(cfg.HTTP.Rule),
		dataChan: make(chan *models.Packet, 4096),
	}
}

// packetSink 把 App 适配为 handler.Sink。
// 用独立类型而不是直接在 App 上导出方法，避免这些内部接口被绑定到前端。
type packetSink struct{ app *App }

func (s packetSink) Emit(packet *models.Packet) { s.app.emit(packet) }
func (s packetSink) MaxBodySize() int64         { return s.app.maxBodySize() }
func (s packetSink) ShouldMITM(host string) bool {
	return s.app.rules.ShouldMITM(host)
}

// emit 非阻塞投递报文。抓包速度可能远快于界面消费速度，
// 阻塞在这里会直接拖慢甚至挂死用户的网络请求，因此队列满时丢弃并计数。
func (a *App) emit(packet *models.Packet) {
	select {
	case a.dataChan <- packet:
	default:
		a.dropped.Add(1)
	}
}

func (a *App) maxBodySize() int64 {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config.HTTP.MaxBodySize
}

// snapshot 返回配置副本，避免调用方在无锁情况下读取共享结构
func (a *App) snapshot() models.Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config
}

func (a *App) updateConfig(fn func(*models.Config)) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	fn(&a.config)
}

// safeGo 启动带 panic 恢复的 goroutine，
// 单个采集协程崩溃不应带走整个应用。
func (a *App) safeGo(name string, fn func()) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("goroutine %s panic: %v", name, r)
				a.FireErrorEvent(1, fmt.Sprintf("%s 内部错误已恢复: %v", name, r))
			}
		}()
		fn()
	}()
}

// 批量推送参数：高频抓包时每包一次 EventsEmit 会让 WebView 的 IPC 与主线程成为瓶颈，
// 因此按时间窗聚合，攒够一批或到点再推。
const (
	flushInterval = 100 * time.Millisecond
	flushMaxBatch = 200
)

func (a *App) runLoop() {
	var (
		logFile *os.File
		logDate string
	)
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	dropTicker := time.NewTicker(5 * time.Second)
	defer dropTicker.Stop()
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	var (
		reportedDrops int64
		httpBatch     []models.HTTPPacket
		ipBatch       []models.IPPacket
	)

	flush := func() {
		if len(httpBatch) > 0 {
			runtime.EventsEmit(a.ctx, "HTTPPackets", httpBatch)
			httpBatch = nil
		}
		if len(ipBatch) > 0 {
			runtime.EventsEmit(a.ctx, "IPPackets", ipBatch)
			ipBatch = nil
		}
	}
	defer flush()

	for {
		select {
		case <-a.ctx.Done():
			return

		case <-flushTicker.C:
			flush()

		case <-dropTicker.C:
			if d := a.dropped.Load(); d > reportedDrops {
				log.Printf("队列拥塞，已丢弃 %d 个报文", d)
				a.FireErrorEvent(3, fmt.Sprintf("界面处理不及时，已丢弃 %d 个报文", d))
				reportedDrops = d
			}

		case packet := <-a.dataChan:
			if packet == nil {
				continue
			}
			cfg := a.snapshot()

			switch packet.PacketType {
			case models.PacketType_HTTP:
				if !matchHTTPFilter(cfg.HTTP, packet.HTTP) {
					continue
				}
				httpBatch = append(httpBatch, packet.HTTP)
				if cfg.HTTP.SaveLogFile {
					logFile, logDate = a.appendPacketLog(logFile, logDate, packet.HTTP)
				}
			case models.PacketType_IP:
				ipBatch = append(ipBatch, packet.IP)
			}

			if len(httpBatch)+len(ipBatch) >= flushMaxBatch {
				flush()
			}
		}
	}
}

func matchHTTPFilter(cfg models.HTTP, packet models.HTTPPacket) bool {
	// 隧道记录用于告知用户该域名按规则未解密，不受内容类型过滤影响
	if packet.HTTPPacketType == models.HTTPPacketType_TUNNEL {
		return cfg.FilterHost == "" || strings.Contains(packet.Host, cfg.FilterHost)
	}
	if cfg.FilterHost != "" && !strings.Contains(packet.Host, cfg.FilterHost) {
		return false
	}
	if len(cfg.ResourceTypes) == 0 {
		return true
	}
	contentType := strings.ToLower(packet.ContentType)
	for _, rt := range cfg.ResourceTypes {
		if strings.Contains(contentType, strings.ToLower(rt)) {
			return true
		}
	}
	return false
}

// appendPacketLog 按天滚动写入抓包记录。写入失败只记日志，不影响抓包。
func (a *App) appendPacketLog(file *os.File, date string, packet models.HTTPPacket) (*os.File, string) {
	today := time.Now().Format(time.DateOnly)
	if file == nil || date != today {
		if file != nil {
			file.Close()
		}
		f, err := os.OpenFile(paths.PacketLogFile(time.Now()), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Println("打开抓包日志失败:", err)
			return nil, today
		}
		file, date = f, today
	}

	b, err := json.Marshal(packet)
	if err != nil {
		log.Println("序列化抓包记录失败:", err)
		return file, date
	}
	if _, err := file.Write(append(b, '\n', '\n')); err != nil {
		log.Println("写入抓包日志失败:", err)
	}
	return file, date
}

func (a *App) startup(ctx context.Context) {
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.loadConfig()
	a.safeGo("事件分发", a.runLoop)
}

// loadConfig 以默认配置为基准合并磁盘配置：
// 新增字段自动获得默认值，磁盘内容损坏时退回默认值而不是让应用不可用。
func (a *App) loadConfig() {
	cfg := models.DefaultConfig()

	b, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Println("读取配置失败，使用默认配置:", err)
		}
	} else if err := json.Unmarshal(b, &cfg); err != nil {
		log.Println("解析配置失败，使用默认配置:", err)
		cfg = models.DefaultConfig()
	}
	cfg.Normalize()

	a.configMu.Lock()
	a.config = cfg
	a.configMu.Unlock()

	a.rules.Load(cfg.HTTP.Rule)
}

func (a *App) saveConfig() {
	cfg := a.snapshot()
	cfg.Normalize()

	b, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		log.Println("序列化配置失败:", err)
		return
	}
	// 先写临时文件再替换，避免进程在写入过程中退出导致配置文件损坏
	tmp := paths.ConfigFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Println("写入配置失败:", err)
		return
	}
	if err := os.Rename(tmp, paths.ConfigFile()); err != nil {
		log.Println("替换配置文件失败:", err)
		os.Remove(tmp)
	}
}

func (a *App) shutdown(ctx context.Context) {
	// 先停外部副作用：还原系统代理、关闭代理与抓包句柄
	a.StopProxy()
	a.StopIPCapture()
	a.saveConfig()

	if a.cancel != nil {
		a.cancel()
	}

	// 等待采集协程退出，超时则放弃等待，保证界面能关掉
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		log.Println("等待后台协程退出超时")
	}
}

func (a *App) FireEvent(code int, msg string) {
	runtime.EventsEmit(a.ctx, events.EVENT_TYPE_RESPONSE, &events.Event{Type: events.GENERAL, Code: code, Message: msg})
}

func (a *App) FireErrorEvent(code int, msg string) {
	log.Println("FireErrorEvent", code, msg)
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: code, Message: msg})
}

func (a *App) GetConfig() models.Config {
	return a.snapshot()
}

// SetConfig 接受界面提交的配置。运行状态由后端维护，不接受前端覆盖。
func (a *App) SetConfig(field string, config models.Config) {
	a.configMu.Lock()
	httpStatus, ipStatus := a.config.HTTP.Status, a.config.IP.Status
	config.Normalize() // Normalize 会把状态清零，之后再恢复真实状态
	config.HTTP.Status, config.IP.Status = httpStatus, ipStatus
	a.config = config
	a.configMu.Unlock()

	// 规则热更新，无需重启代理
	a.rules.Load(config.HTTP.Rule)

	if field == "HTTP.AutoProxy" {
		if config.HTTP.AutoProxy {
			a.EnableProxy()
		} else {
			a.DisableProxy()
		}
	}
	// 配置立即落盘，避免异常退出丢失用户设置
	a.saveConfig()
}

// GetDataDir 返回配置、证书与日志所在目录，方便用户排查问题
func (a *App) GetDataDir() string {
	return paths.Dir()
}

// CertReady 返回根证书是否已生成，供界面提示用户下一步操作
func (a *App) CertReady() bool {
	return proxy.CertExists()
}

func (a *App) GenerateCert() *events.Event {
	if err := proxy.GenerateCert(authorityName); err != nil {
		log.Println("GenerateCert", err)
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) InstallCert() *events.Event {
	if err := proxy.InstallCert(authorityName); err != nil {
		log.Println("InstallCert", err)
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) UninstallCert() *events.Event {
	if err := proxy.UninstallCert(authorityName); err != nil {
		log.Println("UninstallCert", err)
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) EnableProxy() *events.Event {
	port := a.snapshot().HTTP.Port
	if err := proxy.EnableProxy(port); err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	a.updateConfig(func(c *models.Config) { c.HTTP.AutoProxy = true })
	return nil
}

func (a *App) DisableProxy() *events.Event {
	if err := proxy.DisableProxy(); err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	a.updateConfig(func(c *models.Config) { c.HTTP.AutoProxy = false })
	return nil
}

// StartProxy 启动代理服务。
// 监听端口在此同步完成，端口被占用等错误可以立即反馈给界面。
func (a *App) StartProxy() *events.Event {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.serve != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经启动"}
	}

	cfg := a.snapshot()
	// 代理停止时取消该 ctx，断开按规则未解密的长连接隧道
	proxyCtx, proxyStop := context.WithCancel(a.ctx)
	serve, err := proxy.New(authorityName, handler.NewRequestLogger(proxyCtx, packetSink{app: a}), proxy.Options{
		UpstreamProxy: cfg.HTTP.UpstreamProxy,
		ListenPort:    cfg.HTTP.Port,
	})
	if err != nil {
		proxyStop()
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.HTTP.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		proxyStop()
		serve.Close()
		return &events.Event{Type: events.ERROR, Code: 1,
			Message: fmt.Sprintf("监听 %s 失败（端口可能已被占用）: %s", addr, err.Error())}
	}

	if cfg.HTTP.AutoProxy {
		if err := proxy.EnableProxy(cfg.HTTP.Port); err != nil {
			proxyStop()
			l.Close()
			serve.Close()
			return &events.Event{Type: events.ERROR, Code: 1,
				Message: fmt.Sprintf("设置系统代理失败: %s", err.Error())}
		}
	}

	a.serve = serve
	a.listener = l
	a.proxyStop = proxyStop
	a.updateConfig(func(c *models.Config) { c.HTTP.Status = statusRunning })

	a.safeGo("代理服务", func() {
		log.Println("代理已监听:", l.Addr().String())
		err := serve.Serve(l)

		a.lock.Lock()
		stoppedByUser := a.serve != serve
		if !stoppedByUser {
			a.serve = nil
			a.listener = nil
			a.proxyStop = nil
			proxyStop()
			a.updateConfig(func(c *models.Config) { c.HTTP.Status = statusStopped })
		}
		a.lock.Unlock()

		// 主动停止时 Serve 会返回连接关闭错误，不应报给用户
		if err != nil && !stoppedByUser {
			a.FireErrorEvent(1, fmt.Sprintf("代理服务已停止: %s", err.Error()))
		}
	})

	return nil
}

func (a *App) StopProxy() *events.Event {
	a.lock.Lock()
	serve, listener, proxyStop := a.serve, a.listener, a.proxyStop
	a.serve, a.listener, a.proxyStop = nil, nil, nil
	a.lock.Unlock()

	if serve == nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经停止"}
	}

	a.updateConfig(func(c *models.Config) { c.HTTP.Status = statusStopped })
	// 先断开隧道，再关代理与监听
	if proxyStop != nil {
		proxyStop()
	}
	serve.Close()
	if listener != nil {
		listener.Close()
	}

	// 代理已停止，必须还原系统代理，否则用户会完全断网
	if a.snapshot().HTTP.AutoProxy {
		if err := proxy.DisableProxy(); err != nil {
			return &events.Event{Type: events.ERROR, Code: 1,
				Message: fmt.Sprintf("还原系统代理失败，请手动检查系统代理设置: %s", err.Error())}
		}
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
		a.FireErrorEvent(2, fmt.Sprintf("获取设备失败（请确认已安装 Npcap）: %s", err.Error()))
		return
	}

	for _, d := range devices {
		addresses := make([]models.Address, 0, len(d.Addresses))
		for _, address := range d.Addresses {
			addresses = append(addresses, models.Address{IP: address.IP.String(), Netmask: address.Netmask.String()})
		}
		data = append(data, models.Device{Name: d.Name, Description: d.Description, Addresses: addresses})
	}
	return
}

func (a *App) StartIPCapture(device string) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.tcphandle != nil {
		a.FireErrorEvent(2, "数据抓包已经启动")
		return
	}
	if device == "" {
		a.FireErrorEvent(2, "请先选择网络设备")
		return
	}

	cfg := a.snapshot()
	handle, err := pcap.OpenLive(device, cfg.IP.Snaplen, cfg.IP.Promisc, time.Duration(cfg.IP.Timeout)*time.Millisecond)
	if err != nil {
		a.FireErrorEvent(2, fmt.Sprintf("数据抓包开启失败（可能需要管理员权限）: %s", err.Error()))
		return
	}
	if cfg.IP.Filter != "" {
		if err := handle.SetBPFFilter(cfg.IP.Filter); err != nil {
			handle.Close()
			a.FireErrorEvent(2, fmt.Sprintf("数据过滤条件设置失败: %s", err.Error()))
			return
		}
	}

	a.tcphandle = handle
	a.updateConfig(func(c *models.Config) {
		c.IP.Device = device
		c.IP.Status = statusRunning
	})

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	a.safeGo("IP 抓包", func() {
		defer a.updateConfig(func(c *models.Config) { c.IP.Status = statusStopped })
		for {
			select {
			case <-a.ctx.Done():
				return
			case packet, ok := <-packets:
				if !ok {
					return
				}
				a.emit(&models.Packet{
					PacketType: models.PacketType_IP,
					IP:         parsePacket(packet),
				})
			}
		}
	})
}

func (a *App) StopIPCapture() *events.Event {
	a.lock.Lock()
	handle := a.tcphandle
	a.tcphandle = nil
	a.lock.Unlock()

	if handle == nil {
		return &events.Event{Type: events.ERROR, Code: 2, Message: "数据抓包已经停止"}
	}
	a.updateConfig(func(c *models.Config) { c.IP.Status = statusStopped })
	handle.Close()
	return nil
}

// parsePacket 把 gopacket 的分层结构展开为界面需要的字段。
// 这里不做任何标准输出，抓包高峰下逐层打印会成为性能瓶颈。
func parsePacket(packet gopacket.Packet) models.IPPacket {
	data := models.IPPacket{}
	data.Date = time.Now().Format(time.DateTime)
	if n := len(packet.Data()); n > 0 {
		data.Length = uint16(min(n, 65535))
	}

	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Ethernet:
			data.SrcMAC = l.SrcMAC.String()
			data.DstMAC = l.DstMAC.String()
			data.EthernetType = uint16(l.EthernetType)
		case *layers.IPv4:
			data.IPVersion = 4
			data.SrcIP = l.SrcIP.String()
			data.DstIP = l.DstIP.String()
			data.Protocol = uint8(l.Protocol)
		case *layers.IPv6:
			data.IPVersion = 6
			data.SrcIP = l.SrcIP.String()
			data.DstIP = l.DstIP.String()
			data.Protocol = uint8(l.NextHeader)
		case *layers.TCP:
			data.IPPacketType = models.IPPacketType_TCP
			data.Seq = l.Seq
			data.SrcPort = uint16(l.SrcPort)
			data.DstPort = uint16(l.DstPort)
		case *layers.UDP:
			data.IPPacketType = models.IPPacketType_UDP
			data.SrcPort = uint16(l.SrcPort)
			data.DstPort = uint16(l.DstPort)
		}
	}

	// 只带最内层的一份数据，各层 Payload 是同一份内容的嵌套副本
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		data.ApplicationLayer = applicationLayer.LayerType().String()
		data.ApplicationPayload = applicationLayer.Payload()
	}

	return data
}
