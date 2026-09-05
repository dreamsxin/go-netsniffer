package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreamsxin/go-netsniffer/breakpoint"
	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/dreamsxin/go-netsniffer/download"
	"github.com/dreamsxin/go-netsniffer/events"
	"github.com/dreamsxin/go-netsniffer/export"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/dreamsxin/go-netsniffer/paths"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/dreamsxin/go-netsniffer/replay"
	"github.com/dreamsxin/go-netsniffer/rewrite"
	"github.com/dreamsxin/go-netsniffer/rule"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// appVersion 写入导出文件的 creator 信息
const appVersion = "0.2.0"

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
	// rewrites 是改包规则，同样支持热更新
	rewrites *rewrite.Set
	// breakpoints 管理断点。它会真的阻塞被代理的连接，默认关闭
	breakpoints *breakpoint.Manager

	lock      sync.Mutex
	serve     *proxy.Server
	listener  net.Listener
	tcphandle *pcap.Handle

	dataChan chan *models.Packet
	dropped  atomic.Int64

	wg sync.WaitGroup
}

// NewApp creates a new App application struct
func NewApp() *App {
	cfg := models.DefaultConfig()
	a := &App{
		config:   cfg,
		rules:    rule.New(cfg.HTTP.Rule),
		rewrites: rewrite.New(cfg.HTTP.RewriteRules),
		dataChan: make(chan *models.Packet, 4096),
	}
	// 待处理队列变化时推给界面，否则用户不知道有请求被挂住了
	a.breakpoints = breakpoint.New(a.pushBreakpoints)
	a.breakpoints.Load(cfg.HTTP.Breakpoint)
	return a
}

// packetSink 把 App 适配为 handler.Sink。
// 用独立类型而不是直接在 App 上导出方法，避免这些内部接口被绑定到前端。
type packetSink struct{ app *App }

func (s packetSink) Emit(packet *models.Packet) { s.app.emit(packet) }
func (s packetSink) MaxBodySize() int64         { return s.app.maxBodySize() }

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
	// 界面挂载后立即推一次，避免初始状态为空
	a.pushStatus()
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
	if err := a.rewrites.Load(cfg.HTTP.RewriteRules); err != nil {
		log.Println("加载改包规则失败:", err)
	}
	if err := a.breakpoints.Load(cfg.HTTP.Breakpoint); err != nil {
		log.Println("加载断点配置失败:", err)
	}
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

// SaveRewriteRules 保存改包规则并同步返回校验结果。
//
// 单独提供这个方法而不复用 SetConfig，是为了让界面上的"保存"按钮
// 能立刻知道成功与否；靠异步事件反馈会让用户不确定到底存进去没有。
func (a *App) SaveRewriteRules(text string) *events.Event {
	// 先校验，不合法就不写入配置，避免坏规则被持久化
	if err := a.rewrites.Load(text); err != nil {
		return &events.Event{Type: events.ERROR, Code: 7, Message: err.Error()}
	}

	a.configMu.Lock()
	a.config.HTTP.RewriteRules = text
	a.configMu.Unlock()
	a.saveConfig()

	count := 0
	if a.rewrites.Enabled() {
		count = a.rewrites.RuleCount()
	}
	a.pushStatus()
	return &events.Event{Type: events.NOTICE, Code: 0,
		Message: fmt.Sprintf("改包规则已保存，当前生效 %d 条", count)}
}

// SaveDecryptRule 保存解密规则。语法错误的行会被忽略，因此不会失败。
func (a *App) SaveDecryptRule(text string) *events.Event {
	a.rules.Load(text)

	a.configMu.Lock()
	a.config.HTTP.Rule = text
	a.configMu.Unlock()
	a.saveConfig()

	return &events.Event{Type: events.NOTICE, Code: 0, Message: "解密规则已保存，立即生效"}
}

// DefaultRewriteRules 供界面的"恢复默认"使用
func (a *App) DefaultRewriteRules() string { return models.DefaultRewriteRules }

// DefaultDecryptRule 供界面的"恢复默认"使用
func (a *App) DefaultDecryptRule() string { return models.DefaultRule }

// setHTTPStatus / setIPStatus 是状态变更的唯一入口，
// 集中在这里推送状态，避免漏掉某条分支导致界面显示与实际不符。
func (a *App) setHTTPStatus(status int) {
	a.updateConfig(func(c *models.Config) { c.HTTP.Status = status })
	a.pushStatus()
}

func (a *App) setIPStatus(status int) {
	a.updateConfig(func(c *models.Config) { c.IP.Status = status })
	a.pushStatus()
}

// pushBreakpoints 把待处理的断点推给界面。
// 断点会挂住真实流量，用户必须能立刻看到有哪些请求在等他处理。
func (a *App) pushBreakpoints() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "breakpoints", a.breakpoints.Pending())
	a.pushStatus()
}

// GetPendingBreakpoints 供界面初始化时拉取一次
func (a *App) GetPendingBreakpoints() []models.BreakpointHit {
	return a.breakpoints.Pending()
}

// ResolveBreakpoint 处理一个断点：放行、按回传内容改写后放行、或中止。
func (a *App) ResolveBreakpoint(res models.BreakpointResolution) *events.Event {
	if err := a.breakpoints.Resolve(res); err != nil {
		return &events.Event{Type: events.ERROR, Code: 8, Message: err.Error()}
	}
	return nil
}

// ReleaseAllBreakpoints 一次性放行所有挂住的请求，用于"我不管了"的场景
func (a *App) ReleaseAllBreakpoints() *events.Event {
	a.breakpoints.ReleaseAll()
	return &events.Event{Type: events.NOTICE, Code: 0, Message: "已放行所有挂住的请求"}
}

// SaveBreakpointConfig 保存断点配置并同步返回校验结果。
func (a *App) SaveBreakpointConfig(cfg models.BreakpointConfig) *events.Event {
	if err := a.breakpoints.Load(cfg); err != nil {
		return &events.Event{Type: events.ERROR, Code: 8, Message: err.Error()}
	}
	// Load 会把非法的超时值纠正回合理范围，取回来再存
	applied := a.breakpoints.Config()

	a.configMu.Lock()
	a.config.HTTP.Breakpoint = applied
	a.configMu.Unlock()
	a.saveConfig()
	a.pushStatus()

	if !applied.Enabled {
		return &events.Event{Type: events.NOTICE, Code: 0, Message: "断点已关闭"}
	}
	msg := fmt.Sprintf("断点已开启，%d 秒无人处理自动放行", applied.TimeoutSeconds)
	if applied.URLRegex == "" {
		msg += "。当前未设置 URL 匹配，会拦下所有流量"
	}
	return &events.Event{Type: events.NOTICE, Code: 0, Message: msg}
}

// GetStatus 返回当前运行状态，供界面初始化时拉取一次。
func (a *App) GetStatus() models.AppStatus {
	cfg := a.snapshot()
	return models.AppStatus{
		HTTPStatus:       cfg.HTTP.Status,
		IPStatus:         cfg.IP.Status,
		Port:             cfg.HTTP.Port,
		AutoProxy:        cfg.HTTP.AutoProxy,
		Cert:             a.CertStatus(),
		RewriteRuleCount: a.rewrites.RuleCount(),

		BreakpointEnabled:  cfg.HTTP.Breakpoint.Enabled,
		PendingBreakpoints: a.breakpoints.PendingCount(),
	}
}

// pushStatus 把最新状态推给界面。
// 代理可能自己异常停止，只靠按钮点击后刷新会让界面与实际不符。
func (a *App) pushStatus() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "status", a.GetStatus())
}

func (a *App) GetConfig() models.Config {
	return a.snapshot()
}

// needsProxyRestart 判断改动的字段是否只在构造代理时生效。
// 端口、上游代理与 HTTP/2 都是在 proxy.New 时一次性读取的。
func needsProxyRestart(old, cur models.HTTP) bool {
	return old.Port != cur.Port ||
		old.UpstreamProxy != cur.UpstreamProxy ||
		old.AllowHTTP2 != cur.AllowHTTP2
}

// SetConfig 接受界面提交的配置。运行状态由后端维护，不接受前端覆盖。
func (a *App) SetConfig(field string, config models.Config) {
	a.configMu.Lock()
	old := a.config
	httpStatus, ipStatus := a.config.HTTP.Status, a.config.IP.Status
	config.Normalize() // Normalize 会把状态清零，之后再恢复真实状态
	config.HTTP.Status, config.IP.Status = httpStatus, ipStatus
	a.config = config
	a.configMu.Unlock()

	// 规则热更新，无需重启代理
	a.rules.Load(config.HTTP.Rule)
	// 改包规则解析失败时保留上一次生效的规则，并把原因告诉用户，
	// 静默失败会让人以为改包没作用却查不出原因
	if err := a.rewrites.Load(config.HTTP.RewriteRules); err != nil {
		a.FireErrorEvent(7, err.Error())
	}

	// 这几项在构造代理时一次性生效，改完必须重启服务，
	// 否则用户会以为设置没作用
	if httpStatus == statusRunning && needsProxyRestart(old.HTTP, config.HTTP) {
		a.FireEvent(0, "该设置需要点击“停止服务”再“启动服务”后才会生效")
	}

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

// CertStatus 返回证书的真实状态：是否生成、被哪些存储信任、路径与有效期。
// 只判断文件存在会误导用户——文件在不代表系统已经信任它。
func (a *App) CertStatus() models.CertStatus {
	status := models.CertStatus{
		Generated: proxy.CertExists(),
		CertPath:  proxy.CertPath(),
	}
	if status.Generated {
		status.TrustedScopes = proxy.TrustedScopes(authorityName)
		status.NotAfter = proxy.CertNotAfter()
	}
	return status
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
	a.pushStatus()
	return nil
}

// InstallCert 安装根证书。返回的提示里会说明装到了哪个存储范围，
// 用户级安装时 Firefox 等自带证书库的程序还需要手工导入。
func (a *App) InstallCert() *events.Event {
	scope, err := proxy.InstallCert(authorityName)
	if err != nil {
		log.Println("InstallCert", err)
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}

	msg := "证书已安装到本机存储，对所有用户生效"
	if scope == cert.ScopeUser {
		msg = fmt.Sprintf("证书已安装到当前用户存储。若要在本机存储安装请以管理员身份运行。\n"+
			"Firefox 使用独立证书库，需在 设置-隐私与安全-证书 中手工导入：%s", proxy.CertPath())
	}
	log.Println("InstallCert", scope)
	a.pushStatus()
	return &events.Event{Type: events.NOTICE, Code: 0, Message: msg}
}

func (a *App) UninstallCert() *events.Event {
	if err := proxy.UninstallCert(authorityName); err != nil {
		log.Println("UninstallCert", err)
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	a.pushStatus()
	return nil
}

func (a *App) EnableProxy() *events.Event {
	port := a.snapshot().HTTP.Port
	if err := proxy.EnableProxy(port); err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	a.updateConfig(func(c *models.Config) { c.HTTP.AutoProxy = true })
	a.pushStatus()
	return nil
}

func (a *App) DisableProxy() *events.Event {
	if err := proxy.DisableProxy(); err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	a.updateConfig(func(c *models.Config) { c.HTTP.AutoProxy = false })
	a.pushStatus()
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
	serve, err := proxy.New(authorityName, handler.NewRequestLogger(packetSink{app: a}), a.rules, a.rewrites, a.breakpoints, proxy.Options{
		UpstreamProxy: cfg.HTTP.UpstreamProxy,
		ListenPort:    cfg.HTTP.Port,
		AllowHTTP2:    cfg.HTTP.AllowHTTP2,
	})
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.HTTP.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		serve.Close()
		return &events.Event{Type: events.ERROR, Code: 1,
			Message: fmt.Sprintf("监听 %s 失败（端口可能已被占用）: %s", addr, err.Error())}
	}

	if cfg.HTTP.AutoProxy {
		if err := proxy.EnableProxy(cfg.HTTP.Port); err != nil {
			l.Close()
			serve.Close()
			return &events.Event{Type: events.ERROR, Code: 1,
				Message: fmt.Sprintf("设置系统代理失败: %s", err.Error())}
		}
	}

	a.serve = serve
	a.listener = l
	a.setHTTPStatus(statusRunning)

	a.safeGo("代理服务", func() {
		log.Println("代理已监听:", l.Addr().String())
		err := serve.Serve(l)

		a.lock.Lock()
		stoppedByUser := a.serve != serve
		if !stoppedByUser {
			a.serve = nil
			a.listener = nil
			a.setHTTPStatus(statusStopped)
		}
		a.lock.Unlock()

		// 主动停止时 Serve 会返回 ErrServerClosed，不应报给用户
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !stoppedByUser {
			a.FireErrorEvent(1, fmt.Sprintf("代理服务已停止: %s", err.Error()))
		}
	})

	return nil
}

func (a *App) StopProxy() *events.Event {
	a.lock.Lock()
	serve, listener := a.serve, a.listener
	a.serve, a.listener = nil, nil
	a.lock.Unlock()

	if serve == nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经停止"}
	}

	a.setHTTPStatus(statusStopped)
	// Close 会同时断开监听、在途请求与未解密的隧道连接
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

// Download 把某条响应记录对应的资源重新取回本地。
//
// 抓包时不缓存响应体，而是保留了当次的请求头，这里原样重放，
// 因此带防盗链的资源也能下载成功，且不占用内存。
func (a *App) Download(packet models.HTTPPacket) *events.Event {
	if packet.URL == "" {
		return &events.Event{Type: events.ERROR, Code: 4, Message: "该记录没有可下载的地址"}
	}

	suffix := packet.Suffix
	if suffix == "" {
		_, suffix = models.ClassifyContentType(packet.ContentType, packet.URL)
	}
	name := models.FileNameFromURL(packet.URL, suffix)

	cfg := a.snapshot()
	dest := ""
	if cfg.HTTP.DownloadDir != "" {
		dest = filepath.Join(cfg.HTTP.DownloadDir, name)
	} else {
		chosen, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
			Title:           "保存资源",
			DefaultFilename: name,
		})
		if err != nil {
			return &events.Event{Type: events.ERROR, Code: 4, Message: fmt.Sprintf("选择保存位置失败: %s", err)}
		}
		if chosen == "" {
			return nil // 用户取消
		}
		dest = chosen
	}

	client := proxy.NewDownloadClient(cfg.HTTP.UpstreamProxy)
	dl := download.New(client)
	task := download.Task{
		ID:     packet.ID,
		URL:    packet.URL,
		Header: packet.RequestHeader,
		Dest:   dest,
	}

	a.safeGo("资源下载", func() {
		err := dl.Do(a.ctx, task, func(p download.Progress) {
			runtime.EventsEmit(a.ctx, "DownloadProgress", p)
		})
		if err != nil {
			a.FireErrorEvent(4, fmt.Sprintf("下载失败: %s", err))
			return
		}
		a.FireEvent(0, fmt.Sprintf("已保存到 %s", dest))
	})

	return nil
}

// ExportHAR 把界面上的记录导出为 HAR，Chrome DevTools 与 Charles 都能直接打开。
// 记录由前端传入，避免后端再存一份同样的数据。
func (a *App) ExportHAR(packets []models.HTTPPacket) *events.Event {
	if len(packets) == 0 {
		return &events.Event{Type: events.ERROR, Code: 5, Message: "没有可导出的记录"}
	}

	dest, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出 HAR",
		DefaultFilename: fmt.Sprintf("netsniffer-%s.har", time.Now().Format("20060102-150405")),
	})
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 5, Message: fmt.Sprintf("选择保存位置失败: %s", err)}
	}
	if dest == "" {
		return nil // 用户取消
	}

	if err := export.WriteHAR(dest, appVersion, packets); err != nil {
		log.Println("ExportHAR", err)
		return &events.Event{Type: events.ERROR, Code: 5, Message: fmt.Sprintf("导出失败: %s", err)}
	}
	return &events.Event{Type: events.NOTICE, Code: 0, Message: fmt.Sprintf("已导出到 %s", dest)}
}

// Replay 重新发送一个请求。请求经由本机代理发出，
// 因此重放的请求与响应会走一遍正常抓取流程，直接出现在列表里。
func (a *App) Replay(req models.ReplayRequest) *events.Event {
	if req.URL == "" {
		return &events.Event{Type: events.ERROR, Code: 6, Message: "重放地址为空"}
	}

	cfg := a.snapshot()
	// 重放依赖代理本身，代理没启动就无从记录结果
	if cfg.HTTP.Status != statusRunning {
		return &events.Event{Type: events.ERROR, Code: 6, Message: "请先启动代理服务再重放"}
	}

	client, err := replay.New(cfg.HTTP.Port)
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 6, Message: err.Error()}
	}

	a.safeGo("请求重放", func() {
		res, err := client.Send(a.ctx, replay.Request{
			Method: req.Method,
			URL:    req.URL,
			Header: req.Header,
			Body:   req.Body,
		})
		if err != nil {
			a.FireErrorEvent(6, fmt.Sprintf("重放失败: %s", err))
			return
		}
		a.FireEvent(0, fmt.Sprintf("重放完成: %s，耗时 %d ms",
			res.Status, res.Duration.Milliseconds()))
	})

	return nil
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
	a.updateConfig(func(c *models.Config) { c.IP.Device = device })
	a.setIPStatus(statusRunning)

	// 可选地把原始帧流式写入 pcap 文件。流式写入不占额外内存，
	// 也保住了我们为了减小推送体积而丢弃的完整帧数据。
	var pcapFile *os.File
	var pcapWriter *pcapgo.Writer
	if cfg.IP.SavePcapFile {
		path := paths.PcapFile(time.Now())
		f, err := os.Create(path)
		if err != nil {
			a.FireErrorEvent(2, fmt.Sprintf("创建 pcap 文件失败: %s", err))
		} else {
			w := pcapgo.NewWriter(f)
			if err := w.WriteFileHeader(uint32(cfg.IP.Snaplen), handle.LinkType()); err != nil {
				f.Close()
				a.FireErrorEvent(2, fmt.Sprintf("写入 pcap 头失败: %s", err))
			} else {
				pcapFile, pcapWriter = f, w
				a.FireEvent(0, fmt.Sprintf("抓包将同时保存到 %s", path))
			}
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	a.safeGo("IP 抓包", func() {
		defer a.setIPStatus(statusStopped)
		if pcapFile != nil {
			defer pcapFile.Close()
		}
		for {
			select {
			case <-a.ctx.Done():
				return
			case packet, ok := <-packets:
				if !ok {
					return
				}
				if pcapWriter != nil {
					// 写盘失败只记一次日志，不影响抓包继续
					if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
						log.Println("写入 pcap 失败:", err)
						pcapWriter = nil
					}
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
	a.setIPStatus(statusStopped)
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
