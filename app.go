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
	"github.com/google/martian/v3"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	//"net/http/cookiejar"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// App struct
type App struct {
	ctx      context.Context
	config   models.Config
	serve    *martian.Proxy
	lock     sync.Mutex
	dataChan chan *models.Packet
}

// NewApp creates a new App application struct
func NewApp() *App {

	a := &App{
		config: models.Config{
			Port:        9000,
			AutoProxy:   true,
			SaveLogFile: false,
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
		// 处理数据
		if a.config.FilterHost != "" {
			if !strings.Contains(packet.Host, a.config.FilterHost) {
				continue
			}
		}

		runtime.EventsEmit(a.ctx, "Packet", packet)
		if a.config.SaveLogFile {
			b, err := json.Marshal(packet)
			if err != nil {
				log.Println("json.Marshal", err)
				continue
			}
			// 追加内容
			file.Write(b)
			file.WriteString("\n\n")
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

func (a *App) GetConfig() models.Config {
	return a.config
}

func (a *App) SetConfig(field string, config models.Config) {
	a.config = config
	log.Println("SetConfig", field, config)
	if field == "AutoProxy" {
		if a.config.AutoProxy {
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
	a.config.AutoProxy = true
	if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve

		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}

	}
	return nil
}

func (a *App) DisableProxy() *events.Event {
	a.config.AutoProxy = false
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
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.config.Port))
			if err != nil {
				runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
				return
			}

			// serve proxy
			if a.config.AutoProxy {
				if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve

					runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
					return
				}
			}
			fmt.Printf("Proxy listening on: %s", l.Addr().String())
			if err := serve.Serve(l); err != nil {
				a.serve = nil
				a.config.Status = 0
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
	if a.config.AutoProxy {
		err := proxy.DisableProxy()
		if err != nil {
			return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
		}
	}
	if a.serve != nil {
		a.config.Status = 0
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
