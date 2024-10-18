package main

import (
	"context"
	"fmt"
	"log"
	"net"
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
	ctx    context.Context
	config models.Config
	serve  *martian.Proxy
}

// NewApp creates a new App application struct
func NewApp() *App {

	a := &App{
		config: models.Config{
			Port:      9000,
			AutoProxy: true,
		},
	}

	return a
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
	a.StopProxy()
}

func (a *App) GetConfig() models.Config {
	return a.config
}

func (a *App) SetConfig(config models.Config) {
	a.config = config
	log.Println("SetConfig", config)
	if a.config.AutoProxy {
		a.EnableProxy()
	} else {
		a.DisableProxy()
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

	if a.serve != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: "代理服务已经启动"}
	}

	// listen proxy
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.config.Port))
	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}

	// serve proxy
	if a.config.AutoProxy {
		if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve
			return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
		}
	}
	serve, err := proxy.New(authorityName, handler.NewRequestLogger(a.ctx))

	if err != nil {
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	} else {
		a.serve = serve
		a.config.Status = 1
		go func() {
			fmt.Printf("Proxy listening on: %s", l.Addr().String())
			if err := serve.Serve(l); err != nil {
				a.serve = nil
				a.config.Status = 0
				l.Close()
				runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: fmt.Sprintf("启动代理失败: %s", err.Error())})
			}
		}()
	}

	return nil
}

func (a *App) StopProxy() *events.Event {

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
	}
	return nil
}

func (a *App) Test() string {
	runtime.EventsEmit(a.ctx, "Test", time.Now().String())

	return "test"
}
