package main

import (
	"context"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	//"net/http/cookiejar"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// App struct
type App struct {
	ctx       context.Context
	port      int
	autoProxy bool
}

// NewApp creates a new App application struct
func NewApp() *App {

	a := &App{}

	return a
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// 从请求中获取 cookie
func (a *App) StartProxy(port int, autoProxy bool) error {
	a.port = port
	a.autoProxy = autoProxy
	// serve proxy
	if a.autoProxy {
		if err := proxy.EnableProxy(a.port); err != nil { // todo do after serve
			return err
		}
	}
	runtime.EventsEmit(a.ctx, "StartProxy", a.port)
	proxy.Serve(a.port, authorityName, handler.NewRequestLogger(a.ctx))
	return nil
}

func (a *App) StopProxy() error {
	cert.UninstallCert(authorityName)
	if a.autoProxy {
		proxy.DisableProxy()
	}
	return nil
}

func (a *App) Test() string {
	runtime.EventsEmit(a.ctx, "Test", time.Now().String())

	return "test"
}
