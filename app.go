package main

import (
	"context"
	"log"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	//"net/http/cookiejar"

	"github.com/dreamsxin/go-netsniffer/proxy/handler"
)

const authorityName string = "GoNetSniffer Proxy Authority"

// App struct
type App struct {
	ctx    context.Context
	config models.Config
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

func (a *App) GetConfig() models.Config {
	return a.config
}

func (a *App) SetConfig(config models.Config) {
	a.config = config
	log.Println("SetConfig", config)
}

// 从请求中获取 cookie
func (a *App) StartProxy() error {
	// serve proxy
	if a.config.AutoProxy {
		if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve
			return err
		}
	}
	return proxy.Serve(a.config.Port, authorityName, handler.NewRequestLogger(a.ctx))
}

func (a *App) StopProxy() error {
	cert.UninstallCert(authorityName)
	if a.config.AutoProxy {
		proxy.DisableProxy()
	}
	return nil
}

func (a *App) Test() string {
	runtime.EventsEmit(a.ctx, "Test", time.Now().String())

	return "test"
}
