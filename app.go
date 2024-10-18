package main

import (
	"context"
	"log"
	"time"

	"github.com/dreamsxin/go-netsniffer/events"
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
	if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve

		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}

	}
	return nil
}

func (a *App) DisableProxy() *events.Event {
	if err := proxy.DisableProxy(); err != nil { // todo do after serve
		return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
	}
	return nil
}

func (a *App) StartProxy() *events.Event {
	// serve proxy
	if a.config.AutoProxy {
		if err := proxy.EnableProxy(a.config.Port); err != nil { // todo do after serve
			return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
		}
	}
	go func() {
		err := proxy.Serve(a.config.Port, authorityName, handler.NewRequestLogger(a.ctx))

		if err != nil {
			runtime.EventsEmit(a.ctx, events.EVENT_TYPE_ERROR, &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()})
		}

	}()
	return nil
}

func (a *App) StopProxy() *events.Event {
	if a.config.AutoProxy {
		err := proxy.DisableProxy()
		if err != nil {
			return &events.Event{Type: events.ERROR, Code: 1, Message: err.Error()}
		}
	}
	return nil
}

func (a *App) Test() string {
	runtime.EventsEmit(a.ctx, "Test", time.Now().String())

	return "test"
}
