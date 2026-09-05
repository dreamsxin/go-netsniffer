package main

import (
	"embed"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dreamsxin/go-netsniffer/paths"
	"github.com/dreamsxin/go-netsniffer/proxy"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	closeLog := setupLogging()
	defer closeLog()

	app := NewApp()

	// 异常退出（Ctrl+C、任务管理器结束）时也要还原系统代理，
	// 否则用户会在代理已不存在的情况下完全无法上网。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("收到退出信号，正在还原系统代理")
		app.StopProxy()
		os.Exit(0)
	}()

	// wails.Run 返回后（含 panic 恢复路径）确保系统代理被还原
	defer func() {
		if r := recover(); r != nil {
			log.Printf("程序异常: %v", r)
			proxy.DisableProxy()
			os.Exit(1)
		}
	}()

	err := wails.Run(&options.App{
		Title:     "Go NetSniffer",
		MinWidth:  1024,
		MinHeight: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Println("启动失败:", err)
	}
}

// setupLogging 把运行日志同时写入文件，GUI 程序没有控制台，
// 只靠 stderr 会导致问题无法排查。
func setupLogging() func() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	f, err := os.OpenFile(paths.AppLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Println("打开日志文件失败，仅输出到标准错误:", err)
		return func() {}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return func() {
		log.SetOutput(os.Stderr)
		f.Close()
	}
}
