package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const appName = "go-netsniffer"

var (
	once    sync.Once
	dataDir string
)

// Dir 返回应用数据目录（配置、证书、日志）。
// 优先使用用户配置目录，这样程序被安装到 Program Files 等只读位置时依然可写；
// 取不到时退回当前工作目录，保证任何环境下都有可用路径。
func Dir() string {
	once.Do(func() {
		base, err := os.UserConfigDir()
		if err == nil {
			dir := filepath.Join(base, appName)
			if err := os.MkdirAll(dir, 0o755); err == nil {
				dataDir = dir
				migrateLegacyFiles(dir)
				return
			}
		}
		dataDir = "."
	})
	return dataDir
}

// migrateLegacyFiles 把旧版本写在工作目录下的配置与证书搬到数据目录，
// 避免升级后用户需要重新生成并安装证书。
func migrateLegacyFiles(dir string) {
	for _, name := range []string{"config.json", "rootcrt.pem", "rootkey.pem"} {
		dst := filepath.Join(dir, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		os.WriteFile(dst, b, 0o600)
	}
}

func ConfigFile() string { return filepath.Join(Dir(), "config.json") }

func CertFile() string { return filepath.Join(Dir(), "rootcrt.pem") }

func KeyFile() string { return filepath.Join(Dir(), "rootkey.pem") }

// PacketLogFile 返回当天的抓包记录文件路径。
func PacketLogFile(t time.Time) string {
	return filepath.Join(Dir(), fmt.Sprintf("log%s.txt", t.Format(time.DateOnly)))
}

// PcapFile 返回本次抓包的 pcap 文件路径，按时间命名避免覆盖上一次的结果。
func PcapFile(t time.Time) string {
	return filepath.Join(Dir(), fmt.Sprintf("capture-%s.pcap", t.Format("20060102-150405")))
}

// AppLogFile 返回运行日志文件路径。
func AppLogFile() string { return filepath.Join(Dir(), "app.log") }
