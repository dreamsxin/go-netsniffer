package proxy

import (
	"fmt"
	"sync"

	"github.com/dreamsxin/go-netsniffer/cmd"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// 本地地址不走代理，避免代理自身与本地服务被卷入
const defaultProxyOverride = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"

var (
	wininet                  = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOptionW   = wininet.NewProc("InternetSetOptionW")
	internetOptionsChanged   uint32 = 39 // INTERNET_OPTION_SETTINGS_CHANGED
	internetOptionRefresh    uint32 = 37 // INTERNET_OPTION_REFRESH
)

// 保存启用代理前的系统设置，用于退出时还原
type proxyBackup struct {
	valid    bool
	enable   uint64
	server   string
	override string
}

var (
	backupMu sync.Mutex
	backup   proxyBackup
)

func executeCommand(name string, args ...string) ([]byte, error) {
	cmd := cmd.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("命令执行失败: %v, 输出: %s", err, string(output))
	}
	return output, nil
}

// notifyProxyChanged 通知 WinINet 重新读取代理配置。
// 不广播时大量程序（浏览器、系统组件）会继续使用旧设置，代理看起来"没生效"。
func notifyProxyChanged() {
	// LazyProc.Call 在找不到导出函数时会 panic，这里显式判断
	if err := procInternetSetOptionW.Find(); err != nil {
		return
	}
	procInternetSetOptionW.Call(0, uintptr(internetOptionsChanged), 0, 0)
	procInternetSetOptionW.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

func saveBackup() {
	backupMu.Lock()
	defer backupMu.Unlock()
	if backup.valid {
		return
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	backup.enable, _, _ = key.GetIntegerValue("ProxyEnable")
	backup.server, _, _ = key.GetStringValue("ProxyServer")
	backup.override, _, _ = key.GetStringValue("ProxyOverride")
	backup.valid = true
}

func EnableProxy(port int) error {
	saveBackup()

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开系统代理配置失败: %w", err)
	}
	defer key.Close()

	if err := key.SetStringValue("ProxyServer", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return fmt.Errorf("设置代理地址失败: %w", err)
	}
	if err := key.SetStringValue("ProxyOverride", defaultProxyOverride); err != nil {
		return fmt.Errorf("设置代理例外失败: %w", err)
	}
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("启用系统代理失败: %w", err)
	}

	notifyProxyChanged()
	return nil
}

func DisableProxy() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开系统代理配置失败: %w", err)
	}
	defer key.Close()

	backupMu.Lock()
	b := backup
	backup.valid = false
	backupMu.Unlock()

	// 有备份时还原用户原本的设置，否则仅关闭代理开关
	if b.valid {
		if b.server != "" {
			key.SetStringValue("ProxyServer", b.server)
		}
		key.SetStringValue("ProxyOverride", b.override)
		if err := key.SetDWordValue("ProxyEnable", uint32(b.enable)); err != nil {
			return fmt.Errorf("还原系统代理失败: %w", err)
		}
	} else if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("关闭系统代理失败: %w", err)
	}

	notifyProxyChanged()
	return nil
}

/**
 * netsh winhttp show proxy
 */
func EnableGlobalProxy(port int) error {
	_, err := executeCommand("netsh", "winhttp", "set", "proxy", fmt.Sprintf("proxy-server=127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return nil
}

func DisableGlobalProxy() error {
	_, err := executeCommand("netsh", "winhttp", "reset", "proxy")
	return err
}
