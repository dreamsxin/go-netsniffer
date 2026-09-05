//go:build linux

package proxy

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/dreamsxin/go-netsniffer/cmd"
)

// Linux 没有统一的系统代理接口，这里走 GNOME 的 gsettings。
// KDE、其他桌面环境以及纯命令行环境需要用户自行配置代理，
// 因此拿不到 gsettings 时会返回明确的提示而不是静默失败。
//
// 注意：这份实现尚未在 Linux 上实测过。

const gnomeProxySchema = "org.gnome.system.proxy"

func executeCommand(name string, args ...string) ([]byte, error) {
	c := cmd.Command(name, args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("命令执行失败: %v, 输出: %s", err, string(output))
	}
	return output, nil
}

func hasGsettings() error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return fmt.Errorf("未找到 gsettings，无法自动设置系统代理，请在系统设置中手动将代理指向 127.0.0.1")
	}
	return nil
}

func EnableProxy(port int) error {
	if err := hasGsettings(); err != nil {
		return err
	}

	settings := [][]string{
		{gnomeProxySchema + ".http", "host", "127.0.0.1"},
		{gnomeProxySchema + ".http", "port", fmt.Sprintf("%d", port)},
		{gnomeProxySchema + ".https", "host", "127.0.0.1"},
		{gnomeProxySchema + ".https", "port", fmt.Sprintf("%d", port)},
	}
	for _, s := range settings {
		if _, err := executeCommand("gsettings", "set", s[0], s[1], s[2]); err != nil {
			return fmt.Errorf("设置系统代理失败: %w", err)
		}
	}

	// 本地地址不走代理，避免代理自身被卷入
	ignore := "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']"
	if _, err := executeCommand("gsettings", "set", gnomeProxySchema, "ignore-hosts", ignore); err != nil {
		return fmt.Errorf("设置代理例外失败: %w", err)
	}
	if _, err := executeCommand("gsettings", "set", gnomeProxySchema, "mode", "manual"); err != nil {
		return fmt.Errorf("启用系统代理失败: %w", err)
	}
	return nil
}

func DisableProxy() error {
	if err := hasGsettings(); err != nil {
		return err
	}
	if _, err := executeCommand("gsettings", "set", gnomeProxySchema, "mode", "none"); err != nil {
		return fmt.Errorf("关闭系统代理失败: %w", err)
	}
	return nil
}

// currentProxyMode 供排查问题时确认当前模式
func currentProxyMode() string {
	out, err := executeCommand("gsettings", "get", gnomeProxySchema, "mode")
	if err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(string(out)), "'")
}
