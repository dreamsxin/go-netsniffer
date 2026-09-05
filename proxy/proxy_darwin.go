//go:build darwin

package proxy

import (
	"fmt"
	"strings"

	"github.com/dreamsxin/go-netsniffer/cmd"
)

// macOS 通过 networksetup 设置系统代理。
//
// 注意：这份实现尚未在 macOS 上实测过，逻辑依据的是 networksetup 的命令行约定。
// 若行为异常，请手动在 系统设置-网络-代理 中确认。

func executeCommand(name string, args ...string) ([]byte, error) {
	c := cmd.Command(name, args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("命令执行失败: %v, 输出: %s", err, string(output))
	}
	return output, nil
}

// activeNetworkServices 返回处于启用状态的网络服务名。
// networksetup 的输出中带 "*" 前缀的表示该服务已被禁用。
func activeNetworkServices() ([]string, error) {
	out, err := executeCommand("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}

	var services []string
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// 第一行是说明文字，不是服务名
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("未找到可用的网络服务")
	}
	return services, nil
}

func EnableProxy(port int) error {
	services, err := activeNetworkServices()
	if err != nil {
		return err
	}

	host := "127.0.0.1"
	portStr := fmt.Sprintf("%d", port)
	var lastErr error
	applied := 0
	for _, svc := range services {
		// HTTP 与 HTTPS 要分别设置，只设一个会导致另一类流量绕过代理
		if _, err := executeCommand("networksetup", "-setwebproxy", svc, host, portStr); err != nil {
			lastErr = err
			continue
		}
		if _, err := executeCommand("networksetup", "-setsecurewebproxy", svc, host, portStr); err != nil {
			lastErr = err
			continue
		}
		applied++
	}
	if applied == 0 {
		return fmt.Errorf("设置系统代理失败: %w", lastErr)
	}
	return nil
}

func DisableProxy() error {
	services, err := activeNetworkServices()
	if err != nil {
		return err
	}

	var lastErr error
	for _, svc := range services {
		if _, err := executeCommand("networksetup", "-setwebproxystate", svc, "off"); err != nil {
			lastErr = err
		}
		if _, err := executeCommand("networksetup", "-setsecurewebproxystate", svc, "off"); err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return fmt.Errorf("关闭系统代理失败: %w", lastErr)
	}
	return nil
}
