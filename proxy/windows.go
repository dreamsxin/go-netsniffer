package proxy

import (
	"fmt"

	"github.com/dreamsxin/go-netsniffer/cmd"
	"golang.org/x/sys/windows/registry"
)

func executeCommand(name string, args ...string) ([]byte, error) {
	cmd := cmd.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("命令执行失败: %v, 输出: %s", err, string(output))
	}
	return output, nil
}

func EnableProxy(port int) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	err = key.SetStringValue("ProxyServer", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	err = key.SetDWordValue("ProxyEnable", 1)
	if err != nil {
		return err
	}
	return nil
}

func DisableProxy() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	err = key.SetDWordValue("ProxyEnable", 0)
	if err != nil {
		return err
	}
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
