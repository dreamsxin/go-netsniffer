package proxy

import (
	"fmt"
	"strings"

	"github.com/dreamsxin/go-netsniffer/cmd"
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
	// set info
	// set-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyServer -value host:port
	_, err := executeCommand("powershell", fmt.Sprintf("set-itemproperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -name ProxyServer -value 127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	// enable proxy
	// set-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -value 1
	_, err = executeCommand("powershell", "set-itemproperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -name ProxyEnable -value 1")
	if err != nil {
		return err
	}
	return nil
}

func VerifyProxySettings(port int) (bool, error) {
	output, err := executeCommand("netsh", "winhttp", "show", "proxy")
	if err != nil {
		return false, err
	}
	expectedProxy := fmt.Sprintf("127.0.0.1:%d", port)
	return strings.Contains(string(output), expectedProxy), nil
}

func DisableProxy() error {
	// Disable Proxy
	// set-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -value 0
	_, err := executeCommand("powershell", "set-itemproperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -name ProxyEnable -value 0")
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
