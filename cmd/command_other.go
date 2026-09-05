//go:build !windows

package cmd

import "os/exec"

// Command 在非 Windows 平台不需要隐藏窗口，直接透传。
// HideWindow 只在 Windows 的 syscall.SysProcAttr 上存在。
func Command(command string, args ...string) *exec.Cmd {
	return exec.Command(command, args...)
}
