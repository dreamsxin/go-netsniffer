package cmd

import (
	"os/exec"
	"syscall"
)

func Command(command string, args ...string) *exec.Cmd {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd
}
