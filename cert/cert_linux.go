//go:build linux

package cert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Linux 各发行版的 CA 目录与刷新命令不统一，这里覆盖两套主流方案：
// Debian/Ubuntu 的 /usr/local/share/ca-certificates + update-ca-certificates，
// RHEL/Fedora 的 /etc/pki/ca-trust/source/anchors + update-ca-trust。
//
// 两者都需要 root 权限，且只有机器级安装，没有用户级方案，
// 所以权限不足时直接返回明确的手工步骤，而不是假装成功。
//
// 注意：这份实现尚未在 Linux 上实测过。

const certFileName = "go-netsniffer-root.crt"

// caTrustLayout 描述一个发行版的证书目录与刷新命令
type caTrustLayout struct {
	dir     string
	refresh string
}

var caTrustLayouts = []caTrustLayout{
	{dir: "/usr/local/share/ca-certificates", refresh: "update-ca-certificates"},
	{dir: "/etc/pki/ca-trust/source/anchors", refresh: "update-ca-trust"},
}

// detectLayout 返回本机适用的证书目录方案
func detectLayout() (caTrustLayout, error) {
	for _, l := range caTrustLayouts {
		if _, err := os.Stat(l.dir); err != nil {
			continue
		}
		if _, err := exec.LookPath(l.refresh); err != nil {
			continue
		}
		return l, nil
	}
	return caTrustLayout{}, fmt.Errorf("未识别的发行版证书目录，请手动把 %s 安装到系统 CA 库", certFileName)
}

func InstallCert(certpath string) (string, error) {
	data, err := os.ReadFile(certpath)
	if err != nil {
		return "", fmt.Errorf("读取证书文件失败: %w", err)
	}

	layout, err := detectLayout()
	if err != nil {
		return "", err
	}

	dest := filepath.Join(layout.dir, certFileName)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		if os.IsPermission(err) {
			return "", fmt.Errorf("写入 %s 需要 root 权限，请用 sudo 运行，或手动执行：sudo cp %s %s && sudo %s",
				layout.dir, certpath, dest, layout.refresh)
		}
		return "", fmt.Errorf("写入证书失败: %w", err)
	}

	if out, err := exec.Command(layout.refresh).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s 执行失败: %v, 输出: %s", layout.refresh, err, string(out))
	}
	return ScopeMachine, nil
}

func UninstallCert(authorityName string) error {
	layout, err := detectLayout()
	if err != nil {
		return err
	}

	dest := filepath.Join(layout.dir, certFileName)
	if err := os.Remove(dest); err != nil {
		// 已经不存在视为卸载成功，保证幂等
		if os.IsNotExist(err) {
			return nil
		}
		if os.IsPermission(err) {
			return fmt.Errorf("删除 %s 需要 root 权限，请用 sudo 运行", dest)
		}
		return fmt.Errorf("删除证书失败: %w", err)
	}

	if out, err := exec.Command(layout.refresh).CombinedOutput(); err != nil {
		return fmt.Errorf("%s 执行失败: %v, 输出: %s", layout.refresh, err, string(out))
	}
	return nil
}

func TrustedScopes(authorityName string) []string {
	layout, err := detectLayout()
	if err != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(layout.dir, certFileName)); err == nil {
		return []string{ScopeMachine}
	}
	return nil
}
