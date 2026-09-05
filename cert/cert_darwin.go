//go:build darwin

package cert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS 通过 security 命令操作钥匙串。
//
// 系统钥匙串需要管理员权限，因此优先写入当前用户的 login 钥匙串；
// 用户级安装同样能让 Safari、Chrome 生效，Firefox 仍需手工导入。
//
// 注意：这份实现尚未在 macOS 上实测过。

func userKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// 新版 macOS 的钥匙串带 -db 后缀，旧版没有，两个都试
	candidates := []string{
		filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		filepath.Join(home, "Library", "Keychains", "login.keychain"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("未找到用户钥匙串")
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s 执行失败: %v, 输出: %s", name, err, string(out))
	}
	return string(out), nil
}

// InstallCert 把根证书加入钥匙串并标记为受信任。
func InstallCert(certpath string) (string, error) {
	if _, err := os.Stat(certpath); err != nil {
		return "", fmt.Errorf("读取证书文件失败: %w", err)
	}

	keychain, err := userKeychain()
	if err != nil {
		return "", err
	}
	// -r trustRoot 表示作为根证书信任；不带 -d 即写入用户域
	if _, err := run("security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, certpath); err != nil {
		return "", fmt.Errorf("证书安装失败: %w", err)
	}
	return ScopeUser, nil
}

func UninstallCert(authorityName string) error {
	keychain, err := userKeychain()
	if err != nil {
		return err
	}
	// 同名证书可能存在多份，循环删除直到找不到
	for {
		if !certInKeychain(authorityName, keychain) {
			return nil
		}
		if _, err := run("security", "delete-certificate", "-c", authorityName, keychain); err != nil {
			return fmt.Errorf("证书卸载失败: %w", err)
		}
	}
}

func TrustedScopes(authorityName string) []string {
	keychain, err := userKeychain()
	if err != nil {
		return nil
	}
	if certInKeychain(authorityName, keychain) {
		return []string{ScopeUser}
	}
	return nil
}

func certInKeychain(authorityName, keychain string) bool {
	out, err := exec.Command("security", "find-certificate", "-c", authorityName, keychain).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "keychain")
}
