package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 证书存储位置：优先写入本机（需要管理员权限），失败时退回当前用户
var certStoreLocations = []uint32{
	windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
	windows.CERT_SYSTEM_STORE_CURRENT_USER,
}

// 需要清理的证书存储列表
var certStoreNames = []string{"ROOT", "TrustedPublisher"}

// 使用Windows API替代了certutil命令行调用
func InstallCert(certpath string) error {
	certData, err := os.ReadFile(certpath)
	if err != nil {
		return fmt.Errorf("读取证书文件失败: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return errors.New("证书解析失败: 无效的 PEM 数据，请重新生成证书")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}
	if len(crt.Raw) == 0 {
		return errors.New("证书解析失败: 证书内容为空")
	}

	var lastErr error
	for _, location := range certStoreLocations {
		if err := addCertToStore(crt.Raw, "ROOT", location); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("证书安装失败（请尝试以管理员身份运行）: %w", lastErr)
}

func addCertToStore(raw []byte, storeName string, location uint32) error {
	storePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return err
	}

	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		location, uintptr(unsafe.Pointer(storePtr)))
	if err != nil {
		return fmt.Errorf("打开证书存储 %s 失败: %w", storeName, err)
	}
	defer windows.CertCloseStore(store, 0)

	certContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &raw[0], uint32(len(raw)))
	if err != nil {
		return fmt.Errorf("创建证书上下文失败: %w", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	if err := windows.CertAddCertificateContextToStore(store, certContext,
		windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return fmt.Errorf("写入证书存储 %s 失败: %w", storeName, err)
	}
	return nil
}

// UninstallCert 从所有可能的存储位置删除同名证书。
// 未找到证书不视为错误，保证重复卸载是幂等的。
func UninstallCert(authorityName string) error {
	authNamePtr, err := windows.UTF16PtrFromString(authorityName)
	if err != nil {
		return fmt.Errorf("证书名称转换失败: %w", err)
	}

	var lastErr error
	for _, location := range certStoreLocations {
		for _, storeName := range certStoreNames {
			if err := deleteCertsFromStore(authNamePtr, storeName, location); err != nil {
				lastErr = err
			}
		}
	}
	if lastErr != nil {
		return fmt.Errorf("证书卸载失败（请尝试以管理员身份运行）: %w", lastErr)
	}
	return nil
}

func deleteCertsFromStore(authNamePtr *uint16, storeName string, location uint32) error {
	storePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return err
	}

	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		location, uintptr(unsafe.Pointer(storePtr)))
	if err != nil {
		// 存储不存在（例如当前用户下没有 TrustedPublisher）不算失败
		return nil
	}
	defer windows.CertCloseStore(store, 0)

	// CertDeleteCertificateFromStore 会释放传入的 context，
	// 因此每次删除后必须从 nil 重新开始查找，否则是 use-after-free。
	for {
		certContext, err := windows.CertFindCertificateInStore(
			store,
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
			0,
			windows.CERT_FIND_SUBJECT_STR,
			unsafe.Pointer(authNamePtr),
			nil,
		)
		if err != nil || certContext == nil {
			// CRYPT_E_NOT_FOUND 表示已全部删除
			return nil
		}

		if err := windows.CertDeleteCertificateFromStore(certContext); err != nil {
			return fmt.Errorf("从 %s 删除证书失败: %w", storeName, err)
		}
	}
}
