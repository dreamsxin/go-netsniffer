package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 使用Windows API替代了certutil命令行调用
func InstallCert(certpath string) error {
	certData, err := os.ReadFile(certpath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return errors.New("Failed to parse certificate PEM" + err.Error())
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("installCert3:" + err.Error())
	}

	rootStorePtr, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return errors.New("installCert4:" + err.Error())
	}

	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, uintptr(unsafe.Pointer(rootStorePtr)))
	if err != nil {
		return errors.New("installCert5:" + err.Error())
	}
	defer windows.CertCloseStore(store, 0)

	certContext, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &cert.Raw[0], uint32(len(cert.Raw)))
	if err != nil {
		return errors.New("installCert6:" + err.Error())
	}
	defer windows.CertFreeCertificateContext(certContext)
	err = windows.CertAddCertificateContextToStore(store, certContext, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
	if err != nil {
		return errors.New("installCert7:" + err.Error())
	}
	return nil
}

func UninstallCert(authorityName string) error {
	// 转换证书名称为UTF16指针
	authNamePtr, err := windows.UTF16PtrFromString(authorityName)
	if err != nil {
		return errors.New("failed to convert authority name: " + err.Error())
	}

	// 需要清理的证书存储列表
	stores := []string{"ROOT", "TrustedPublisher"}
	for _, storeName := range stores {
		// 打开系统证书存储
		storePtr, err := windows.UTF16PtrFromString(storeName)
		if err != nil {
			return errors.New("failed to convert store name: " + err.Error())
		}

		store, err := windows.CertOpenStore(
			windows.CERT_STORE_PROV_SYSTEM,
			0,
			0,
			windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
			uintptr(unsafe.Pointer(storePtr)),
		)
		if err != nil {
			return errors.New("failed to open store " + storeName + ": " + err.Error())
		}

		// 在存储中查找证书
		var certContext *windows.CertContext
		for {
			certContext, err = windows.CertFindCertificateInStore(
				store,
				windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
				0,
				windows.CERT_FIND_SUBJECT_STR,
				unsafe.Pointer(authNamePtr),
				certContext,
			)
			if err != nil || certContext == nil {
				break
			}

			// 删除找到的证书
			if err := windows.CertDeleteCertificateFromStore(certContext); err != nil {
				windows.CertCloseStore(store, 0)
				return errors.New("failed to delete certificate from " + storeName + ": " + err.Error())
			}
		}

		// 关闭证书存储
		err = windows.CertCloseStore(store, 0)

		// 检查是否找到并删除了证书
		if err != nil && err != windows.Errno(windows.CRYPT_E_NOT_FOUND) {
			return errors.New("failed to delete certificate from " + storeName + ": " + err.Error())
		}
	}

	return nil
}
