package proxy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)

// 定义接口
type ServeHandler interface {
	ModifyRequest(req *http.Request) error
	ModifyResponse(res *http.Response) error
}

const (
	keyPath = "./rootkey.pem"
	crtPath = "./rootcrt.pem"
)

func Serve(port int, authorityName string, handler ServeHandler) error {

	_, err := os.Stat(crtPath)
	if err != nil {
		return fmt.Errorf("请安装证书: %w", err)
	}

	var crt *x509.Certificate
	var privKey *rsa.PrivateKey

	// 读取证书
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("证书读取失败: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("证书读取失败: %w", err)
	}
	if block.Type == "RSA PRIVATE KEY" {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("私钥解析失败: %w", err)
		}
	} else {
		return fmt.Errorf("证书读取失败: Unsupported key type: %s", block.Type)
	}

	pemBytes, err = os.ReadFile(crtPath)
	if err != nil {
		return fmt.Errorf("证书读取失败: %w", err)
	}

	block, _ = pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("证书读取失败: %w", err)
	}
	if block.Type == "CERTIFICATE" {
		crt, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("证书读取失败: %w", err)
		}
	} else {
		return fmt.Errorf("证书读取失败: Unsupported key type: %s", block.Type)
	}

	mitmConf, err := mitm.NewConfig(crt, privKey)
	mitmConf.SetOrganization(authorityName)
	if err != nil {
		return fmt.Errorf("初始化证书生成失败: %w", err)
	}

	proxy := martian.NewProxy()
	proxy.SetMITM(mitmConf)
	proxy.SetRequestModifier(handler)
	proxy.SetResponseModifier(handler)

	// listen proxy
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("端口监听失败: %w", err)
	}

	fmt.Printf("Proxy listening on: %s", l.Addr().String())
	if err := proxy.Serve(l); err != nil {
		cert.UninstallCert(authorityName)
		return fmt.Errorf("启动代理失败: %w", err)
	}
	return nil
}

func GenerateCert(authorityName string) error {

	crt, privKey, err := mitm.NewAuthority(authorityName, fmt.Sprintf("The %s Company", authorityName), 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}

	if err = cert.SaveBlockToFile(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}); err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}

	if err = cert.WriteCertToFile(crt, crtPath); err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}
	return nil
}

func InstallCert(authorityName string) error {
	_, err := os.Stat(crtPath)

	if err != nil { // 文件不存在时跳转到生成
		return fmt.Errorf("安装证书失败: %w", err)
	}

	if err := cert.InstallCert(crtPath); err != nil {
		return err
	} else {
		fmt.Println("install cert success")
	}
	return nil
}

func UninstallCert(authorityName string) error {
	err := cert.UninstallCert(authorityName)
	if err != nil { // 文件不存在时跳转到生成
		return fmt.Errorf("卸载证书失败: %w", err)
	}
	return nil
}
