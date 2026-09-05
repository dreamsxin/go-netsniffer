package proxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dreamsxin/go-netsniffer/cert"
	"github.com/dreamsxin/go-netsniffer/paths"
	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)

// 定义接口
type ServeHandler interface {
	ModifyRequest(req *http.Request) error
	ModifyResponse(res *http.Response) error
}

// Options 控制代理的网络行为，零值表示使用默认值。
type Options struct {
	// 上游代理地址，形如 http://127.0.0.1:7890，留空表示直连
	UpstreamProxy string
	// 本地监听端口，用于识别并拒绝把自己设置为上游代理
	ListenPort int
}

const (
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 30 * time.Second
	responseHeadTimeout = 60 * time.Second
	idleConnTimeout     = 30 * time.Second
	proxyConnTimeout    = 5 * time.Minute
	certValidity        = 365 * 24 * time.Hour
)

func keyPath() string { return paths.KeyFile() }
func crtPath() string { return paths.CertFile() }

// CertExists 判断根证书与私钥是否都已生成，供界面展示状态。
func CertExists() bool {
	if _, err := os.Stat(crtPath()); err != nil {
		return false
	}
	_, err := os.Stat(keyPath())
	return err == nil
}

func New(authorityName string, handler ServeHandler, opts Options) (*martian.Proxy, error) {
	crt, privKey, err := loadAuthority()
	if err != nil {
		return nil, err
	}

	if time.Now().After(crt.NotAfter) {
		return nil, fmt.Errorf("根证书已于 %s 过期，请重新生成并安装证书", crt.NotAfter.Format(time.DateOnly))
	}

	mitmConf, err := mitm.NewConfig(crt, privKey)
	if err != nil {
		return nil, fmt.Errorf("初始化证书生成失败: %w", err)
	}
	mitmConf.SetOrganization(authorityName)
	mitmConf.SetValidity(certValidity) // 设置证书有效期为1年

	proxy := martian.NewProxy()
	proxy.SetMITM(mitmConf)
	proxy.SetRequestModifier(handler)
	proxy.SetResponseModifier(handler)
	// 没有超时时，卡住的上游连接会一直占用 goroutine 与文件描述符
	proxy.SetTimeout(proxyConnTimeout)
	proxy.SetRoundTripper(newTransport())

	if err := applyUpstreamProxy(proxy, opts); err != nil {
		proxy.Close()
		return nil, err
	}

	return proxy, nil
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil, // 上游代理由 martian 的 DownstreamProxy 统一控制
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeadTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   8,
	}
}

func applyUpstreamProxy(proxy *martian.Proxy, opts Options) error {
	if opts.UpstreamProxy == "" {
		return nil
	}
	u, err := url.Parse(opts.UpstreamProxy)
	if err != nil {
		return fmt.Errorf("上游代理地址无效: %w", err)
	}
	if u.Host == "" {
		return errors.New("上游代理地址无效: 缺少主机与端口")
	}
	// 上游代理指向自身会导致请求无限自环
	if opts.ListenPort > 0 {
		if _, port, err := net.SplitHostPort(u.Host); err == nil &&
			port == fmt.Sprintf("%d", opts.ListenPort) {
			return errors.New("上游代理不能指向本程序自身的监听端口")
		}
	}
	proxy.SetDownstreamProxy(u)
	return nil
}

func loadAuthority() (*x509.Certificate, *rsa.PrivateKey, error) {
	if _, err := os.Stat(crtPath()); err != nil {
		return nil, nil, errors.New("根证书不存在，请先生成并安装证书")
	}

	keyBytes, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("私钥读取失败: %w", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, nil, errors.New("私钥解析失败: 无效的 PEM 数据，请重新生成证书")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("私钥解析失败: 不支持的类型 %s", block.Type)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("私钥解析失败: %w", err)
	}

	crtBytes, err := os.ReadFile(crtPath())
	if err != nil {
		return nil, nil, fmt.Errorf("证书读取失败: %w", err)
	}
	block, _ = pem.Decode(crtBytes)
	if block == nil {
		return nil, nil, errors.New("证书解析失败: 无效的 PEM 数据，请重新生成证书")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("证书解析失败: 不支持的类型 %s", block.Type)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("证书解析失败: %w", err)
	}
	return crt, privKey, nil
}

func GenerateCert(authorityName string) error {
	crt, privKey, err := mitm.NewAuthority(authorityName, fmt.Sprintf("The %s Company", authorityName), certValidity)
	if err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}

	if err = cert.SaveBlockToFile(keyPath(), &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}); err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}

	if err = cert.WriteCertToFile(crt, crtPath()); err != nil {
		return fmt.Errorf("证书生成失败: %w", err)
	}
	return nil
}

func InstallCert(authorityName string) error {
	if _, err := os.Stat(crtPath()); err != nil {
		return errors.New("根证书不存在，请先生成证书")
	}
	return cert.InstallCert(crtPath())
}

func UninstallCert(authorityName string) error {
	return cert.UninstallCert(authorityName)
}
