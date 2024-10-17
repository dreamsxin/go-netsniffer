package proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"
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

func Serve(port int, authorityName string, handler ServeHandler) {

	// listen proxy
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatalf(err.Error())
	}

	crt, privKey, err := mitm.NewAuthority(authorityName, fmt.Sprintf("The %s Company", authorityName), 365*24*time.Hour)
	if err != nil {
		log.Fatalf(err.Error())
	}

	crtPath := "./rootcrt.pem"
	if err = cert.WriteCertToFile(crt, crtPath); err != nil {
		log.Fatalf(err.Error())
	}
	if err := cert.InstallCert(crtPath); err != nil {
		log.Fatalf(err.Error())
	} else {
		fmt.Println("install cert success")
	}

	mitmConf, err := mitm.NewConfig(crt, privKey)
	mitmConf.SetOrganization(authorityName)
	if err != nil {
		cert.UninstallCert(authorityName)
		log.Fatalf(err.Error())
	}

	proxy := martian.NewProxy()
	proxy.SetMITM(mitmConf)
	proxy.SetRequestModifier(handler)
	proxy.SetResponseModifier(handler)

	fmt.Printf("Proxy listening on: %s", l.Addr().String())
	if err := proxy.Serve(l); err != nil {
		cert.UninstallCert(authorityName)
		log.Fatalf(err.Error())
	}
}
