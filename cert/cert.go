package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RootCommonName         = "Local Root CA"
	IntermediateCommonName = "Local Intermediate CA"
)

// 签发证书
func GrantCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM, nil
}

// 生成Root证书
func GenRootCA() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {

	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"Company Co."},
			CommonName:   RootCommonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCert, rootPEM, err := GrantCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	return rootCert, rootPEM, priv, err
}

// 根据Root证书私钥生成中级证书
func GenIntermediateCA(RootCert *x509.Certificate, RootKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	var CATemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"Company Co."},
			CommonName:   IntermediateCommonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	DCACert, DCAPEM, err := GrantCert(&CATemplate, RootCert, &priv.PublicKey, RootKey)
	return DCACert, DCAPEM, priv, err
}

// 根据中级证书私钥生成用户证书
func GenUserCert(CACert *x509.Certificate, CAKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	var UserTemplate = x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}

	userCert, userPEM, err := GrantCert(&UserTemplate, CACert, &priv.PublicKey, CAKey)
	return userCert, userPEM, priv, err

}

func VerifyCA(root *x509.Certificate, ca *x509.Certificate, intermediates ...*x509.Certificate) (chains [][]*x509.Certificate, err error) {
	roots := x509.NewCertPool()
	roots.AddCert(root)

	inter := x509.NewCertPool()
	for _, ica := range intermediates {
		inter.AddCert(ica)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	}

	chains, err = ca.Verify(opts)
	return
}

func WriteCertToFile(cert *x509.Certificate, certFilePath string) error {
	// open cert file
	certOut, err := os.OpenFile(certFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()

	// convert cert to pem format
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// write cert to file
	if err := pem.Encode(certOut, certBlock); err != nil {
		os.Remove(certFilePath)
		return err
	}

	// close file
	if err := certOut.Close(); err != nil {
		os.Remove(certFilePath)
		return err
	}

	return nil

}

func SaveBlockToFile(filename string, block *pem.Block) {
	outFile, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	err = pem.Encode(outFile, block)
	if err != nil {
		panic(err)
	}
}

func SaveToFile(filename string, data []byte) {
	outFile, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	_, err = outFile.Write(data)
	if err != nil {
		panic(err)
	}
}
