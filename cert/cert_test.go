package cert

import (
	"fmt"
	"testing"
)

// 测试证书生成
func TestGenCert(t *testing.T) {
	// Test case 1: Normal generation
	rootCert, rootCertPEM, rootKey, err := GenRootCA()
	if err != nil {
		t.Errorf("GenCARoot failed: %s", err.Error())
	} else {
		fmt.Println("rootCert\n", string(rootCertPEM))
	}

	iCACert, iCACertPEM, iCAKey, err := GenIntermediateCA(rootCert, rootKey)
	if err != nil {
		t.Errorf("GenIntermediateCA failed: %s", err.Error())
	} else {
		fmt.Println("rootCert\n", string(iCACertPEM))
	}

	_, err = VerifyCA(rootCert, iCACert)
	if err != nil {
		t.Errorf("VerifyCA failed: %s", err.Error())
	}
	userCert, userPEM, _, err := GenUserCert(iCACert, iCAKey)
	if err != nil {
		t.Errorf("VerifyCA failed: %s", err.Error())
	} else {
		fmt.Println("rootCert\n", string(userPEM))
	}

	_, err = VerifyCA(rootCert, userCert, iCACert)
	if err != nil {
		t.Errorf("VerifyCA failed: %s", err.Error())
	}
}
