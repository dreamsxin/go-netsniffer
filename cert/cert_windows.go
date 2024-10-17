package cert

import (
	"fmt"
	"os"

	"github.com/dreamsxin/go-netsniffer/cmd"
)

func InstallCert(certpath string) error {
	if _, err := os.Stat(certpath); os.IsNotExist(err) {
		return fmt.Errorf("installCert: Certificate does not exist")
	}

	// Register certificate with the Trusted Root store
	err := cmd.Command("certutil.exe", "-f", "-addstore", "Root", certpath).Run()
	if err != nil {
		return fmt.Errorf("failed to install Trusted Root certificate: %+v", err)
	}

	// Register certificate with the Trusted Publisher store
	err = cmd.Command("certutil.exe", "-f", "-addstore", "TrustedPublisher", certpath).Run()
	if err != nil {
		return fmt.Errorf("failed to install Trusted Publisher certificate: %+v", err)
	}
	return nil
}

func UninstallCert(authorityName string) error {
	// Remove certificate from TrustedPublisher
	err := cmd.Command("certutil.exe", "-f", "-delstore", "TrustedPublisher", authorityName).Run()
	if err != nil {
		return err
	}

	// Remove certificate from Trusted Root
	err = cmd.Command("certutil.exe", "-f", "-delstore", "Root", authorityName).Run()
	if err != nil {
		return err
	}
	return nil
}
