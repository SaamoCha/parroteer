package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCaptureRealChrome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	chromePath, err := exec.LookPath("google-chrome-stable")
	if err != nil {
		t.Skip("chrome not found")
	}

	// Generate self-signed cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	resultCh := make(chan CHInspection, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		header := make([]byte, 5)
		if _, err := fullRead(conn, header); err != nil {
			t.Logf("read header: %v", err)
			return
		}
		recordLen := int(header[3])<<8 | int(header[4])
		record := make([]byte, recordLen)
		if _, err := fullRead(conn, record); err != nil {
			t.Logf("read record: %v", err)
			return
		}
		resultCh <- parseClientHello("real_chrome", header, record)
	}()

	// Launch Chrome
	userDataDir := t.TempDir()
	_ = certDER // Chrome uses --ignore-certificate-errors
	url := fmt.Sprintf("https://127.0.0.1:%d/", port)
	cmd := exec.Command(chromePath,
		"--headless=new",
		"--disable-gpu",
		"--disable-quic",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-background-networking",
		"--ignore-certificate-errors",
		"--user-data-dir="+filepath.Join(userDataDir, "profile"),
		"--dump-dom",
		url,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultCh:
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

		// Also capture utls for comparison
		certPEM, keyPEM := generateSelfSignedCert()
		_ = certPEM
		_ = keyPEM

		t.Logf("Real Chrome CH: total_record_len=%d, ech_ext_len=%d, padding=%v (len=%d), compress_cert=%v",
			result.TotalRecordLen, result.ECHExtLen, result.PaddingPresent, result.PaddingLen, result.CompressCertAlgs)

	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for Chrome connection")
	}

	cmd.Process.Kill()
	cmd.Wait()
}
