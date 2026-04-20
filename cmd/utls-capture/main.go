package main

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var parrots = map[string]tls.ClientHelloID{
	"chrome":  tls.HelloChrome_Auto,
	"firefox": tls.HelloFirefox_Auto,
	"edge":    tls.HelloEdge_Auto,
	"safari":  tls.HelloSafari_Auto,
	"ios":     tls.HelloIOS_Auto,
}

func capture(parrotName string) ([]byte, error) {
	helloID, ok := parrots[parrotName]
	if !ok {
		return nil, fmt.Errorf("unknown parrot: %s (available: chrome, firefox, edge, safari, ios)", parrotName)
	}

	host := "tls.browserleaks.com"
	roots, _ := x509.SystemCertPool()

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.UClient(tcpConn, &tls.Config{
			ServerName: host,
			RootCAs:    roots,
		}, helloID)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
			return dialTLS(ctx, network, addr)
		},
	}

	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", "https://"+host+"/json", nil)
	resp, err := client.Do(req)
	if err != nil {
		// HTTP/2 might fail for some parrots that don't negotiate h2, fall back to HTTP/1.1
		transport1 := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTLS(ctx, network, addr)
			},
		}
		client1 := &http.Client{Transport: transport1}
		resp, err = client1.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP error: %w", err)
		}
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func main() {
	parrotName := "chrome"
	if len(os.Args) > 1 {
		parrotName = os.Args[1]
	}

	body, err := capture(parrotName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
