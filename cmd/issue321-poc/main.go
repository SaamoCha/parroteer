package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type H2Fingerprint struct {
	AKAMAI         string `json:"akamai_fingerprint"`
	AKAMAIHash     string `json:"akamai_fingerprint_hash"`
	InitialSetting []struct {
		ID    string `json:"id"`
		Value int    `json:"value"`
	} `json:"settings"`
	WindowUpdate int      `json:"window_update_increment"`
	Priorities   []string `json:"priority_frames"`
}

type PeetResponse struct {
	HTTP2 H2Fingerprint `json:"http2"`
	TLS   struct {
		JA3     string `json:"ja3"`
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
		Akamai  string `json:"akamai"`
	} `json:"tls"`
	HTTPVersion string `json:"http_version"`
}

func fetchPeet(label string, client *http.Client) {
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Printf("  %s: ERROR: %v\n", label, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var parsed PeetResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		fmt.Printf("  %s: parse error: %v\n", label, err)
		return
	}

	fmt.Printf("  %s:\n", label)
	fmt.Printf("    HTTP version:   %s\n", parsed.HTTPVersion)
	fmt.Printf("    JA4:            %s\n", parsed.TLS.JA4)
	fmt.Printf("    Akamai h2 fp:   %s\n", parsed.TLS.Akamai)

	if len(parsed.HTTP2.InitialSetting) > 0 {
		fmt.Printf("    H2 SETTINGS:\n")
		for _, s := range parsed.HTTP2.InitialSetting {
			fmt.Printf("      %s = %d\n", s.ID, s.Value)
		}
		fmt.Printf("    H2 WINDOW_UPDATE: %d\n", parsed.HTTP2.WindowUpdate)
	}
	if parsed.HTTP2.AKAMAI != "" {
		fmt.Printf("    Akamai h2:      %s\n", parsed.HTTP2.AKAMAI)
	}
	fmt.Println()
}

func main() {
	const host = "tls.peet.ws"

	// 1. Go native TLS (http2)
	fmt.Println("=== HTTP/2 Fingerprint Comparison via tls.peet.ws ===\n")
	goClient := &http.Client{Timeout: 15 * time.Second}
	fetchPeet("Go native TLS", goClient)

	// 2. utls Chrome
	chromeDialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	chromeClient := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return chromeDialTLS(ctx, network, addr)
			},
		},
		Timeout: 15 * time.Second,
	}
	fetchPeet("utls Chrome (HelloChrome_Auto)", chromeClient)

	// 3. utls Firefox
	firefoxDialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloFirefox_Auto)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	firefoxClient := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return firefoxDialTLS(ctx, network, addr)
			},
		},
		Timeout: 15 * time.Second,
	}
	fetchPeet("utls Firefox (HelloFirefox_Auto)", firefoxClient)

	// Summary
	fmt.Println("=== Analysis ===")
	fmt.Println()
	fmt.Println("Expected real browser HTTP/2 SETTINGS:")
	fmt.Println("  Chrome:  HEADER_TABLE_SIZE=65536, INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144")
	fmt.Println("  Firefox: HEADER_TABLE_SIZE=65536, INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384")
	fmt.Println("  Go:      HEADER_TABLE_SIZE=4096, MAX_FRAME_SIZE=16384, INITIAL_WINDOW_SIZE=4194304, MAX_HEADER_LIST_SIZE=10485760")
	fmt.Println()
	fmt.Println("If utls Chrome/Firefox show Go's SETTINGS instead of the browser's,")
	fmt.Println("the server can detect that TLS says Chrome but HTTP/2 says Go.")

	// Now try a site that might actually block
	fmt.Println()
	fmt.Println("=== Testing bot-detection sites ===")
	fmt.Println()

	botSites := []string{
		"https://www.g2.com/",
		"https://www.bestbuy.com/",
	}

	for _, url := range botSites {
		fmt.Printf("--- %s ---\n", url)

		host := strings.TrimPrefix(url, "https://")
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}

		// Go native
		goResp, err := goClient.Get(url)
		if err != nil {
			fmt.Printf("  Go native:    ERROR: %v\n", err)
		} else {
			body, _ := io.ReadAll(io.LimitReader(goResp.Body, 200))
			goResp.Body.Close()
			preview := strings.ReplaceAll(string(body), "\n", " ")
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			fmt.Printf("  Go native:    HTTP %d | %s\n", goResp.StatusCode, preview)
		}

		// utls Chrome
		dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			tcpConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
			if err := tlsConn.Handshake(); err != nil {
				tcpConn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
		utlsClient := &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return dialTLS(ctx, network, addr)
				},
			},
			Timeout: 15 * time.Second,
		}
		utlsResp, err := utlsClient.Get(url)
		if err != nil {
			fmt.Printf("  utls Chrome:  ERROR: %v\n", err)
		} else {
			body, _ := io.ReadAll(io.LimitReader(utlsResp.Body, 200))
			utlsResp.Body.Close()
			preview := strings.ReplaceAll(string(body), "\n", " ")
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			fmt.Printf("  utls Chrome:  HTTP %d | %s\n", utlsResp.StatusCode, preview)
		}
		fmt.Println()
	}
}
