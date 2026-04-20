package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type ExtInfo struct {
	Type   uint16 `json:"type"`
	Length int    `json:"length"`
	Name   string `json:"name,omitempty"`
}

type CHInspection struct {
	Label            string   `json:"label"`
	TotalRecordLen   int      `json:"total_record_len"`
	HandshakeLen     int      `json:"handshake_len"`
	SupportedGroups  []uint16 `json:"supported_groups"`
	CompressCertAlgs []uint16 `json:"compress_cert_algs,omitempty"`
	ECHPresent       bool     `json:"ech_present"`
	ECHExtLen        int      `json:"ech_ext_len,omitempty"`
	PaddingPresent   bool     `json:"padding_present"`
	PaddingLen       int      `json:"padding_len,omitempty"`
	Extensions       []ExtInfo `json:"extensions"`
}

var extNames = map[uint16]string{
	0: "server_name", 5: "status_request", 10: "supported_groups",
	11: "ec_point_formats", 13: "signature_algorithms", 16: "alpn",
	18: "sct", 21: "padding", 23: "extended_master_secret",
	27: "compress_certificate", 28: "record_size_limit",
	34: "delegated_credentials", 35: "session_ticket",
	43: "supported_versions", 45: "psk_key_exchange_modes",
	51: "key_share", 17513: "alps_old", 17613: "alps_new",
	65037: "ech_grease", 65281: "renegotiation_info",
}

func main() {
	certPEM, keyPEM := generateSelfSignedCert()

	parrots := []struct {
		name string
		id   tls.ClientHelloID
	}{
		{"utls_chrome_auto", tls.HelloChrome_Auto},
		{"utls_firefox_auto", tls.HelloFirefox_Auto},
		{"utls_edge_auto", tls.HelloEdge_Auto},
	}

	results := []CHInspection{}

	for _, p := range parrots {
		inspection, err := captureUTLSClientHello(p.name, p.id, certPEM, keyPEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p.name, err)
			continue
		}
		results = append(results, inspection)
	}

	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))
}

func captureUTLSClientHello(label string, helloID tls.ClientHelloID, certPEM, keyPEM []byte) (CHInspection, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return CHInspection{}, err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.UClient(conn, &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
		}, helloID)
		errCh <- tlsConn.Handshake()
	}()

	conn, err := ln.Accept()
	if err != nil {
		return CHInspection{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read TLS record header
	header := make([]byte, 5)
	if _, err := fullRead(conn, header); err != nil {
		return CHInspection{}, err
	}
	recordLen := int(header[3])<<8 | int(header[4])
	record := make([]byte, recordLen)
	if _, err := fullRead(conn, record); err != nil {
		return CHInspection{}, err
	}

	return parseClientHello(label, header, record), nil
}

func parseClientHello(label string, header, record []byte) CHInspection {
	result := CHInspection{
		Label:          label,
		TotalRecordLen: 5 + len(record),
	}

	if len(record) < 4 {
		return result
	}
	result.HandshakeLen = int(record[1])<<16 | int(record[2])<<8 | int(record[3])

	s := cryptobyte.String(record[4:])
	var clientVersion uint16
	var random []byte
	if !s.ReadUint16(&clientVersion) || !s.ReadBytes(&random, 32) {
		return result
	}
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return result
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return result
	}
	var compMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compMethods) {
		return result
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return result
	}

	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			break
		}
		name := extNames[extType]
		if name == "" {
			if extType&0x0f0f == 0x0a0a {
				name = "GREASE"
			} else {
				name = fmt.Sprintf("unknown(0x%04x)", extType)
			}
		}
		info := ExtInfo{Type: extType, Length: len(extData), Name: name}
		result.Extensions = append(result.Extensions, info)

		switch extType {
		case 10:
			d := cryptobyte.String(extData)
			var gl cryptobyte.String
			if d.ReadUint16LengthPrefixed(&gl) {
				for !gl.Empty() {
					var g uint16
					if gl.ReadUint16(&g) {
						result.SupportedGroups = append(result.SupportedGroups, g)
					}
				}
			}
		case 27:
			d := cryptobyte.String(extData)
			var al cryptobyte.String
			if d.ReadUint8LengthPrefixed(&al) {
				for !al.Empty() {
					var a uint16
					if al.ReadUint16(&a) {
						result.CompressCertAlgs = append(result.CompressCertAlgs, a)
					}
				}
			}
		case 21:
			result.PaddingPresent = true
			result.PaddingLen = len(extData)
		case 65037:
			result.ECHPresent = true
			result.ECHExtLen = len(extData)
		}
	}
	return result
}

func fullRead(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func generateSelfSignedCert() ([]byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
