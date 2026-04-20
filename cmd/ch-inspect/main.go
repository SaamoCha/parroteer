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

	"golang.org/x/crypto/cryptobyte"
)

// Parsed extension info
type ExtInfo struct {
	Type   uint16 `json:"type"`
	Length int    `json:"length"`
	Name   string `json:"name,omitempty"`
}

type CHInspection struct {
	RecordLen        int       `json:"record_len"`
	HandshakeLen     int       `json:"handshake_len"`
	SupportedGroups  []uint16  `json:"supported_groups"`
	CompressCertAlgs []uint16  `json:"compress_cert_algs,omitempty"`
	ECHPresent       bool      `json:"ech_present"`
	ECHExtLen        int       `json:"ech_ext_len,omitempty"`
	PaddingPresent   bool      `json:"padding_present"`
	PaddingLen       int       `json:"padding_len,omitempty"`
	Extensions       []ExtInfo `json:"extensions"`
	TotalCHLen       int       `json:"total_ch_len"`
}

var extNames = map[uint16]string{
	0: "server_name", 1: "max_fragment_length", 5: "status_request",
	10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
	16: "alpn", 18: "sct", 21: "padding", 23: "extended_master_secret",
	27: "compress_certificate", 28: "record_size_limit",
	34: "delegated_credentials", 35: "session_ticket",
	43: "supported_versions", 45: "psk_key_exchange_modes",
	51: "key_share", 17513: "alps_old", 17613: "alps_new",
	65037: "ech", 65281: "renegotiation_info",
}

func main() {
	// Generate self-signed cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write temp cert files
	os.WriteFile("/tmp/ch-inspect-cert.pem", certPEM, 0600)
	os.WriteFile("/tmp/ch-inspect-key.pem", keyPEM, 0600)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Listening on %s\n", ln.Addr())
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)

	conn, err := ln.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := fullRead(conn, header); err != nil {
		fmt.Fprintf(os.Stderr, "read header: %v\n", err)
		os.Exit(1)
	}

	recordLen := int(header[3])<<8 | int(header[4])
	record := make([]byte, recordLen)
	if _, err := fullRead(conn, record); err != nil {
		fmt.Fprintf(os.Stderr, "read record: %v\n", err)
		os.Exit(1)
	}

	inspection := inspectClientHello(header, record)
	out, _ := json.MarshalIndent(inspection, "", "  ")
	fmt.Fprintln(os.Stderr, string(out))
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

func inspectClientHello(header, record []byte) CHInspection {
	result := CHInspection{
		RecordLen:  len(record),
		TotalCHLen: 5 + len(record), // record header + body
	}

	// Skip handshake header (1 type + 3 length)
	if len(record) < 4 {
		return result
	}
	result.HandshakeLen = int(record[1])<<16 | int(record[2])<<8 | int(record[3])

	s := cryptobyte.String(record[4:]) // skip handshake header

	// client_version (2) + random (32) = 34
	var clientVersion uint16
	var random []byte
	if !s.ReadUint16(&clientVersion) || !s.ReadBytes(&random, 32) {
		return result
	}

	// session_id
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return result
	}

	// cipher_suites
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return result
	}

	// compression_methods
	var compMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compMethods) {
		return result
	}

	// extensions
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
				name = fmt.Sprintf("unknown(%d)", extType)
			}
		}

		info := ExtInfo{Type: extType, Length: len(extData), Name: name}
		result.Extensions = append(result.Extensions, info)

		switch extType {
		case 10: // supported_groups
			d := cryptobyte.String(extData)
			var groupList cryptobyte.String
			if d.ReadUint16LengthPrefixed(&groupList) {
				for !groupList.Empty() {
					var g uint16
					if groupList.ReadUint16(&g) {
						result.SupportedGroups = append(result.SupportedGroups, g)
					}
				}
			}
		case 27: // compress_certificate
			d := cryptobyte.String(extData)
			var algList cryptobyte.String
			if d.ReadUint8LengthPrefixed(&algList) {
				for !algList.Empty() {
					var alg uint16
					if algList.ReadUint16(&alg) {
						result.CompressCertAlgs = append(result.CompressCertAlgs, alg)
					}
				}
			}
		case 21: // padding
			result.PaddingPresent = true
			result.PaddingLen = len(extData)
		case 65037: // ECH
			result.ECHPresent = true
			result.ECHExtLen = len(extData)
		}
	}

	return result
}
