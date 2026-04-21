// replay-verify loads a utls spec JSON, connects to the reflector using
// that spec, and compares the resulting fingerprint against the original
// capture to verify the spec reproduces the browser's fingerprint.
//
// Usage: go run cmd/replay-verify/main.go <spec.json> <original-capture.json>
//
// Exit code 0: fingerprints match
// Exit code 1: fingerprints differ (prints diff)
// Exit code 2: error
package main

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"

	tls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
	"golang.org/x/net/http2"
)

const reflectorHost = "tls.browserleaks.com"
const reflectorURL = "https://tls.browserleaks.com/"

func init() {
	// Patch dicttls maps with entries not yet upstream
	dicttls.DictSupportedGroupsNameIndexed["X25519MLKEM768"] = 4588
	dicttls.DictSupportedGroupsValueIndexed[4588] = "X25519MLKEM768"

	// ECH GREASE extension
	dicttls.DictExtTypeNameIndexed["encrypted_client_hello"] = 0xfe0d
	dicttls.DictExtTypeValueIndexed[0xfe0d] = "encrypted_client_hello"

	// application_settings_new (17613) — may already be in dicttls but ensure it
	dicttls.DictExtTypeNameIndexed["application_settings_new"] = 17613
	dicttls.DictExtTypeValueIndexed[17613] = "application_settings_new"
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: replay-verify <spec.json> <original-capture.json>\n")
		os.Exit(2)
	}

	specFile := os.Args[1]
	captureFile := os.Args[2]

	// Load and parse the spec
	specJSON, err := os.ReadFile(specFile)
	if err != nil {
		fatal("read spec: %v", err)
	}

	// Pre-process: remove extensions that utls's JSON unmarshaler can't handle
	originalSpecJSON := specJSON
	specJSON = preprocessSpec(specJSON)

	specUnmarshaler := tls.ClientHelloSpecJSONUnmarshaler{
		Extensions: &tls.TLSExtensionsJSONUnmarshaler{
			AllowUnknownExt: true,
		},
	}
	if err := json.Unmarshal(specJSON, &specUnmarshaler); err != nil {
		fatal("parse spec: %v", err)
	}
	spec := specUnmarshaler.ClientHelloSpec()

	// Re-inject extensions that were stripped during preprocessing
	spec = injectMissingExtensions(originalSpecJSON, spec)

	// Connect to reflector using the spec
	fmt.Fprintf(os.Stderr, "Connecting to %s with generated spec...\n", reflectorHost)
	replayJSON, err := connectWithSpec(spec)
	if err != nil {
		fatal("replay connection: %v", err)
	}

	// Load original capture
	captureJSON, err := os.ReadFile(captureFile)
	if err != nil {
		fatal("read capture: %v", err)
	}

	// Normalize both
	replayFP := normalizeCapture(replayJSON)
	originalFP := normalizeCapture(captureJSON)

	// Compare
	diffs := compareFP(originalFP, replayFP)
	if len(diffs) == 0 {
		fmt.Println("MATCH: replay fingerprint matches original capture")
		os.Exit(0)
	} else {
		fmt.Println("MISMATCH: replay fingerprint differs from original capture")
		fmt.Println()
		for _, d := range diffs {
			fmt.Printf("  %s:\n    original: %v\n    replay:   %v\n\n", d.field, d.original, d.replay)
		}
		os.Exit(1)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(2)
}

func connectWithSpec(spec tls.ClientHelloSpec) ([]byte, error) {
	roots, _ := x509.SystemCertPool()

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.UClient(tcpConn, &tls.Config{
			ServerName: reflectorHost,
			RootCAs:    roots,
		}, tls.HelloCustom)
		if err := tlsConn.ApplyPreset(&spec); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("apply preset: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("handshake: %w", err)
		}
		return tlsConn, nil
	}

	// Try HTTP/2 first
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
			return dialTLS(ctx, network, addr)
		},
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", reflectorURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		// Fallback to HTTP/1.1
		transport1 := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTLS(ctx, network, addr)
			},
		}
		client1 := &http.Client{Transport: transport1}
		resp, err = client1.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// ─── Minimal normalization (Go port of key parts of normalize.ts) ─────

type fingerprint struct {
	cipherSuites []int
	extensions   []int
	groups       []int
	versions     []int
	keyShares    []int
	sigAlgs      []int
}

type idNameObj struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type extObj struct {
	ID   int             `json:"id"`
	Name string          `json:"name"`
	Data json.RawMessage `json:"data,omitempty"`
}

type captureTop struct {
	TLS *captureTLS `json:"tls"`
}

type captureTLS struct {
	CipherSuites []idNameObj `json:"cipher_suites"`
	Extensions   []extObj    `json:"extensions"`
}

func greaseReplace(id int) int {
	if id >= 0x0a0a && (id&0x0f0f) == 0x0a0a {
		return -1
	}
	return id
}

func normalizeCapture(data []byte) fingerprint {
	var cap captureTop
	json.Unmarshal(data, &cap)

	fp := fingerprint{}
	if cap.TLS == nil {
		return fp
	}

	for _, cs := range cap.TLS.CipherSuites {
		fp.cipherSuites = append(fp.cipherSuites, greaseReplace(int(cs.ID)))
	}

	// Extensions: extract IDs, stabilize order (GREASE bookends, sort middle)
	extIDs := make([]int, 0, len(cap.TLS.Extensions))
	for _, e := range cap.TLS.Extensions {
		extIDs = append(extIDs, greaseReplace(int(e.ID)))
	}
	fp.extensions = stabilizeExtOrder(extIDs)

	// Parse sub-extension data
	for _, e := range cap.TLS.Extensions {
		switch e.ID {
		case 10: // supported_groups
			var d struct {
				NamedGroupList []idNameObj `json:"named_group_list"`
			}
			json.Unmarshal(e.Data, &d)
			for _, g := range d.NamedGroupList {
				fp.groups = append(fp.groups, greaseReplace(int(g.ID)))
			}
		case 43: // supported_versions
			var d struct {
				Versions []idNameObj `json:"versions"`
			}
			json.Unmarshal(e.Data, &d)
			for _, v := range d.Versions {
				fp.versions = append(fp.versions, greaseReplace(int(v.ID)))
			}
		case 51: // key_share
			var d struct {
				ClientShares []struct {
					Group idNameObj `json:"group"`
				} `json:"client_shares"`
			}
			json.Unmarshal(e.Data, &d)
			for _, s := range d.ClientShares {
				fp.keyShares = append(fp.keyShares, greaseReplace(int(s.Group.ID)))
			}
		case 13: // signature_algorithms
			var d struct {
				Algs []idNameObj `json:"supported_signature_algorithms"`
			}
			json.Unmarshal(e.Data, &d)
			for _, a := range d.Algs {
				fp.sigAlgs = append(fp.sigAlgs, int(a.ID))
			}
		}
	}

	return fp
}

func stabilizeExtOrder(ids []int) []int {
	// Peel leading GREASE
	i := 0
	var leading []int
	for i < len(ids) && ids[i] == -1 {
		leading = append(leading, -1)
		i++
	}
	// Peel trailing GREASE
	j := len(ids) - 1
	var trailing []int
	for j >= i && ids[j] == -1 {
		trailing = append(trailing, -1)
		j--
	}
	// Sort middle
	middle := make([]int, 0, j-i+1)
	if j >= i {
		middle = append(middle, ids[i:j+1]...)
	}
	sort.Ints(middle)

	result := make([]int, 0, len(ids))
	result = append(result, leading...)
	result = append(result, middle...)
	result = append(result, trailing...)
	return result
}

type diff struct {
	field    string
	original interface{}
	replay   interface{}
}

func compareFP(a, b fingerprint) []diff {
	var diffs []diff
	if !intSliceEqual(a.cipherSuites, b.cipherSuites) {
		diffs = append(diffs, diff{"cipher_suites", a.cipherSuites, b.cipherSuites})
	}
	if !intSliceEqual(a.extensions, b.extensions) {
		diffs = append(diffs, diff{"extensions", a.extensions, b.extensions})
	}
	if !intSliceEqual(a.groups, b.groups) {
		diffs = append(diffs, diff{"supported_groups", a.groups, b.groups})
	}
	if !intSliceEqual(a.versions, b.versions) {
		diffs = append(diffs, diff{"supported_versions", a.versions, b.versions})
	}
	if !intSliceEqual(a.keyShares, b.keyShares) {
		diffs = append(diffs, diff{"key_share_groups", a.keyShares, b.keyShares})
	}
	if !intSliceEqual(a.sigAlgs, b.sigAlgs) {
		diffs = append(diffs, diff{"signature_algorithms", a.sigAlgs, b.sigAlgs})
	}
	return diffs
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// injectMissingExtensions adds back extensions that were stripped during
// preprocessing (because the JSON unmarshaler can't handle them).
func injectMissingExtensions(originalSpecJSON []byte, spec tls.ClientHelloSpec) tls.ClientHelloSpec {
	// Check if original spec had ECH
	var raw struct {
		Extensions []struct {
			Name string `json:"name"`
		} `json:"extensions"`
	}
	json.Unmarshal(originalSpecJSON, &raw)

	for _, ext := range raw.Extensions {
		if ext.Name == "encrypted_client_hello" {
			// Insert GREASEEncryptedClientHelloExtension before the last extension
			echExt := &tls.GREASEEncryptedClientHelloExtension{}
			// Insert near the end (before trailing GREASE/padding)
			n := len(spec.Extensions)
			if n > 1 {
				spec.Extensions = append(spec.Extensions[:n-1], echExt, spec.Extensions[n-1])
			} else {
				spec.Extensions = append(spec.Extensions, echExt)
			}
			break
		}
	}
	return spec
}

// preprocessSpec removes or replaces extensions that utls's JSON
// unmarshaler cannot handle (e.g., ECH GREASE).
func preprocessSpec(specJSON []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(specJSON, &raw); err != nil {
		return specJSON
	}

	var extensions []map[string]interface{}
	if err := json.Unmarshal(raw["extensions"], &extensions); err != nil {
		return specJSON
	}

	// Filter out incompatible extensions, replace ECH with GREASE
	filtered := make([]map[string]interface{}, 0, len(extensions))
	for _, ext := range extensions {
		name, _ := ext["name"].(string)
		switch name {
		case "encrypted_client_hello":
			// ECH GREASE isn't JSON-compatible in utls, skip it.
			// The fingerprint comparison will note its absence.
			continue
		default:
			filtered = append(filtered, ext)
		}
	}

	filteredJSON, _ := json.Marshal(filtered)
	raw["extensions"] = filteredJSON
	result, _ := json.Marshal(raw)
	return result
}
