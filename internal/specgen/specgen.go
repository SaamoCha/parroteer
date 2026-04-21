// Package specgen translates a browserleaks raw capture JSON into the
// utls ClientHelloSpec JSON format that can be loaded by utls's
// ClientHelloSpecJSONUnmarshaler.
package specgen

import (
	"encoding/json"
	"fmt"
	"sort"
)

// BrowserleaksCapture is the top-level response from tls.browserleaks.com/
type BrowserleaksCapture struct {
	TLS *TLSObject `json:"tls"`
}

type TLSObject struct {
	CipherSuites []IdName     `json:"cipher_suites"`
	Extensions   []Extension  `json:"extensions"`
}

type IdName struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

type Extension struct {
	ID   uint16          `json:"id"`
	Name string          `json:"name"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Parsed extension data types
type SupportedGroupsData struct {
	NamedGroupList []IdName `json:"named_group_list"`
}

type SignatureAlgorithmsData struct {
	SupportedSignatureAlgorithms []IdName `json:"supported_signature_algorithms"`
}

type ALPNData struct {
	ProtocolNameList []string `json:"protocol_name_list"`
}

type SupportedVersionsData struct {
	Versions []IdName `json:"versions"`
}

type KeyShareData struct {
	ClientShares []KeyShareEntry `json:"client_shares"`
}

type KeyShareEntry struct {
	Group             IdName `json:"group"`
	KeyExchangeLength int    `json:"key_exchange_length"`
}

type ECPointFormatsData struct {
	ECPointFormatList []IdName `json:"ec_point_format_list"`
}

type PSKKeyExchangeModesData struct {
	KEModes []IdName `json:"ke_modes"`
}

type CompressCertData struct {
	Algorithms []IdName `json:"algorithms"`
}

// ─── Output types (utls JSON format) ────────────────────────────────────

type UTLSSpec struct {
	CipherSuites       []string       `json:"cipher_suites"`
	CompressionMethods []string       `json:"compression_methods"`
	Extensions         []UTLSExtJSON  `json:"extensions"`
}

// UTLSExtJSON is a flexible map for extension JSON output
type UTLSExtJSON map[string]interface{}

// ─── Mappings ────────────────────────────────────────────────────────────

var cipherSuiteIDToName = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0xc0a2: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc0a0: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc0a3: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc0a1: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	// Safari legacy
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
}

var groupIDToName = map[uint16]string{
	4588: "X25519MLKEM768",
	29:   "x25519",
	23:   "secp256r1",
	24:   "secp384r1",
	25:   "secp521r1",
	30:   "x448",
	256:  "ffdhe2048",
	257:  "ffdhe3072",
}

var sigSchemeIDToName = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	// Post-quantum
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
}

var versionIDToName = map[uint16]string{
	0x0304: "TLS 1.3",
	0x0303: "TLS 1.2",
	0x0302: "TLS 1.1",
	0x0301: "TLS 1.0",
}

var certCompIDToName = map[uint16]string{
	1: "zlib",
	2: "brotli",
	3: "zstd",
}

var pskModeIDToName = map[uint16]string{
	0: "psk_ke",
	1: "psk_dhe_ke",
}

var pointFormatIDToName = map[uint16]string{
	0: "uncompressed",
	1: "ansiX962_compressed_prime",
	2: "ansiX962_compressed_char2",
}

func isGREASE(id uint16) bool {
	return id >= 0x0a0a && (id&0x0f0f) == 0x0a0a
}

// Generate converts a browserleaks raw capture JSON into utls spec JSON.
func Generate(captureJSON []byte) ([]byte, error) {
	var capture BrowserleaksCapture
	if err := json.Unmarshal(captureJSON, &capture); err != nil {
		return nil, fmt.Errorf("parse capture: %w", err)
	}

	if capture.TLS == nil {
		return nil, fmt.Errorf("capture has no tls object")
	}

	spec := UTLSSpec{
		CompressionMethods: []string{"NULL"},
	}

	// Cipher suites
	for _, cs := range capture.TLS.CipherSuites {
		if isGREASE(cs.ID) {
			spec.CipherSuites = append(spec.CipherSuites, "GREASE")
		} else if name, ok := cipherSuiteIDToName[cs.ID]; ok {
			spec.CipherSuites = append(spec.CipherSuites, name)
		} else {
			// Fallback: use the name from the capture itself
			spec.CipherSuites = append(spec.CipherSuites, cs.Name)
		}
	}

	// Extensions
	for _, ext := range capture.TLS.Extensions {
		extJSON, err := translateExtension(ext)
		if err != nil {
			return nil, fmt.Errorf("extension %d (%s): %w", ext.ID, ext.Name, err)
		}
		spec.Extensions = append(spec.Extensions, extJSON)
	}

	return json.MarshalIndent(spec, "", "\t")
}

func translateExtension(ext Extension) (UTLSExtJSON, error) {
	if isGREASE(ext.ID) {
		return UTLSExtJSON{"name": "GREASE"}, nil
	}

	switch ext.ID {
	case 0: // server_name
		return UTLSExtJSON{"name": "server_name"}, nil
	case 5: // status_request
		return UTLSExtJSON{"name": "status_request"}, nil
	case 10: // supported_groups
		return translateSupportedGroups(ext)
	case 11: // ec_point_formats
		return translateECPointFormats(ext)
	case 13: // signature_algorithms
		return translateSignatureAlgorithms(ext)
	case 16: // ALPN
		return translateALPN(ext)
	case 17: // extended_master_secret  (actually ID 23, but let's handle by ID)
		return UTLSExtJSON{"name": "extended_master_secret"}, nil
	case 18: // signed_certificate_timestamp
		return UTLSExtJSON{"name": "signed_certificate_timestamp"}, nil
	case 21: // padding
		return UTLSExtJSON{"name": "padding", "len": 0}, nil
	case 22: // encrypt_then_mac
		return UTLSExtJSON{"name": "encrypt_then_mac"}, nil
	case 23: // extended_master_secret
		return UTLSExtJSON{"name": "extended_master_secret"}, nil
	case 27: // compress_certificate
		return translateCompressCert(ext)
	case 28: // record_size_limit
		return UTLSExtJSON{"name": "record_size_limit", "limit": 0x4001}, nil
	case 34: // delegated_credentials
		return translateDelegatedCredentials(ext)
	case 35: // session_ticket
		return UTLSExtJSON{"name": "session_ticket"}, nil
	case 43: // supported_versions
		return translateSupportedVersions(ext)
	case 45: // psk_key_exchange_modes
		return translatePSKModes(ext)
	case 49: // post_handshake_auth
		return UTLSExtJSON{"name": "post_handshake_auth"}, nil
	case 51: // key_share
		return translateKeyShare(ext)
	case 17513: // application_settings (old)
		return translateALPS(ext, "application_settings")
	case 17613: // application_settings (new codepoint)
		return translateALPS(ext, "application_settings_new")
	case 65037: // ECH GREASE (0xfe0d)
		return UTLSExtJSON{"name": "encrypted_client_hello"}, nil
	case 65281: // renegotiation_info
		return UTLSExtJSON{"name": "renegotiation_info"}, nil
	default:
		// Generic fallback
		return UTLSExtJSON{"name": ext.Name}, nil
	}
}

func translateSupportedGroups(ext Extension) (UTLSExtJSON, error) {
	var data SupportedGroupsData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	groups := make([]string, 0, len(data.NamedGroupList))
	for _, g := range data.NamedGroupList {
		if isGREASE(g.ID) {
			groups = append(groups, "GREASE")
		} else if name, ok := groupIDToName[g.ID]; ok {
			groups = append(groups, name)
		} else {
			groups = append(groups, g.Name)
		}
	}

	return UTLSExtJSON{
		"name":             "supported_groups",
		"named_group_list": groups,
	}, nil
}

func translateECPointFormats(ext Extension) (UTLSExtJSON, error) {
	var data ECPointFormatsData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	formats := make([]string, 0, len(data.ECPointFormatList))
	for _, f := range data.ECPointFormatList {
		if name, ok := pointFormatIDToName[f.ID]; ok {
			formats = append(formats, name)
		} else {
			formats = append(formats, f.Name)
		}
	}

	return UTLSExtJSON{
		"name":                 "ec_point_formats",
		"ec_point_format_list": formats,
	}, nil
}

func translateSignatureAlgorithms(ext Extension) (UTLSExtJSON, error) {
	var data SignatureAlgorithmsData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	algs := make([]string, 0, len(data.SupportedSignatureAlgorithms))
	for _, a := range data.SupportedSignatureAlgorithms {
		if name, ok := sigSchemeIDToName[a.ID]; ok {
			algs = append(algs, name)
		} else {
			algs = append(algs, a.Name)
		}
	}

	return UTLSExtJSON{
		"name":                          "signature_algorithms",
		"supported_signature_algorithms": algs,
	}, nil
}

func translateALPN(ext Extension) (UTLSExtJSON, error) {
	var data ALPNData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	return UTLSExtJSON{
		"name":               "application_layer_protocol_negotiation",
		"protocol_name_list": data.ProtocolNameList,
	}, nil
}

func translateSupportedVersions(ext Extension) (UTLSExtJSON, error) {
	var data SupportedVersionsData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	versions := make([]string, 0, len(data.Versions))
	for _, v := range data.Versions {
		if isGREASE(v.ID) {
			versions = append(versions, "GREASE")
		} else if name, ok := versionIDToName[v.ID]; ok {
			versions = append(versions, name)
		} else {
			versions = append(versions, v.Name)
		}
	}

	return UTLSExtJSON{
		"name":     "supported_versions",
		"versions": versions,
	}, nil
}

func translateKeyShare(ext Extension) (UTLSExtJSON, error) {
	var data KeyShareData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	shares := make([]map[string]interface{}, 0, len(data.ClientShares))
	for _, s := range data.ClientShares {
		if isGREASE(s.Group.ID) {
			shares = append(shares, map[string]interface{}{
				"group":        "GREASE",
				"key_exchange": []int{0},
			})
		} else {
			groupName := s.Group.Name
			if name, ok := groupIDToName[s.Group.ID]; ok {
				groupName = name
			}
			shares = append(shares, map[string]interface{}{
				"group": groupName,
			})
		}
	}

	return UTLSExtJSON{
		"name":          "key_share",
		"client_shares": shares,
	}, nil
}

func translatePSKModes(ext Extension) (UTLSExtJSON, error) {
	var data PSKKeyExchangeModesData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	modes := make([]string, 0, len(data.KEModes))
	for _, m := range data.KEModes {
		if name, ok := pskModeIDToName[m.ID]; ok {
			modes = append(modes, name)
		} else {
			modes = append(modes, m.Name)
		}
	}

	return UTLSExtJSON{
		"name":     "psk_key_exchange_modes",
		"ke_modes": modes,
	}, nil
}

func translateCompressCert(ext Extension) (UTLSExtJSON, error) {
	var data CompressCertData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return nil, err
		}
	}

	algs := make([]string, 0, len(data.Algorithms))
	for _, a := range data.Algorithms {
		if name, ok := certCompIDToName[a.ID]; ok {
			algs = append(algs, name)
		} else {
			algs = append(algs, a.Name)
		}
	}

	return UTLSExtJSON{
		"name":       "compress_certificate",
		"algorithms": algs,
	}, nil
}

func translateDelegatedCredentials(ext Extension) (UTLSExtJSON, error) {
	// browserleaks returns the sig algs supported for delegated creds
	var data SignatureAlgorithmsData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			// If data doesn't match, just emit name-only
			return UTLSExtJSON{"name": "delegated_credentials"}, nil
		}
	}

	algs := make([]string, 0, len(data.SupportedSignatureAlgorithms))
	for _, a := range data.SupportedSignatureAlgorithms {
		if name, ok := sigSchemeIDToName[a.ID]; ok {
			algs = append(algs, name)
		} else {
			algs = append(algs, a.Name)
		}
	}

	return UTLSExtJSON{
		"name":                          "delegated_credentials",
		"supported_signature_algorithms": algs,
	}, nil
}

func translateALPS(ext Extension, name string) (UTLSExtJSON, error) {
	// ALPS has same structure as ALPN
	var data ALPNData
	if ext.Data != nil {
		if err := json.Unmarshal(ext.Data, &data); err != nil {
			return UTLSExtJSON{"name": name, "supported_protocols": []string{"h2"}}, nil
		}
	}

	protocols := data.ProtocolNameList
	if len(protocols) == 0 {
		protocols = []string{"h2"}
	}

	return UTLSExtJSON{
		"name":                name,
		"supported_protocols": protocols,
	}, nil
}

// Unused but keeping sort import happy
var _ = sort.Strings
