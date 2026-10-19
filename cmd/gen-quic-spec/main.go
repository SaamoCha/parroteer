// gen-quic-spec starts from a uquic parrot, patches it toward a real browser's
// QUIC capture, and records the Initial flight the patched spec sends.
//
// It patches what a clienthellod capture exposes: the transport parameter set
// and the values clienthellod decodes, plus the supported_groups, key_share,
// signature_algorithms, ALPN, supported_versions, psk_key_exchange_modes and
// compress_certificate lists. Whole TLS extensions are not added or removed;
// those show up as remaining differences when the result is compared.
//
// Usage: go run ./cmd/gen-quic-spec -capture real.json -parrot chrome -out patched.json
//
// The patch notes are printed to stdout as a Markdown list.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	tls "github.com/refraction-networking/utls"

	quic "github.com/refraction-networking/uquic"

	"github.com/parroteer/parroteer/internal/quiccapture"
)

var parrots = map[string]quic.QUICID{
	"chrome":  quic.QUICChrome_146,
	"firefox": quic.QUICFirefox_116,
}

const (
	tpVersionInformation       = 0x11
	tpVersionInformationLegacy = 0xff73db
	tpGoogleInitialRTT         = 0x3127 // stateful, see normalize-quic.ts
	tpGrease                   = 27
)

// clienthellod field names for the transport parameters whose values it decodes.
var tpNames = map[uint64]string{
	0x01: "max_idle_timeout",
	0x03: "max_udp_payload_size",
	0x04: "initial_max_data",
	0x05: "initial_max_stream_data_bidi_local",
	0x06: "initial_max_stream_data_bidi_remote",
	0x07: "initial_max_stream_data_uni",
	0x08: "initial_max_streams_bidi",
	0x09: "initial_max_streams_uni",
	0x0b: "max_ack_delay",
	0x0e: "active_connection_id_limit",
	0x20: "max_datagram_frame_size",
}

type capture struct {
	ClientInitials struct {
		ClientHello struct {
			SupportedGroups     []uint16 `json:"supported_groups"`
			KeyShare            []uint16 `json:"key_share"`
			SignatureAlgorithms []uint16 `json:"signature_algorithms"`
			ALPN                []string `json:"alpn"`
			SupportedVersions   []uint16 `json:"supported_versions"`
			PSKModes            []uint8  `json:"psk_key_exchange_modes"`
			CompressCertificate []uint16 `json:"compress_certificate"`
		} `json:"client_hello"`
		TransportParameters map[string]json.RawMessage `json:"transport_parameters"`
	} `json:"ClientInitials"`
}

var notes []string

func note(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }

func main() {
	captureFile := flag.String("capture", "", "real browser QUIC capture (clienthellod JSON)")
	parrot := flag.String("parrot", "chrome", "uquic parrot to start from: chrome or firefox")
	out := flag.String("out", "", "where to write the patched spec's QUIC fingerprint (JSON)")
	sni := flag.String("sni", "reflector.test", "server name to put in the ClientHello")
	flag.Parse()
	if *captureFile == "" || *out == "" {
		fail("usage: gen-quic-spec -capture real.json -parrot chrome -out patched.json")
	}

	raw, err := os.ReadFile(*captureFile)
	if err != nil {
		fail("read capture: %v", err)
	}
	var real capture
	if err := json.Unmarshal(raw, &real); err != nil {
		fail("parse capture: %v", err)
	}
	id, ok := parrots[*parrot]
	if !ok {
		fail("unknown parrot %q", *parrot)
	}
	spec, err := quic.QUICID2Spec(id)
	if err != nil {
		fail("QUICID2Spec: %v", err)
	}

	patchTransportParameters(&spec, &real)
	patchClientHello(&spec, &real)

	fp, err := quiccapture.Offline(&spec, *sni, 3*time.Second)
	if err != nil {
		fail("capture patched spec: %v", err)
	}
	fp.UserAgent = "uquic " + *parrot + " (patched)"
	b, err := json.MarshalIndent(fp, "", " ")
	if err != nil {
		fail("marshal: %v", err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fail("write: %v", err)
	}

	if len(notes) == 0 {
		fmt.Println("- no patch needed for the fields gen-quic-spec covers")
	}
	for _, n := range notes {
		fmt.Println("- " + n)
	}
}

func realTransportParameters(real *capture) (ids map[uint64]bool, values map[uint64]uint64) {
	ids, values = map[uint64]bool{}, map[uint64]uint64{}
	var tpids []uint64
	_ = json.Unmarshal(real.ClientInitials.TransportParameters["tpids"], &tpids)
	for _, id := range tpids {
		if id != tpGrease && id != tpGoogleInitialRTT {
			ids[id] = true
		}
	}
	for id, name := range tpNames {
		var bs []byte
		if json.Unmarshal(real.ClientInitials.TransportParameters[name], &bs) == nil && len(bs) > 0 {
			var v uint64
			for _, x := range bs {
				v = v<<8 | uint64(x)
			}
			values[id] = v
		}
	}
	return ids, values
}

func findQTP(spec *quic.QUICSpec) *tls.QUICTransportParametersExtension {
	for _, ext := range spec.ClientHelloSpec.Extensions {
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			return qtp
		}
	}
	return nil
}

func patchTransportParameters(spec *quic.QUICSpec, real *capture) {
	qtp := findQTP(spec)
	if qtp == nil {
		note("parrot has no QUIC transport parameters extension; skipped transport parameters")
		return
	}
	ids, values := realTransportParameters(real)
	var kept tls.TransportParameters
	have := map[uint64]bool{}
	for _, tp := range qtp.TransportParameters {
		id := tp.ID()
		if quic.IsGREASEQTPID(id) || id == tpGoogleInitialRTT {
			kept = append(kept, tp)
			continue
		}
		if vi, ok := tp.(*tls.VersionInformation); ok {
			switch {
			case id == tpVersionInformationLegacy && ids[tpVersionInformation] && !ids[tpVersionInformationLegacy]:
				vi.LegacyID = false
				note("version_information: send the RFC 9368 ID 0x11 instead of the draft ID 0xff73db (`LegacyID: false`)")
				id = tpVersionInformation
			case id == tpVersionInformation && ids[tpVersionInformationLegacy] && !ids[tpVersionInformation]:
				vi.LegacyID = true
				note("version_information: send the draft ID 0xff73db instead of 0x11 (`LegacyID: true`)")
				id = tpVersionInformationLegacy
			}
		}
		if !ids[id] {
			note("drop transport parameter 0x%x", id)
			continue
		}
		if v, ok := values[id]; ok {
			if cur, ok := uintValue(tp); ok && cur != v {
				note("transport parameter %s (0x%x): %d -> %d", tpNames[id], id, cur, v)
				tp = newTypedParameter(id, v)
			}
		}
		kept = append(kept, tp)
		have[id] = true
	}
	var missing []uint64
	for id := range ids {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	slices.Sort(missing)
	for _, id := range missing {
		tp, how := newParameter(id, values)
		kept = append(kept, tp)
		note("add transport parameter 0x%x (%s)", id, how)
	}
	qtp.TransportParameters = kept
}

func uintValue(tp tls.TransportParameter) (uint64, bool) {
	switch v := tp.(type) {
	case tls.MaxIdleTimeout:
		return uint64(v), true
	case tls.MaxUDPPayloadSize:
		return uint64(v), true
	case tls.InitialMaxData:
		return uint64(v), true
	case tls.InitialMaxStreamDataBidiLocal:
		return uint64(v), true
	case tls.InitialMaxStreamDataBidiRemote:
		return uint64(v), true
	case tls.InitialMaxStreamDataUni:
		return uint64(v), true
	case tls.InitialMaxStreamsBidi:
		return uint64(v), true
	case tls.InitialMaxStreamsUni:
		return uint64(v), true
	case tls.MaxAckDelay:
		return uint64(v), true
	case tls.ActiveConnectionIDLimit:
		return uint64(v), true
	case tls.MaxDatagramFrameSize:
		return uint64(v), true
	}
	return 0, false
}

func newTypedParameter(id, v uint64) tls.TransportParameter {
	switch id {
	case 0x01:
		return tls.MaxIdleTimeout(v)
	case 0x03:
		return tls.MaxUDPPayloadSize(v)
	case 0x04:
		return tls.InitialMaxData(v)
	case 0x05:
		return tls.InitialMaxStreamDataBidiLocal(v)
	case 0x06:
		return tls.InitialMaxStreamDataBidiRemote(v)
	case 0x07:
		return tls.InitialMaxStreamDataUni(v)
	case 0x08:
		return tls.InitialMaxStreamsBidi(v)
	case 0x09:
		return tls.InitialMaxStreamsUni(v)
	case 0x0b:
		return tls.MaxAckDelay(v)
	case 0x0e:
		return tls.ActiveConnectionIDLimit(v)
	case 0x20:
		return tls.MaxDatagramFrameSize(v)
	}
	return nil
}

func newParameter(id uint64, values map[uint64]uint64) (tls.TransportParameter, string) {
	if v, ok := values[id]; ok {
		if tp := newTypedParameter(id, v); tp != nil {
			return tp, fmt.Sprintf("value %d", v)
		}
	}
	switch id {
	case 0x0c:
		return &tls.DisableActiveMigration{}, "disable_active_migration"
	case 0x0f:
		return tls.InitialSourceConnectionID([]byte{}), "initial_source_connection_id"
	case tpVersionInformation, tpVersionInformationLegacy:
		return &tls.VersionInformation{
			ChoosenVersion:    tls.VERSION_1,
			AvailableVersions: []uint32{tls.VERSION_1},
			LegacyID:          id == tpVersionInformationLegacy,
		}, "version_information; available versions not exposed by the capture, assumed [v1]"
	case 0x2ab2:
		return &tls.GREASEQUICBit{}, "grease_quic_bit"
	}
	return &tls.FakeQUICTransportParameter{Id: id}, "value not exposed by the capture, sent empty"
}

func patchClientHello(spec *quic.QUICSpec, real *capture) {
	ch := real.ClientInitials.ClientHello
	for _, ext := range spec.ClientHelloSpec.Extensions {
		switch e := ext.(type) {
		case *tls.SupportedCurvesExtension:
			want := curves(ch.SupportedGroups)
			if len(want) > 0 && !slices.Equal(e.Curves, want) {
				note("supported_groups: %v -> %v", e.Curves, want)
				e.Curves = want
			}
		case *tls.KeyShareExtension:
			want := curves(ch.KeyShare)
			var cur []tls.CurveID
			for _, ks := range e.KeyShares {
				cur = append(cur, ks.Group)
			}
			if len(want) > 0 && !slices.Equal(cur, want) {
				var shares []tls.KeyShare
				for _, g := range want {
					i := slices.IndexFunc(e.KeyShares, func(ks tls.KeyShare) bool { return ks.Group == g })
					if i >= 0 {
						shares = append(shares, e.KeyShares[i])
					} else {
						shares = append(shares, tls.KeyShare{Group: g})
					}
				}
				note("key_share groups: %v -> %v", cur, want)
				e.KeyShares = shares
			}
		case *tls.SignatureAlgorithmsExtension:
			var want []tls.SignatureScheme
			for _, s := range ch.SignatureAlgorithms {
				want = append(want, tls.SignatureScheme(s))
			}
			if len(want) > 0 && !slices.Equal(e.SupportedSignatureAlgorithms, want) {
				note("signature_algorithms: %v -> %v", e.SupportedSignatureAlgorithms, want)
				e.SupportedSignatureAlgorithms = want
			}
		case *tls.ALPNExtension:
			if len(ch.ALPN) > 0 && !slices.Equal(e.AlpnProtocols, ch.ALPN) {
				note("ALPN: %v -> %v", e.AlpnProtocols, ch.ALPN)
				e.AlpnProtocols = ch.ALPN
			}
		case *tls.SupportedVersionsExtension:
			if len(ch.SupportedVersions) > 0 && !slices.Equal(e.Versions, ch.SupportedVersions) {
				note("supported_versions: %v -> %v", e.Versions, ch.SupportedVersions)
				e.Versions = ch.SupportedVersions
			}
		case *tls.PSKKeyExchangeModesExtension:
			if len(ch.PSKModes) > 0 && !slices.Equal(e.Modes, ch.PSKModes) {
				note("psk_key_exchange_modes: %v -> %v", e.Modes, ch.PSKModes)
				e.Modes = ch.PSKModes
			}
		case *tls.UtlsCompressCertExtension:
			var want []tls.CertCompressionAlgo
			for _, a := range ch.CompressCertificate {
				want = append(want, tls.CertCompressionAlgo(a))
			}
			if len(want) > 0 && !slices.Equal(e.Algorithms, want) {
				note("compress_certificate: %v -> %v", e.Algorithms, want)
				e.Algorithms = want
			}
		}
	}
}

func curves(ids []uint16) []tls.CurveID {
	out := make([]tls.CurveID, 0, len(ids))
	for _, id := range ids {
		out = append(out, tls.CurveID(id))
	}
	return out
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-quic-spec: "+format+"\n", args...)
	os.Exit(1)
}
