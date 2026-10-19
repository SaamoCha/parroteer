// uquic-capture records the QUIC Initial flight a uquic parrot sends and prints
// its QUIC fingerprint as JSON, in the same shape a clienthellod reflector
// returns for real browsers. The capture is offline: no server and no completed
// handshake are needed.
//
// Usage: go run ./cmd/uquic-capture [-parrot chrome|chrome-115|firefox] [-sni reflector.test]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	quic "github.com/refraction-networking/uquic"

	"github.com/parroteer/parroteer/internal/quiccapture"
)

var parrots = map[string]quic.QUICID{
	"chrome":     quic.QUICChrome_146,
	"chrome-115": quic.QUICChrome_115,
	"firefox":    quic.QUICFirefox_116,
}

func main() {
	parrot := flag.String("parrot", "chrome", "uquic parrot: chrome, chrome-115 or firefox")
	sni := flag.String("sni", "reflector.test", "server name to put in the ClientHello")
	wait := flag.Duration("wait", 3*time.Second, "how long to wait for the Initial flight")
	flag.Parse()

	id, ok := parrots[*parrot]
	if !ok {
		fail("unknown parrot %q (available: chrome, chrome-115, firefox)", *parrot)
	}
	spec, err := quic.QUICID2Spec(id)
	if err != nil {
		fail("QUICID2Spec: %v", err)
	}
	fp, err := quiccapture.Offline(&spec, *sni, *wait)
	if err != nil {
		fail("%s parrot: %v", *parrot, err)
	}
	fp.UserAgent = "uquic " + *parrot
	out, err := json.MarshalIndent(fp, "", " ")
	if err != nil {
		fail("marshal: %v", err)
	}
	fmt.Println(string(out))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "uquic-capture: "+format+"\n", args...)
	os.Exit(1)
}
