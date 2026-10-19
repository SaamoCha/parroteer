// Package quiccapture records the QUIC Initial flight a uquic QUICSpec sends,
// without a server, and parses it with clienthellod.
package quiccapture

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gaukas/clienthellod"
	tls "github.com/refraction-networking/utls"

	quic "github.com/refraction-networking/uquic"
)

// Offline dials a local UDP socket with spec and returns the clienthellod
// fingerprint of the Initial packets it receives. No handshake is completed.
func Offline(spec *quic.QUICSpec, sni string, wait time.Duration) (*clienthellod.QUICFingerprint, error) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer sink.Close()

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	go func() {
		pc, err := net.ListenUDP("udp", nil)
		if err != nil {
			return
		}
		defer pc.Close()
		ut := &quic.UTransport{Transport: &quic.Transport{Conn: pc}, QUICSpec: spec}
		_, _ = ut.DialEarly(ctx, sink.LocalAddr(), &tls.Config{ServerName: sni, NextProtos: []string{"h3"}}, &quic.Config{})
	}()

	gci := clienthellod.GatherClientInitialsWithDeadline(time.Now().Add(wait))
	buf := make([]byte, 65535)
	for !gci.Completed() {
		_ = sink.SetReadDeadline(time.Now().Add(wait))
		n, _, err := sink.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("no complete Initial flight: %w", err)
		}
		ci, err := clienthellod.UnmarshalQUICClientInitialPacket(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue // not a client Initial packet
		}
		if err := gci.AddPacket(ci); err != nil {
			return nil, fmt.Errorf("gather Initial packets: %w", err)
		}
	}
	return &clienthellod.QUICFingerprint{ClientInitials: gci}, nil
}
