#!/usr/bin/env bash
# Start a local clienthellod QUIC reflector on 127.0.0.1:443 for run-quic.ts.
#
# - builds Caddy with the clienthellod module (cached in $QUIC_REFLECTOR_DIR)
# - creates a private CA and a certificate for reflector.test
# - lets Firefox trust that CA through an enterprise policy (set FIREFOX_DIR)
# - sets the loopback MTU to 1500 so browsers split Initial packets the way
#   they would on a real network path
#
# Prints QUIC_REFLECTOR_SPKI (and appends it to $GITHUB_ENV when set).
set -euo pipefail

DIR=${QUIC_REFLECTOR_DIR:-$PWD/.quic-reflector}
CADDY_VERSION=v2.11.2
XCADDY_VERSION=v0.4.4
CLIENTHELLOD_VERSION=v0.5.0-alpha
SUDO=$([ "$(id -u)" = 0 ] && echo "" || echo sudo)
mkdir -p "$DIR"

if [ ! -x "$DIR/caddy" ]; then
  echo "=== Building Caddy $CADDY_VERSION with clienthellod $CLIENTHELLOD_VERSION ==="
  go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION"
  "$(go env GOPATH)/bin/xcaddy" build "$CADDY_VERSION" --output "$DIR/caddy" \
    --with "github.com/gaukas/clienthellod/modcaddy@$CLIENTHELLOD_VERSION"
fi

if [ ! -f "$DIR/cert.pem" ]; then
  echo "=== Creating a private CA and a certificate for reflector.test ==="
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 30 -nodes \
    -keyout "$DIR/ca.key" -out "$DIR/ca.pem" -subj "/CN=Parroteer Local Reflector CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$DIR/key.pem" -out "$DIR/leaf.csr" -subj /CN=reflector.test 2>/dev/null
  printf "subjectAltName=DNS:reflector.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > "$DIR/leaf.ext"
  openssl x509 -req -in "$DIR/leaf.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
    -days 30 -out "$DIR/cert.pem" -extfile "$DIR/leaf.ext" 2>/dev/null
fi
SPKI=$(openssl x509 -in "$DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64)

if [ -n "${FIREFOX_DIR:-}" ]; then
  $SUDO mkdir -p "$FIREFOX_DIR/distribution"
  printf '{"policies":{"Certificates":{"Install":["%s"]}}}\n' "$DIR/ca.pem" \
    | $SUDO tee "$FIREFOX_DIR/distribution/policies.json" >/dev/null
fi

$SUDO ip link set lo mtu 1500 || echo "warning: could not set the loopback MTU"

sed -e "s#@CERT@#$DIR/cert.pem#" -e "s#@KEY@#$DIR/key.pem#" -e "s#@LOG@#$DIR/caddy.log#" \
  "$(dirname "$0")/../reflector/local/Caddyfile" > "$DIR/Caddyfile"
$SUDO "$DIR/caddy" start --config "$DIR/Caddyfile" --adapter caddyfile --pidfile "$DIR/caddy.pid"

echo "QUIC_REFLECTOR_SPKI=$SPKI"
if [ -n "${GITHUB_ENV:-}" ]; then echo "QUIC_REFLECTOR_SPKI=$SPKI" >> "$GITHUB_ENV"; fi
