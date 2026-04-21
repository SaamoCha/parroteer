#!/usr/bin/env bash
# Setup clienthellod reflector on Oracle Always Free (Ubuntu)
# Run as root or with sudo
set -euo pipefail

echo "=== 1. Install Go ==="
if ! command -v go &>/dev/null; then
    wget -q https://go.dev/dl/go1.26.2.linux-arm64.tar.gz -O /tmp/go.tar.gz
    # Use amd64 if not arm: https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    export PATH=$PATH:/usr/local/go/bin
fi
go version

echo "=== 2. Build Caddy with clienthellod ==="
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
$(go env GOPATH)/bin/xcaddy build \
    --with github.com/gaukas/clienthellod/modcaddy@master \
    --output /usr/bin/caddy

echo "=== 3. Open firewall ports ==="
# Oracle Linux / Ubuntu iptables
# Note: also open ports in Oracle Cloud Console → VCN → Security List
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p udp --dport 443 -j ACCEPT
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

echo "=== 4. Setup Caddyfile ==="
mkdir -p /etc/caddy
cp Caddyfile /etc/caddy/Caddyfile

echo "=== 5. Create systemd service ==="
cat > /etc/systemd/system/caddy-reflector.service << 'UNIT'
[Unit]
Description=Parroteer TLS/QUIC Reflector (Caddy + clienthellod)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable caddy-reflector
systemctl start caddy-reflector

echo "=== Done ==="
echo "Check status: systemctl status caddy-reflector"
echo "Check logs:   journalctl -u caddy-reflector -f"
echo ""
echo "Don't forget:"
echo "  1. Open ports 80, 443 TCP, 443 UDP in Oracle Cloud Console"
echo "     → Networking → VCN → Security List → Add Ingress Rules"
echo "  2. Point reflect.matseoi.com A record to this VM's public IP"
echo "  3. Caddy will auto-obtain Let's Encrypt cert via HTTP-01"
