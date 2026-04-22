#!/usr/bin/env bash
# Install real browser binaries for parroteer fingerprint capture.
# Designed for Ubuntu (GitHub Actions ubuntu-latest or a VPS).
set -euo pipefail

echo "=== Installing Chrome Stable ==="
if ! command -v google-chrome-stable &>/dev/null; then
  wget -q -O - https://dl.google.com/linux/linux_signing_key.pub \
    | sudo gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
    | sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq google-chrome-stable
fi
google-chrome-stable --version

echo "=== Installing Edge Stable ==="
if ! command -v microsoft-edge-stable &>/dev/null; then
  wget -q -O - https://packages.microsoft.com/keys/microsoft.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-edge.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-edge.gpg] https://packages.microsoft.com/repos/edge stable main" \
    | sudo tee /etc/apt/sources.list.d/microsoft-edge.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq microsoft-edge-stable
fi
microsoft-edge-stable --version

echo "=== Installing Firefox Stable (direct from Mozilla) ==="
# Download latest stable directly from Mozilla — faster than waiting for apt
# Mozilla now ships .tar.xz (was .tar.bz2), use --compressed and auto-detect
curl -sL "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US" \
  -o /tmp/firefox.tar
sudo rm -rf /opt/firefox-stable
sudo tar -xf /tmp/firefox.tar -C /opt/
sudo mv /opt/firefox /opt/firefox-stable
sudo ln -sf /opt/firefox-stable/firefox /usr/bin/firefox
# Install runtime deps Firefox needs
sudo apt-get install -y -qq libdbus-glib-1-2 libgtk-3-0 libasound2t64 2>/dev/null || true
rm /tmp/firefox.tar
firefox --version

echo "=== All browsers installed ==="
