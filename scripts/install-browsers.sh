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
curl -sL "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US" \
  -o /tmp/firefox.tar.bz2
sudo rm -rf /opt/firefox-stable
sudo tar -xjf /tmp/firefox.tar.bz2 -C /opt/
sudo mv /opt/firefox /opt/firefox-stable
sudo ln -sf /opt/firefox-stable/firefox /usr/bin/firefox
rm /tmp/firefox.tar.bz2
firefox --version

echo "=== All browsers installed ==="
