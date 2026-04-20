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

echo "=== Installing Firefox Stable ==="
if ! command -v firefox &>/dev/null; then
  sudo apt-get install -y -qq firefox
fi
firefox --version

echo "=== All browsers installed ==="
