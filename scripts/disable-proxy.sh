#!/bin/bash
# Sistem proxy ayarlarını kapatır.
# Kullanım: ./disable-proxy.sh [servis-adı]

set -euo pipefail

SERVICE="${1:-}"

detect_service() {
  if [[ -n "$SERVICE" ]]; then
    echo "$SERVICE"
    return
  fi
  if networksetup -getinfo "Wi-Fi" &>/dev/null; then
    echo "Wi-Fi"
    return
  fi
  echo "Wi-Fi"
}

SVC="$(detect_service)"

echo "→ Servis: $SVC — proxy kapatılıyor..."

networksetup -setwebproxystate "$SVC" off
networksetup -setsecurewebproxystate "$SVC" off
networksetup -setsocksfirewallproxystate "$SVC" off 2>/dev/null || true

echo "✓ Proxy kapatıldı ($SVC)"
echo "  İpucu: birden fazla arayüz varsa: ./disable-proxy.sh Ethernet"
