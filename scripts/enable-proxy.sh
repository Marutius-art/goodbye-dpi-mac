#!/bin/bash
# macOS sistem HTTP/HTTPS proxy'sini GoodbyeDPI-mac'e yönlendirir.
# Kullanım: ./enable-proxy.sh [port] [servis-adı]
# Örnek:    ./enable-proxy.sh 8080
#           ./enable-proxy.sh 8080 "Wi-Fi"

set -euo pipefail

PORT="${1:-8080}"
SERVICE="${2:-}"
HOST="127.0.0.1"

# Aktif ağ servisini bul (Wi-Fi, Ethernet, ...)
detect_service() {
  if [[ -n "$SERVICE" ]]; then
    echo "$SERVICE"
    return
  fi
  # Önce Wi-Fi dene
  if networksetup -getinfo "Wi-Fi" &>/dev/null; then
    # Wi-Fi bağlı mı?
    if networksetup -getairportnetwork en0 2>/dev/null | grep -qv "not associated"; then
      echo "Wi-Fi"
      return
    fi
  fi
  # networksetup listesinden ilk "enabled" hardware port
  local svc
  while IFS= read -r line; do
    if [[ "$line" =~ ^\(Hardware\ Port:\ (.+),\ Device:\ (.+)\)$ ]]; then
      svc="${BASH_REMATCH[1]}"
      # ignore Bluetooth, Thunderbolt Bridge etc. if possible
      case "$svc" in
        Wi-Fi|Ethernet|"USB 10/100"*|"USB 10/100/1000"*) echo "$svc"; return ;;
      esac
    fi
  done < <(networksetup -listallhardwareports)
  # fallback
  echo "Wi-Fi"
}

SVC="$(detect_service)"

echo "→ Servis: $SVC"
echo "→ Proxy:  $HOST:$PORT"

networksetup -setwebproxy "$SVC" "$HOST" "$PORT" off
networksetup -setsecurewebproxy "$SVC" "$HOST" "$PORT" off
networksetup -setwebproxystate "$SVC" on
networksetup -setsecurewebproxystate "$SVC" on

# SOCKS kullanmıyoruz; kapalı kalsın
networksetup -setsocksfirewallproxystate "$SVC" off 2>/dev/null || true

echo ""
echo "✓ Sistem HTTP/HTTPS proxy açıldı: $HOST:$PORT ($SVC)"
echo "  goodbyedpi.py çalışıyor olmalı."
echo "  Kapatmak: ./scripts/disable-proxy.sh"
echo ""
echo "Test:"
echo "  curl -x http://127.0.0.1:$PORT -I https://example.com"
