#!/bin/bash
# QUIC/HTTP3 (UDP 443) tarayıcının proxy'yi atlamasına yol açar → kararsızlık.
# Bu script UDP/443'ü engeller; tarayıcı zorunlu olarak TCP+proxy kullanır.
# Kullanım: sudo ./scripts/block-quic.sh   enable|disable|status

set -euo pipefail
ACTION="${1:-enable}"
ANCHOR="goodbyedpi.quic"
RULES_FILE="/tmp/goodbyedpi-quic.pf"

case "$ACTION" in
  enable)
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "Root gerekli. Çalıştır:  sudo $0 enable"
      exit 1
    fi
    cat > "$RULES_FILE" <<'EOF'
# GoodbyeDPI-mac: block QUIC so browsers use TCP proxy
block drop out quick proto udp from any to any port 443
EOF
    pfctl -a "$ANCHOR" -f "$RULES_FILE" 2>/dev/null || true
    # anchor'ı ana kurallara ekle (varsa yükle)
    if ! pfctl -sr 2>/dev/null | grep -q "anchor \"$ANCHOR\""; then
      # geçici: sadece anchor yükle + pf enable
      pfctl -e 2>/dev/null || true
    fi
    # macOS'ta user anchor için:
    pfctl -a "$ANCHOR" -f "$RULES_FILE"
    pfctl -e 2>/dev/null || true
    echo "✓ QUIC (UDP 443) engellendi — tarayıcı proxy üzerinden gidecek"
    ;;
  disable)
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "Root gerekli. Çalıştır:  sudo $0 disable"
      exit 1
    fi
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
    rm -f "$RULES_FILE"
    echo "✓ QUIC engeli kaldırıldı"
    ;;
  status)
    echo "Anchor $ANCHOR:"
    pfctl -a "$ANCHOR" -sr 2>/dev/null || echo "(boş / yok)"
    ;;
  *)
    echo "Kullanım: sudo $0 enable|disable|status"
    exit 1
    ;;
esac
