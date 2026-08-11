#!/bin/bash
# GoodbyeDPI-mac'i başlatır ve isteğe bağlı sistem proxy'sini açar.
# Kullanım:
#   ./start.sh              # sadece proxy sunucusu
#   ./start.sh --system     # + sistem proxy aç
#   ./start.sh --aggressive # agresif fragment mode
#   ./start.sh --system --aggressive

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT=8080
MODE=sni
SYSTEM=0
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system|-s) SYSTEM=1; shift ;;
    --aggressive|-a) MODE=aggressive; shift ;;
    --fixed) MODE=fixed; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --verbose|-v) EXTRA+=(-v); shift ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done

cleanup() {
  if [[ "$SYSTEM" -eq 1 ]]; then
    echo ""
    echo "Sistem proxy kapatılıyor..."
    bash "$ROOT/scripts/disable-proxy.sh" || true
  fi
}
trap cleanup EXIT INT TERM

if [[ "$SYSTEM" -eq 1 ]]; then
  bash "$ROOT/scripts/enable-proxy.sh" "$PORT"
fi

echo "GoodbyeDPI-mac başlıyor (mode=$MODE port=$PORT)..."
exec python3 "$ROOT/goodbyedpi.py" --port "$PORT" --mode "$MODE" "${EXTRA[@]}"
