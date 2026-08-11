#!/bin/bash
# Discord — tüm tarayıcı / sekmeler
#   cd ~/goodbye-dpi-mac && ./scripts/discord.sh
# Durdur: Ctrl+C

set -eo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT=8080
MODE=tls
VERBOSE=0
QUIC_ON=0
PROXY_ON=0
PROXY_PID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --block-quic|--no-browser|--no-app|--system|-s|-a|--aggressive) shift ;;
    *) shift ;;
  esac
done

cleanup() {
  echo ""
  echo "-> Kapaniyor..."
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    for p in $(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null); do
      kill "$p" 2>/dev/null || true
    done
  fi
  if [ "$PROXY_ON" -eq 1 ]; then
    bash "$ROOT/scripts/disable-proxy.sh" 2>/dev/null || true
  fi
  if [ "$QUIC_ON" -eq 1 ]; then
    sudo bash "$ROOT/scripts/block-quic.sh" disable 2>/dev/null || true
  fi
  echo "OK Kapandi. Tekrar: cd ~/goodbye-dpi-mac && ./scripts/discord.sh"
}
trap cleanup EXIT INT TERM

echo ""
echo "  ========================================"
echo "   GoodbyeDPI  ·  Discord  v1.2.1"
echo "  ========================================"
echo ""

# ÖNEMLİ: NO_PROXY='*' KOYMA!
# curl NO_PROXY=* görünce -x proxy'yi de yok sayar → zehirli DNS'e gider → HTTP 000
unset NO_PROXY no_proxy
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy

# Eski surec
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "-> Eski proxy kapatiliyor..."
  for p in $(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null); do
    kill "$p" 2>/dev/null || true
  done
  sleep 0.5
fi

# 1) Proxy motoru (DoH zaten kendi kodunda proxy kullanmiyor)
: > /tmp/goodbyedpi.log
if [ "$VERBOSE" -eq 1 ]; then
  python3 "$ROOT/goodbyedpi.py" --port "$PORT" --mode "$MODE" -v >>/tmp/goodbyedpi.log 2>&1 &
else
  python3 "$ROOT/goodbyedpi.py" --port "$PORT" --mode "$MODE" >>/tmp/goodbyedpi.log 2>&1 &
fi
PROXY_PID=$!
echo "-> Proxy basladi (pid $PROXY_PID)"

echo -n "-> Port dinleniyor"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo " OK"
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo ""
    echo "X Proxy dustu:"
    cat /tmp/goodbyedpi.log
    exit 1
  fi
  echo -n "."
  sleep 0.2
done

# 2) Health check — proxy ZORUNLU (-x), NO_PROXY yok
echo "-> discord.com test ediliyor..."
READY=0
i=0
while [ "$i" -lt 8 ]; do
  i=$((i + 1))
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "X Proxy dustu. Log:"
    cat /tmp/goodbyedpi.log
    exit 1
  fi
  echo -n "   deneme $i/8 ... "
  # --proxy ile acikca; env proxy yok
  ERRF="/tmp/goodbyedpi-curl-err.txt"
  CODE=$(curl -sS --proxy "http://127.0.0.1:${PORT}" \
    --connect-timeout 5 --max-time 12 \
    -o /dev/null -w "%{http_code}" \
    https://discord.com 2>"$ERRF") || true
  CODE=$(printf '%s' "$CODE" | tr -cd '0-9')
  [ -z "$CODE" ] && CODE="000"
  # sadece son 3 hane (http kodu)
  CODE=$(printf '%s' "$CODE" | awk '{print substr($0,length($0)-2)}')
  echo "HTTP $CODE"
  case "$CODE" in
    200|301|302|303|307|308)
      READY=1
      echo "OK  Proxy uzerinden Discord calisiyor!"
      break
      ;;
  esac
  if [ "$i" -eq 1 ] && [ -s "$ERRF" ]; then
    echo "   (curl: $(head -1 "$ERRF"))"
  fi
  sleep 0.4
done

if [ "$READY" -ne 1 ]; then
  echo "X Test basarisiz. curl hata:"
  cat /tmp/goodbyedpi-curl-err.txt 2>/dev/null || true
  echo "Proxy log:"
  tail -40 /tmp/goodbyedpi.log || true
  exit 1
fi

# 3) DNS + QUIC + sistem proxy
echo "-> DNS cache (sifre sorabilir)..."
sudo dscacheutil -flushcache 2>/dev/null || true
sudo killall -HUP mDNSResponder 2>/dev/null || true

echo "-> QUIC engeli (sifre sorabilir)..."
if sudo bash "$ROOT/scripts/block-quic.sh" enable; then
  QUIC_ON=1
else
  echo "!! QUIC engellenemedi — devam"
fi

bash "$ROOT/scripts/enable-proxy.sh" "$PORT"
PROXY_ON=1

# Discord app — mutlaka proxy bayraklariyla (Launchpad'den acma!)
if [ -x "/Applications/Discord.app/Contents/MacOS/Discord" ] || \
   [ -x "$HOME/Applications/Discord.app/Contents/MacOS/Discord" ]; then
  bash "$ROOT/scripts/launch-discord-app.sh" "$PORT" || true
else
  echo "!! Discord.app yok — sadece site kullanilabilir"
fi

echo ""
echo "  ----------------------------------------"
echo "  HAZIR"
echo "    Site: Safari/Chrome -> https://discord.com"
echo "    App:  otomatik acildi. Dock/Launchpad'den ACMA."
echo "          Elle acmak gerekirse:"
echo "            ./scripts/launch-discord-app.sh"
echo "  Terminal ACIK kalsin. Bitince: Ctrl+C"
echo "  ----------------------------------------"
echo ""

wait "$PROXY_PID"
