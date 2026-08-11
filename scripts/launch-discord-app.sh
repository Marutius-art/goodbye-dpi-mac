#!/bin/bash
# Discord masaüstü uygulamasını proxy ile açar.
# Önce ./scripts/discord.sh çalışıyor olmalı (proxy ayakta).
#
#   ./scripts/launch-discord-app.sh
#   ./scripts/launch-discord-app.sh 8080

set -eo pipefail

PORT="${1:-8080}"
PROXY="http://127.0.0.1:${PORT}"

DISCORD=""
for c in \
  "/Applications/Discord.app/Contents/MacOS/Discord" \
  "$HOME/Applications/Discord.app/Contents/MacOS/Discord"
do
  if [ -x "$c" ]; then
    DISCORD="$c"
    break
  fi
done

if [ -z "$DISCORD" ]; then
  echo "X Discord.app bulunamadi. Once App Store / discord.com dan yukle."
  exit 1
fi

# Proxy ayakta mi?
if ! lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "X Proxy ($PORT) calismiyor."
  echo "  Once su komutu calistir ve ACIK birak:"
  echo "    cd ~/goodbye-dpi-mac && ./scripts/discord.sh"
  exit 1
fi

echo "-> Discord kapatiliyor (proxy'siz acilmissa)..."
osascript -e 'quit app "Discord"' 2>/dev/null || true
killall Discord 2>/dev/null || true
# helper processler
sleep 1.5
# zorla
pkill -x Discord 2>/dev/null || true
sleep 0.5

echo "-> Discord proxy ile aciliyor ($PROXY)..."
# Electron/Chromium bayraklari:
#  --proxy-server     tum HTTP/HTTPS/WS
#  --disable-quic     UDP ile proxy atlamasin
#  --host-resolver-rules  DNS'i mümkün oldugunca proxy/CONNECT uzerinden
export http_proxy="$PROXY"
export https_proxy="$PROXY"
export HTTP_PROXY="$PROXY"
export HTTPS_PROXY="$PROXY"
export ALL_PROXY="$PROXY"

nohup "$DISCORD" \
  --proxy-server="$PROXY" \
  --proxy-bypass-list="<-loopback>" \
  --disable-quic \
  --disable-features=WebRtcHideLocalIpsWithMdns \
  >/tmp/goodbyedpi-discord.log 2>&1 &

sleep 2
if pgrep -x Discord >/dev/null 2>&1; then
  echo "OK  Discord app acildi (proxy: $PROXY)"
  echo "    Hala baglanamazsa Discord'u tamamen kapatip bu scripti tekrar calistir."
  echo "    Log: /tmp/goodbyedpi-discord.log"
else
  echo "X Discord baslamadi. Log:"
  cat /tmp/goodbyedpi-discord.log 2>/dev/null || true
  exit 1
fi
