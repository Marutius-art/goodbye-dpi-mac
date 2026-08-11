#!/bin/bash
# Cift tikla → Terminal acilir, Discord proxy baslar.
# Bitince Terminal'de Ctrl+C

cd "$HOME/goodbye-dpi-mac" || {
  echo "Klasor bulunamadi: ~/goodbye-dpi-mac"
  read -r -p "Kapatmak icin Enter..."
  exit 1
}

clear
echo ""
echo "  Discord (GoodbyeDPI) baslatiliyor..."
echo "  Kapatmak icin: Ctrl+C"
echo ""

exec ./scripts/discord.sh
