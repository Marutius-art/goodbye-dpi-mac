# GoodbyeDPI-mac

macOS için [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) tarzı **DPI bypass** aracı.

Yerel HTTP/HTTPS proxy çalıştırır; TLS **ClientHello** paketini (SNI) parçalayarak ISP Deep Packet Inspection engelini aşmaya çalışır. **VPN değildir** — trafik uzak sunucuya tünellenmez.

> Sansür / site engeli aşmak içindir. Kullanım kendi sorumluluğunuzdadır.

---

## Özellikler

| Teknik | Açıklama |
|--------|----------|
| **TLS record fragmentation** | ClientHello’yu birden fazla TLS kaydına böler (TCP split yetmeyen DPI’lara karşı) |
| **DNS-over-HTTPS** | DNS zehirlemesine karşı; IP bootstrap (proxy kısır döngüsü yok) |
| **Sistem proxy** | Safari / Chrome tüm sekmeler |
| **Discord app** | Electron proxy bayraklarıyla güvenli başlatma |
| **QUIC engeli** | HTTP/3’ün proxy’yi atlamasını engeller (opsiyonel `pf`) |
| **Tek tık** | `Discord Ac.command` |

Bağımlılık yok: **Python 3** (macOS’ta genelde yüklü).

---

## Hızlı başlangıç (Discord)

```bash
git clone https://github.com/Marutius-art/goodbye-dpi-mac.git
cd goodbye-dpi-mac
chmod +x scripts/*.sh "Discord Ac.command" goodbyedpi.py
./scripts/discord.sh
```

veya masaüstüne kopyaladığın **`Discord Ac.command`** dosyasına çift tıkla.

- Terminal **açık kalsın**
- Discord app’i Dock/Launchpad’den değil, script ile açılsın
- Bitince: **Ctrl+C**

Sadece app’i (proxy zaten çalışırken) yeniden başlatmak:

```bash
./scripts/launch-discord-app.sh
```

---

## Genel proxy

```bash
python3 goodbyedpi.py --port 8080 --mode tls
./scripts/enable-proxy.sh 8080
# ...
./scripts/disable-proxy.sh
```

### Modlar

| Mod | Ne zaman |
|-----|----------|
| `tls` (varsayılan) | Çoğu DPI / Discord |
| `fixed` | Daha küçük ilk fragment |
| `aggressive` | Çok parçalı |
| `sni` | SNI ortasından kes |

```bash
python3 goodbyedpi.py --mode aggressive
python3 goodbyedpi.py --delay 5
```

---

## Dosyalar

```
goodbye-dpi-mac/
├── goodbyedpi.py              # proxy motoru
├── Discord Ac.command         # çift tıkla başlat
├── scripts/
│   ├── discord.sh             # Discord için tam kurulum
│   ├── launch-discord-app.sh  # app’i proxy ile aç
│   ├── enable-proxy.sh
│   ├── disable-proxy.sh
│   ├── block-quic.sh
│   └── start.sh
└── README.md
```

---

## Çalışma mantığı (özet)

1. ISP Discord’u **DNS zehirleyerek** ve/veya **SNI DPI** ile engeller.
2. Bu araç DoH ile gerçek IP’leri bulur, bağlantıyı yerel proxy üzerinden kurar.
3. İlk TLS ClientHello’yu **TLS record** seviyesinde böler → DPI hostname’i okuyamaz, sunucu birleştirir.
4. Sistem HTTP(S) proxy + QUIC engeli ile tarayıcı ve Discord app aynı yolu kullanır.

IP tamamen null-route ise (paket hiç gitmiyorsa) fragment yetmez → VPN gerekir.

---

## Benzer araçlar

- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) (Windows)
- [SpoofDPI](https://github.com/xvzc/SpoofDPI)
- [zapret](https://github.com/bol-van/zapret)
- [PowerTunnel](https://github.com/krlvm/PowerTunnel)

---

## Lisans

MIT
