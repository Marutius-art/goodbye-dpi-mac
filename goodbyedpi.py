#!/usr/bin/env python3
"""
GoodbyeDPI-mac — DPI (Deep Packet Inspection) bypass for macOS
================================================================
VPN kullanmadan SNI/DPI engellerini aşmak için yerel HTTP proxy.
TLS ClientHello paketlerini parçalayarak (fragmentation) ISP DPI'sını
yanıltır. DNS engellerine karşı DNS-over-HTTPS kullanır.

Kullanım:
  python3 goodbyedpi.py
  python3 goodbyedpi.py --port 8080 --mode aggressive
  ./scripts/enable-proxy.sh   # sistem proxy'sini aç
  ./scripts/disable-proxy.sh  # kapat
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import random
import select
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

__version__ = "1.2.0"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_DOH = "https://1.1.1.1/dns-query"
BUFFER = 65536
LOG = logging.getLogger("goodbyedpi")

# DoH sunucularına IP ile git — hostname DNS'e ihtiyaç duymasın (bootstrap)
# (ip, tls_sni, http_host)
DOH_BOOTSTRAP = (
    ("1.1.1.1", "cloudflare-dns.com", "cloudflare-dns.com"),
    ("1.0.0.1", "cloudflare-dns.com", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google", "dns.google"),
    ("8.8.4.4", "dns.google", "dns.google"),
    ("9.9.9.9", "dns.quad9.net", "dns.quad9.net"),
)

# Discord / CF — DoH tamamen kırılırsa son çare (Cloudflare anycast)
STATIC_HOSTS = {
    "discord.com": ["162.159.128.233", "162.159.135.232", "162.159.136.232", "162.159.138.232"],
    "www.discord.com": ["162.159.128.233", "162.159.135.232", "162.159.136.232"],
    "discordapp.com": ["162.159.128.233", "162.159.135.232", "162.159.136.232"],
    "gateway.discord.gg": ["162.159.134.234", "162.159.135.234", "162.159.136.234"],
    "cdn.discordapp.com": ["162.159.129.233", "162.159.130.233", "162.159.135.233"],
    "media.discordapp.net": ["162.159.128.233", "162.159.135.232"],
    "images-ext-1.discordapp.net": ["162.159.128.233", "162.159.135.232"],
    "images-ext-2.discordapp.net": ["162.159.128.233", "162.159.135.232"],
    "status.discord.com": ["162.159.128.233", "162.159.135.232"],
    "updates.discord.com": ["162.159.135.232", "162.159.136.232"],
    "discord.gg": ["162.159.134.234", "162.159.135.234"],
    "discordapp.net": ["162.159.128.233", "162.159.135.232", "162.159.136.232"],
    "stable.dl2.discordapp.net": ["162.159.128.233", "162.159.135.232", "162.159.136.232"],
    "dl2.discordapp.net": ["162.159.128.233", "162.159.135.232"],
    "latency.discord.media": ["162.159.128.233", "162.159.135.232"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
    "dns.google": ["8.8.8.8", "8.8.4.4"],
}

# TR operatör engel sayfası / DNS zehirlemesi — asla bağlanma
POISON_PREFIXES_V4 = (
    "195.175.254.",
    "195.175.255.",
    "0.0.0.",
    "127.0.0.",
)
POISON_PREFIXES_V6 = (
    "2a01:358:",
)


def is_poison_ip(ip: str) -> bool:
    if not ip:
        return True
    low = ip.lower()
    if ":" in low:
        return any(low.startswith(p) for p in POISON_PREFIXES_V6)
    return any(low.startswith(p) for p in POISON_PREFIXES_V4)


# ---------------------------------------------------------------------------
# DNS over HTTPS — proxy BYPASS + IP bootstrap (kısır döngü yok)
# ---------------------------------------------------------------------------

class DoHResolver:
    """
    DoH resolver that never uses the system/HTTP proxy and never needs
    recursive DNS to find the DoH server (connects by IP with correct SNI).
    """

    def __init__(self, url: str = DEFAULT_DOH, timeout: float = 5.0, ipv4_only: bool = True):
        self.timeout = timeout
        self.ipv4_only = ipv4_only
        self._cache: dict = {}
        self._lock = threading.Lock()
        self._ctx = ssl.create_default_context()
        # urllib asla sistem proxy'sine gitmesin
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def resolve(self, hostname: str) -> Optional[str]:
        ips = self.resolve_all(hostname)
        return ips[0] if ips else None

    def resolve_all(self, hostname: str) -> List[str]:
        hostname = hostname.strip(".").lower()
        if not hostname:
            return []

        try:
            socket.inet_pton(socket.AF_INET, hostname)
            return [] if is_poison_ip(hostname) else [hostname]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            if self.ipv4_only or is_poison_ip(hostname):
                return []
            return [hostname]
        except OSError:
            pass

        with self._lock:
            cached = self._cache.get(hostname)
            if cached and cached[1] > time.time() and cached[0]:
                return list(cached[0])

        ips = self._query_bootstrap(hostname, qtype=1)
        ips = [ip for ip in ips if not is_poison_ip(ip)]

        if not ips:
            # statik yedek (Discord)
            for key, vals in STATIC_HOSTS.items():
                if hostname == key or hostname.endswith("." + key):
                    ips = list(vals)
                    break
            # parent domain
            if not ips:
                parts = hostname.split(".")
                for i in range(len(parts) - 1):
                    parent = ".".join(parts[i:])
                    if parent in STATIC_HOSTS:
                        ips = list(STATIC_HOSTS[parent])
                        break

        if ips:
            with self._lock:
                self._cache[hostname] = (ips, time.time() + 120)
        return ips

    def invalidate(self, hostname: str) -> None:
        with self._lock:
            self._cache.pop(hostname.strip(".").lower(), None)

    def _query_bootstrap(self, name: str, qtype: int) -> List[str]:
        packet = self._build_query(name, qtype)
        b64 = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
        path = f"/dns-query?dns={b64}"

        for ip, sni, host_hdr in DOH_BOOTSTRAP:
            try:
                body = self._http_get_direct(ip, sni, host_hdr, path)
                if body:
                    ips = self._parse_answers(body, qtype)
                    if ips:
                        return ips
            except Exception as exc:
                LOG.debug("DoH bootstrap %s failed: %s", ip, exc)
        return []

    def _http_get_direct(self, ip: str, sni: str, host_hdr: str, path: str) -> Optional[bytes]:
        """TLS+HTTP GET straight to IP — no DNS, no proxy."""
        raw = socket.create_connection((ip, 443), self.timeout)
        try:
            raw.settimeout(self.timeout)
            ssock = self._ctx.wrap_socket(raw, server_hostname=sni)
            try:
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_hdr}\r\n"
                    f"Accept: application/dns-message\r\n"
                    f"User-Agent: GoodbyeDPI-mac/{__version__}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                ssock.sendall(req.encode("ascii"))
                data = b""
                while True:
                    chunk = ssock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            finally:
                try:
                    ssock.close()
                except OSError:
                    pass
        finally:
            try:
                raw.close()
            except OSError:
                pass

        if b"\r\n\r\n" not in data:
            return None
        header_blob, body = data.split(b"\r\n\r\n", 1)
        status_line = header_blob.split(b"\r\n", 1)[0]
        if b" 200" not in status_line:
            return None
        headers = header_blob.lower()
        if b"transfer-encoding: chunked" in headers:
            body = self._dechunk(body)
        return body

    @staticmethod
    def _dechunk(data: bytes) -> bytes:
        out = b""
        rest = data
        try:
            while rest:
                if b"\r\n" not in rest:
                    break
                line, rest = rest.split(b"\r\n", 1)
                n = int(line.split(b";")[0].strip() or b"0", 16)
                if n == 0:
                    break
                out += rest[:n]
                rest = rest[n + 2 :]  # skip chunk + CRLF
        except Exception:
            return data
        return out

    @staticmethod
    def _build_query(name: str, qtype: int) -> bytes:
        tid = random.randint(0, 0xFFFF)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            raw = label.encode("idna")
            qname += bytes([len(raw)]) + raw
        qname += b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return header + question

    @staticmethod
    def _parse_answers(data: bytes, qtype: int) -> List[str]:
        if len(data) < 12:
            return []
        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if (flags & 0x000F) != 0 or ancount == 0:
            return []
        offset = 12
        out: List[str] = []

        def skip_name(buf: bytes, off: int) -> int:
            while off < len(buf):
                length = buf[off]
                if length == 0:
                    return off + 1
                if length & 0xC0 == 0xC0:
                    return off + 2
                off += 1 + length
            return off

        for _ in range(qdcount):
            offset = skip_name(data, offset)
            offset += 4

        for _ in range(ancount):
            offset = skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            if rtype == qtype == 1 and rdlength == 4:
                out.append(socket.inet_ntop(socket.AF_INET, rdata))
            if rtype == qtype == 28 and rdlength == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return out


# ---------------------------------------------------------------------------
# TLS / packet helpers
# ---------------------------------------------------------------------------

def extract_sni(data: bytes) -> Optional[str]:
    """Extract SNI hostname from a TLS ClientHello record (best-effort)."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        # TLS record: type(1) version(2) length(2)
        rec_len = struct.unpack("!H", data[3:5])[0]
        hs = data[5 : 5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
            return None
        # handshake header: type(1) length(3)
        body = hs[4:]
        if len(body) < 34:
            return None
        # client_version(2) random(32)
        session_id_len = body[34]
        pos = 35 + session_id_len
        if pos + 2 > len(body):
            return None
        cipher_len = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(body):
            return None
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(body):
            etype, elen = struct.unpack("!HH", body[pos : pos + 4])
            pos += 4
            if etype == 0x0000 and pos + elen <= len(body):  # server_name
                # list length(2) name_type(1) name_len(2) name
                if elen < 5:
                    return None
                name_len = struct.unpack("!H", body[pos + 3 : pos + 5])[0]
                name = body[pos + 5 : pos + 5 + name_len]
                return name.decode("ascii", errors="ignore")
            pos += elen
    except Exception:
        return None
    return None


def _is_tls_record(data: bytes) -> bool:
    return len(data) >= 5 and data[0] in (0x14, 0x15, 0x16, 0x17)


def tls_record_fragments(data: bytes, mode: str = "tls", pieces: int = 2) -> List[bytes]:
    """
    Split a TLS record into multiple TLS records (record-layer fragmentation).

    Critical for modern DPI (e.g. Turkish ISP Discord blocks): they reassemble TCP
    segments, so plain TCP splits fail. Splitting the ClientHello across multiple
    TLS records still fools them while remaining valid for the server.

    modes:
      tls / sni  — first record tiny (2–10 B of handshake), rest in second record
      aggressive — 1 + 1 + rest (three records)
      chunks     — N equal-sized record payload pieces
      fixed      — first record = 1 byte of handshake payload
    """
    if not _is_tls_record(data):
        # non-TLS: fall back to simple TCP split
        if len(data) < 4:
            return [data]
        return [data[:2], data[2:]]

    # May contain more than one record; only fragment the first, append the rest raw
    rec_len = struct.unpack("!H", data[3:5])[0]
    first_rec_end = 5 + rec_len
    if first_rec_end > len(data):
        first_rec_end = len(data)
    first = data[:first_rec_end]
    leftover = data[first_rec_end:]

    content_type = first[0:1]
    version = first[1:3]
    payload = first[5:]
    if len(payload) < 2:
        return [data]

    mode = mode.lower()
    if mode in ("sni", "tls", "default"):
        # Proven working against Discord DPI: first ~1–10 bytes of handshake alone
        cut = min(2, len(payload) - 1)
        sizes = [cut, len(payload) - cut]
    elif mode == "fixed":
        sizes = [1, len(payload) - 1]
    elif mode == "aggressive":
        if len(payload) >= 3:
            sizes = [1, 1, len(payload) - 2]
        else:
            sizes = [1, len(payload) - 1]
    elif mode == "chunks":
        n = max(2, pieces)
        size = max(1, len(payload) // n)
        sizes = []
        pos = 0
        while pos < len(payload):
            sizes.append(min(size, len(payload) - pos))
            pos += size
    else:
        cut = min(2, len(payload) - 1)
        sizes = [cut, len(payload) - cut]

    # Optionally cut through middle of SNI for sni mode secondary split
    if mode == "sni":
        sni = extract_sni(data)
        if sni:
            needle = sni.encode("ascii")
            idx = payload.find(needle)
            if idx != -1 and len(needle) >= 2:
                mid = idx + len(needle) // 2
                sizes = [mid, len(payload) - mid]

    out: List[bytes] = []
    pos = 0
    for sz in sizes:
        if sz <= 0 or pos >= len(payload):
            continue
        chunk = payload[pos : pos + sz]
        pos += sz
        out.append(content_type + version + struct.pack("!H", len(chunk)) + chunk)
    if pos < len(payload):
        chunk = payload[pos:]
        out.append(content_type + version + struct.pack("!H", len(chunk)) + chunk)

    if leftover:
        out.append(leftover)
    return out or [data]


def fragment_payload(data: bytes, mode: str = "tls", pieces: int = 2) -> List[bytes]:
    """Public fragment API — prefers TLS record fragmentation."""
    return tls_record_fragments(data, mode=mode, pieces=pieces)


def send_fragmented(sock: socket.socket, data: bytes, mode: str, pieces: int, delay_ms: float) -> None:
    """Write data as TLS-record fragments with TCP_NODELAY."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

    chunks = fragment_payload(data, mode=mode, pieces=pieces)
    LOG.debug("fragment %d bytes -> %s", len(data), [len(c) for c in chunks])
    for i, chunk in enumerate(chunks):
        sock.sendall(chunk)
        if delay_ms > 0 and i < len(chunks) - 1:
            time.sleep(delay_ms / 1000.0)
        elif delay_ms == 0 and i < len(chunks) - 1:
            # tiny yield helps some middleboxes; still fast
            time.sleep(0.001)


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------

class ProxyServer:
    def __init__(
        self,
        host: str,
        port: int,
        mode: str = "sni",
        pieces: int = 2,
        delay_ms: float = 0,
        doh_url: str = DEFAULT_DOH,
        use_doh: bool = True,
        fake_ttl: bool = False,
        only_domains: Optional[List[str]] = None,
        workers: int = 64,
    ):
        self.host = host
        self.port = port
        self.mode = mode
        self.pieces = pieces
        self.delay_ms = delay_ms
        self.use_doh = use_doh
        self.fake_ttl = fake_ttl
        self.only_domains = [d.lower().lstrip(".") for d in (only_domains or [])]
        self.resolver = DoHResolver(doh_url, ipv4_only=True) if use_doh else None
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self.stats = {"connections": 0, "fragmented": 0, "errors": 0, "retries": 0}

    def _domain_match(self, host: str) -> bool:
        if not self.only_domains:
            return True
        h = host.lower().rstrip(".")
        for d in self.only_domains:
            if h == d or h.endswith("." + d):
                return True
        return False

    def _resolve_all(self, host: str) -> List[str]:
        if self.resolver:
            ips = self.resolver.resolve_all(host)
            if ips:
                return ips
            LOG.warning("DoH boş: %s — sistem DNS kullanılmayacak (zehir riski)", host)
            return []
        # DoH kapalıysa sistem DNS; zehirli IP'leri ele
        out: List[str] = []
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                ip = sockaddr[0]
                if not is_poison_ip(ip):
                    # IPv4 tercih
                    if fam == socket.AF_INET:
                        out.insert(0, ip)
                    else:
                        out.append(ip)
        except OSError:
            pass
        # unique preserve order
        seen = set()
        uniq = []
        for ip in out:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        return uniq

    def _connect_remote(self, host: str, port: int, timeout: float = 4.0) -> socket.socket:
        ips = self._resolve_all(host)
        if not ips:
            raise OSError(f"no safe DNS records for {host}")

        # En fazla 3 IP dene; her biri kısa timeout — donma olmasın
        last_err: Optional[Exception] = None
        for i, ip in enumerate(ips[:3]):
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            remote = socket.socket(family, socket.SOCK_STREAM)
            remote.settimeout(timeout)
            try:
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
            try:
                remote.connect((ip, port))
                if i > 0:
                    self.stats["retries"] += 1
                    LOG.info("bağlandı %s -> %s (deneme %d)", host, ip, i + 1)
                return remote
            except OSError as exc:
                last_err = exc
                LOG.debug("connect fail %s(%s): %s", host, ip, exc)
                try:
                    remote.close()
                except OSError:
                    pass

        raise OSError(f"connect failed {host}:{port} via {ips[:3]}: {last_err}")

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # macOS: allow quick rebind
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self._sock.bind((self.host, self.port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)
        LOG.info("GoodbyeDPI-mac v%s listening on %s:%d", __version__, self.host, self.port)
        LOG.info("mode=%s pieces=%d delay_ms=%s doh=%s", self.mode, self.pieces, self.delay_ms, self.use_doh)
        print(f"  ▶  Proxy:  http://{self.host}:{self.port}  mode={self.mode}", flush=True)

        # DNS ısıtmayı ARKA PLANDA yap — ana thread accept etsin (donma olmasın)
        if self.resolver:
            def _warm():
                for warm in ("discord.com", "gateway.discord.gg", "cdn.discordapp.com"):
                    try:
                        ips = self.resolver.resolve_all(warm)
                        LOG.info("DNS warm %s -> %s", warm, ips[:3] if ips else [])
                    except Exception as exc:
                        LOG.debug("warm %s: %s", warm, exc)

            threading.Thread(target=_warm, name="dns-warm", daemon=True).start()

        try:
            while not self._stop.is_set():
                try:
                    client, addr = self._sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.stats["connections"] += 1
                self.pool.submit(self._handle_client, client, addr)
        except KeyboardInterrupt:
            print("\nDurduruluyor...")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self.pool.shutdown(wait=False, cancel_futures=True)
        LOG.info(
            "stats: connections=%d fragmented=%d errors=%d",
            self.stats["connections"],
            self.stats["fragmented"],
            self.stats["errors"],
        )

    def _handle_client(self, client: socket.socket, addr) -> None:
        remote: Optional[socket.socket] = None
        try:
            client.settimeout(30.0)
            req = self._recv_http_headers(client)
            if not req:
                return
            first = req.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            parts = first.split()
            if len(parts) < 2:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return

            method, target = parts[0].upper(), parts[1]

            if method == "CONNECT":
                host, port = self._parse_hostport(target, 443)
                self._handle_connect(client, host, port)
            elif method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                self._handle_http(client, req, method, target)
            else:
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
        except Exception as exc:
            self.stats["errors"] += 1
            LOG.debug("client error %s: %s", addr, exc)
        finally:
            try:
                client.close()
            except OSError:
                pass
            if remote:
                try:
                    remote.close()
                except OSError:
                    pass

    def _handle_connect(self, client: socket.socket, host: str, port: int) -> None:
        try:
            remote = self._connect_remote(host, port)
        except Exception as exc:
            LOG.warning("CONNECT %s:%d failed: %s", host, port, exc)
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
            self.stats["errors"] += 1
            return

        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            try:
                remote.close()
            except OSError:
                pass
            return

        client.settimeout(60.0)
        remote.settimeout(60.0)

        should_frag = self._domain_match(host) and port in (443, 8443)

        try:
            if should_frag:
                hello = self._recv_tls_client_hello(client)
                if hello:
                    sni = extract_sni(hello) or host
                    LOG.info("HTTPS  %s  (SNI=%s)  frag=%s", host, sni, self.mode)
                    send_fragmented(remote, hello, self.mode, self.pieces, self.delay_ms)
                    self.stats["fragmented"] += 1

            self._pipe(client, remote)
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                remote.close()
            except OSError:
                pass

    @staticmethod
    def _pipe(client: socket.socket, remote: socket.socket) -> None:
        try:
            client.settimeout(60.0)
            remote.settimeout(60.0)
        except OSError:
            pass
        try:
            while True:
                r, _, _ = select.select([client, remote], [], [], 180.0)
                if not r:
                    break
                if client in r:
                    data = client.recv(BUFFER)
                    if not data:
                        break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(BUFFER)
                    if not data:
                        break
                    client.sendall(data)
        except (OSError, ConnectionError):
            pass

    @staticmethod
    def _recv_tls_client_hello(sock: socket.socket, timeout: float = 4.0) -> bytes:
        """Read at least one full TLS record (ClientHello) from the client."""
        sock.settimeout(0.5)
        data = b""
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                try:
                    chunk = sock.recv(BUFFER)
                except socket.timeout:
                    if data:
                        break
                    continue
                if not chunk:
                    break
                data += chunk
                if len(data) >= 5 and data[0] == 0x16:
                    rec_len = struct.unpack("!H", data[3:5])[0]
                    if len(data) >= 5 + rec_len:
                        break
                elif len(data) >= 5 and data[0] != 0x16:
                    break
        finally:
            sock.settimeout(60.0)
        return data

    def _handle_http(self, client: socket.socket, req: bytes, method: str, target: str) -> None:
        # absolute-form URL: GET http://host/path HTTP/1.1
        host = None
        port = 80
        path = target
        if target.startswith("http://"):
            rest = target[7:]
            slash = rest.find("/")
            if slash == -1:
                authority, path = rest, "/"
            else:
                authority, path = rest[:slash], rest[slash:]
            host, port = self._parse_hostport(authority, 80)
        else:
            # Host header
            for line in req.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    authority = line.split(b":", 1)[1].strip().decode("latin-1")
                    host, port = self._parse_hostport(authority, 80)
                    break
        if not host:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        # rebuild request as origin-form
        lines = req.split(b"\r\n")
        lines[0] = f"{method} {path} HTTP/1.1".encode("latin-1")
        # drop Proxy-Connection
        lines = [ln for ln in lines if not ln.lower().startswith(b"proxy-connection:")]
        new_req = b"\r\n".join(lines)
        if not new_req.endswith(b"\r\n\r\n"):
            # keep body if present
            pass

        try:
            remote = self._connect_remote(host, port)
        except Exception as exc:
            LOG.warning("HTTP %s:%d failed: %s", host, port, exc)
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            self.stats["errors"] += 1
            return

        LOG.info("HTTP   %s %s", method, host)
        try:
            if self._domain_match(host):
                send_fragmented(remote, new_req, "fixed", 2, self.delay_ms)
                self.stats["fragmented"] += 1
            else:
                remote.sendall(new_req)

            while True:
                r, _, _ = select.select([client, remote], [], [], 60.0)
                if not r:
                    break
                if client in r:
                    data = client.recv(BUFFER)
                    if not data:
                        break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(BUFFER)
                    if not data:
                        break
                    client.sendall(data)
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                remote.close()
            except OSError:
                pass

    @staticmethod
    def _recv_http_headers(sock: socket.socket, max_size: int = 65536) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < max_size:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _parse_hostport(authority: str, default_port: int) -> Tuple[str, int]:
        authority = authority.strip()
        if authority.startswith("["):
            # [ipv6]:port
            end = authority.find("]")
            host = authority[1:end]
            rest = authority[end + 1 :]
            if rest.startswith(":"):
                return host, int(rest[1:])
            return host, default_port
        if authority.count(":") == 1:
            h, p = authority.rsplit(":", 1)
            if p.isdigit():
                return h, int(p)
        return authority, default_port


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="goodbyedpi",
        description="macOS için GoodbyeDPI tarzı DPI bypass (yerel HTTP proxy)",
    )
    p.add_argument("-H", "--host", default=DEFAULT_HOST, help="Dinleme adresi (varsayılan 127.0.0.1)")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Dinleme portu (varsayılan 8080)")
    p.add_argument(
        "-m",
        "--mode",
        choices=["tls", "sni", "fixed", "chunks", "aggressive"],
        default="tls",
        help="TLS record fragment: tls (önerilen/Discord) | sni | fixed | chunks | aggressive",
    )
    p.add_argument("--pieces", type=int, default=2, help="chunks modunda parça sayısı")
    p.add_argument(
        "--delay",
        type=float,
        default=0,
        metavar="MS",
        help="Parçalar arası gecikme (ms). Bazı DPI'lar için 1-10 dene",
    )
    p.add_argument("--doh", default=DEFAULT_DOH, help="DNS-over-HTTPS endpoint")
    p.add_argument("--no-doh", action="store_true", help="DoH kapat, sistem DNS kullan")
    p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Sadece bu domain(ler) için fragment (tekrarlanabilir)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug log")
    p.add_argument("--version", action="version", version=f"GoodbyeDPI-mac {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-5s  %(message)s",
        datefmt="%H:%M:%S",
    )

    print(
        r"""
   ____                 _ _            ____  ____ ___                
  / ___| ___   ___   __| | |__  _   _  |  _ \|  _ \_ _|  _ __ ___   __ _  ___
 | |  _ / _ \ / _ \ / _` | '_ \| | | | | | | | |_) | |  | '_ ` _ \ / _` |/ __|
 | |_| | (_) | (_) | (_| | |_) | |_| | | |_| |  __/| |  | | | | | | (_| | (__
  \____|\___/ \___/ \__,_|_.__/ \__, | |____/|_|  |___| |_| |_| |_|\__,_|\___|
                                |___/   macOS edition  v{ver}
""".format(
            ver=__version__
        )
    )

    server = ProxyServer(
        host=args.host,
        port=args.port,
        mode=args.mode,
        pieces=args.pieces,
        delay_ms=args.delay,
        doh_url=args.doh,
        use_doh=not args.no_doh,
        only_domains=args.only,
    )
    try:
        server.start()
    except OSError as exc:
        LOG.error("Port açılamadı (%s:%d): %s", args.host, args.port, exc)
        LOG.error("Başka bir program portu kullanıyor olabilir.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
