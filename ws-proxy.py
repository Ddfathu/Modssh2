#!/usr/bin/env python3
"""
WebSocket <-> SSH proxy (Enhanced Hybrid Server-Side Version).

Menerima koneksi HTTP/WebSocket di suatu port. Script ini dimodifikasi khusus
agar kebal terhadap payload super panjang, menyaring sisa teks manipulasi,
serta mengimplementasikan trik Server-Side Enhanced (Fragmentasi Respon + Delay)
agar aplikasi yang tidak memiliki fitur enhanced (seperti Dark Tunnel) bisa tetap
konek stabil tanpa terputus (anti-RST) setelah sukses autentikasi password.

[UPDATE 2026]: Dioptimalkan untuk lingkungan Docker/Serverless (Railway.app)
dengan suntikan Socket TCP Keepalive langsung di level aplikasi.
"""

import asyncio
import base64
import hashlib
import logging
import os
import signal
import sys
import secrets
import socket

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("WS_PORT", "8880"))
TARGET_HOST = os.environ.get("WS_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("WS_TARGET_PORT", "22"))
DEFAULT_RESPONSE = os.environ.get(
    "WS_RESPONSE",
    "HTTP/1.1 101 Switching Protocols\r\n\r\n",
)

logging.basicConfig(
    level=logging.INFO,
    format="[ws-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ws-proxy")


def parse_headers(raw: bytes) -> dict:
    """Fungsi pembaca header kecepatan tinggi (High-Speed Engine)."""
    headers = {}
    try:
        header_part = raw.split(b"\r\n\r\n", 1)[0]
        lines = header_part.decode(errors="ignore").split("\r\n")
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    except Exception as e:
        log.debug("Gagal parse header: %s", e)
    return headers


def make_accept_key(ws_key: str) -> str:
    sha1 = hashlib.sha1((ws_key + WS_MAGIC).encode()).digest()
    return base64.b64encode(sha1).decode()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    log.info("Koneksi masuk dari %s", peer)

    try:
        raw_headers = await reader.read(4096)
        if not raw_headers:
            writer.close()
            return

        headers = parse_headers(raw_headers)
        raw_text_lower = raw_headers.decode(errors="ignore").lower()

        is_ws_upgrade = "upgrade: websocket" in raw_text_lower or headers.get("upgrade", "").lower() == "websocket"

        if is_ws_upgrade:
            ws_key = headers.get("sec-websocket-key")
            if not ws_key and "sec-websocket-key:" in raw_text_lower:
                try:
                    for line in raw_headers.decode(errors="ignore").split("\r\n"):
                        if "sec-websocket-key" in line.lower():
                            ws_key = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

            if not ws_key:
                log.info("Client tidak mengirim Sec-WebSocket-Key. Membuat key otomatis...")
                ws_key = base64.b64encode(secrets.token_bytes(16)).decode()

            accept_key = make_accept_key(ws_key)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n"
            )
            if "sec-websocket-protocol" in headers:
                response += f"Sec-WebSocket-Protocol: {headers['sec-websocket-protocol']}\r\n"
            response += "\r\n"
            writer.write(response.encode())
        else:
            writer.write(DEFAULT_RESPONSE.encode())

        await writer.drain()

        try:
            target_reader, target_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT
            )
        except Exception as e:
            log.error("Gagal konek ke target %s:%s -> %s", TARGET_HOST, TARGET_PORT, e)
            writer.close()
            return

        # --- TUNING DROPBEAR FILTER: Kebal Fragmentasi & Enhanced Payload ---
        async def pipe_client_to_ssh(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            first_packet = True
            buffer_data = b""
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    
                    if first_packet:
                        buffer_data += data
                        # Cek apakah banner SSH sudah masuk ke dalam tumpukan payload kustom
                        if b"SSH-" in buffer_data:
                            idx = buffer_data.find(b"SSH-")
                            # Potong teks sampah (PATCH/GET/POST), ambil dari banner "SSH-" ke belakang
                            clean_data = buffer_data[idx:]
                            
                            dst.write(clean_data)
                            await dst.drain()
                            
                            first_packet = False  # Handshake aman, matikan filter
                            buffer_data = b""     # Bersihkan penampung buffer
                        else:
                            # Jika belum ada banner SSH, tamping terus datanya (menghindari packet splitting)
                            if len(buffer_data) > 32768: 
                                log.warning("Buffer penuh tanpa SSH banner. Membersihkan data sampah...")
                                buffer_data = b""
                            continue
                    else:
                        # Aliran data normal setelah jabat tangan berhasil
                        dst.write(data)
                        await dst.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            except Exception as e:
                log.debug("pipe_client error: %s", e)
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        # --- SERVER-SIDE ENHANCED: Mengecoh DPI Operator dari Sisi Server (Anti-Disconnect Dark Tunnel) ---
        async def pipe_ssh_to_client(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            first_packet = True
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    
                    # Jika ini respon/paket pertama dari SSH (Handshake/Banner)
                    if first_packet and b"SSH-" in data:
                        log.info("Mengaktifkan Server-Side Enhanced Trick untuk Dark Tunnel...")
                        
                        # Pecah paket SSH menjadi potongan kecil (per 3 bytes)
                        chunk_size = 3
                        for i in range(0, len(data), chunk_size):
                            chunk = data[i:i+chunk_size]
                            dst.write(chunk)
                            await dst.drain()
                            # Beri jeda super singkat (0.01 detik) agar DPI operator gagal membaca signature SSH
                            await asyncio.sleep(0.01)
                            
                        first_packet = False # Trik selesai, paket berikutnya dikirim normal speed
                    else:
                        # Jalur data setelah terkoneksi (normal speed)
                        dst.write(data)
                        await dst.drain()
                        
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            except Exception as e:
                log.debug("pipe_ssh error: %s", e)
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe_client_to_ssh(reader, target_writer),
            pipe_ssh_to_client(target_reader, writer),
        )

    except Exception as e:
        log.error("Error menangani klien %s: %s", peer, e)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        log.info("Koneksi %s ditutup", peer)


async def main():
    # Fungsi internal untuk menyuntikkan TCP Keepalive langsung ke Socket level Container
    def configure_socket(writer_spec):
        sock = writer_spec.get_extra_info('socket')
        if sock is not None:
            # Aktifkan instruksi Keepalive dasar
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Tuning agresif: Cek tiap 15 detik, ulangi per 5 detik jika loss, drop setelah 3x gagal
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except AttributeError:
                pass

    # Menggunakan callback dinamis untuk menangkap transport socket client sebelum diproses
    async def client_connected_cb(reader, writer):
        configure_socket(writer)
        await handle_client(reader, writer)

    # Mengunci 'limit=8192' agar buffer kebal total dari payload super panjang
    server = await asyncio.start_server(client_connected_cb, LISTEN_HOST, LISTEN_PORT, limit=8192)
    
    log.info(
        "WS proxy jalan di %s:%s -> Dropbear Backend Active (Server-Side Enhanced Injector Mode)",
        LISTEN_HOST, LISTEN_PORT,
    )
    async with server:
        await server.serve_forever()


def handle_sigterm(*_):
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sigterm)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
