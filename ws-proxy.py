#!/usr/bin/env python3
"""
WebSocket <-> SSH proxy (Signal Armor Premium Fixed Version).

Menerima koneksi HTTP dari Dark Tunnel/HTTP Custom. Kode ini menggunakan kasta 
tertinggi optimalisasi jaringan (TCP_NODELAY + Buffer 512KB) serta dituning 
dengan "Signal Armor" yang sudah diperbaiki secara presisi agar koneksi melekat 
kuat seperti perangko tanpa memicu eror 502 Bad Gateway.

[UPDATE 2026]: Dioptimalkan untuk lingkungan Docker/Serverless (Railway.app)
dengan suntikan Socket TCP Keepalive level dewa langsung di aplikasi.
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

logging.basicConfig(
    level=logging.INFO,
    format="[ws-proxy-armor] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ws-proxy-armor")


def parse_headers(raw: bytes) -> dict:
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

    try:
        raw_headers = await reader.read(8192)
        if not raw_headers:
            writer.close()
            return

        headers = parse_headers(raw_headers)
        raw_text_lower = raw_headers.decode(errors="ignore").lower()

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
            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()

        # Respon buta premium (Anti 301)
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
        await writer.drain()

        try:
            target_reader, target_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT
            )
        except Exception as e:
            log.error("Gagal konek ke target SSH -> %s", e)
            writer.close()
            return

        target_sock = target_writer.get_extra_info('socket')
        if target_sock is not None:
            target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # --- DROPBEAR MATCH FILTER ---
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
                        if b"SSH-" in buffer_data:
                            idx = buffer_data.find(b"SSH-")
                            clean_data = buffer_data[idx:]
                            dst.write(clean_data)
                            await dst.drain()
                            first_packet = False
                            buffer_data = b""
                        else:
                            if len(buffer_data) > 65536: 
                                buffer_data = b""
                            continue
                    else:
                        dst.write(data)
                        await dst.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        # --- HIGH-SPEED BLIND PIPE ---
        async def pipe_ssh_to_client(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe_client_to_ssh(reader, target_writer),
            pipe_ssh_to_client(target_reader, writer),
        )

    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    def configure_socket(writer_spec):
        sock = writer_spec.get_extra_info('socket')
        if sock is not None:
            # Turbo speed (Nagle Off)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Monster Buffer (512 KB)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
            
            # 🔥 PERBAIKAN TUNING KERNEL (Anti-Disconnect Tanpa Bug 502):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                # Beri kelonggaran awal 30 detik saat sinyal hilang kontak
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                # Jeda antar pengiriman sinyal pancingan (10 detik)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                # KOREKSI: Menggunakan konstanta TCP_KEEPCNT asli Linux secara presisi
                # Jika sistem tidak mendeteksi atribut teksnya, otomatis fallback aman ke angka sistem (6)
                keepcnt_opt = getattr(socket, 'TCP_KEEPCNT', 6)
                sock.setsockopt(socket.IPPROTO_TCP, keepcnt_opt, 12)
            except Exception as e:
                log.debug("Gagal setting keepalive kernel: %s", e)

    async def client_connected_cb(reader, writer):
        configure_socket(writer)
        await handle_client(reader, writer)

    server = await asyncio.start_server(client_connected_cb, LISTEN_HOST, LISTEN_PORT, limit=32768)
    log.info("WS proxy jalan di %s:%s -> Dropbear Active (Fixed Signal Armor Enabled)", LISTEN_HOST, LISTEN_PORT)
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
