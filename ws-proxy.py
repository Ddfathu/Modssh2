#!/usr/bin/env python3
"""
WebSocket <-> SSH Proxy (Full Frame Parser Edition).

Mendukung:
- Handshake WebSocket (RFC 6455)
- Parsing & unmasking frame
- Binary/Text frame ke SSH, dan sebaliknya
- Ping/Pong otomatis (dengan heartbeat periodik)
- Close frame graceful
- TCP_NODELAY, buffer 512KB, keepalive 2,5 menit
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
import struct
import time

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("WS_PORT", "8880"))
TARGET_HOST = os.environ.get("WS_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("WS_TARGET_PORT", "22"))

logging.basicConfig(
    level=logging.INFO,
    format="[ws-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ws-proxy")


# =====================================================================
#  FUNGSI HANDLER FRAME WEBSOCKET (RFC 6455)
# =====================================================================

async def read_frame(reader: asyncio.StreamReader):
    """
    Membaca satu frame WebSocket dari reader.
    Return: (opcode, payload)  (payload sudah di-unmask jika perlu)
    Raise:  ConnectionResetError jika koneksi putus.
    """
    header = await reader.readexactly(2)
    byte1, byte2 = header[0], header[1]

    fin = (byte1 & 0x80) != 0
    opcode = byte1 & 0x0F
    masked = (byte2 & 0x80) != 0
    payload_len = byte2 & 0x7F

    # Baca extended length jika perlu
    if payload_len == 126:
        ext = await reader.readexactly(2)
        payload_len = struct.unpack('>H', ext)[0]
    elif payload_len == 127:
        ext = await reader.readexactly(8)
        payload_len = struct.unpack('>Q', ext)[0]

    # Baca masking key jika ada
    mask_key = b''
    if masked:
        mask_key = await reader.readexactly(4)

    # Baca payload
    payload = await reader.readexactly(payload_len)

    # Unmask jika perlu
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    # Untuk frame kontrol (Ping/Pong/Close), fin harus 1
    if opcode in (0x8, 0x9, 0xA) and not fin:
        raise ValueError("Control frame must have FIN=1")

    return opcode, payload


async def send_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes):
    """
    Mengirim satu frame WebSocket (tanpa masking, karena server -> client tidak wajib mask).
    """
    header = bytearray()
    header.append(0x80 | opcode)  # FIN=1

    length = len(payload)
    if length <= 125:
        header.append(length)
    elif length <= 65535:
        header.append(126)
        header.extend(struct.pack('>H', length))
    else:
        header.append(127)
        header.extend(struct.pack('>Q', length))

    writer.write(bytes(header) + payload)
    await writer.drain()


# =====================================================================
#  FUNGSI UTAMA PROXY
# =====================================================================

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    log.info("Koneksi masuk dari %s", peer)

    try:
        # 1. BACA HEADER HANDSHAKE
        raw_headers = await reader.read(8192)
        if not raw_headers:
            writer.close()
            return

        headers = {}
        header_part = raw_headers.split(b"\r\n\r\n", 1)[0]
        lines = header_part.decode(errors="ignore").split("\r\n")
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        ws_key = headers.get("sec-websocket-key")
        if not ws_key:
            # Coba ekstrak manual
            for line in lines:
                if "sec-websocket-key" in line.lower():
                    ws_key = line.split(":", 1)[1].strip()
                    break

        if not ws_key:
            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()

        # 2. BALAS HANDSHAKE 101
        accept_key = base64.b64encode(
            hashlib.sha1((ws_key + WS_MAGIC).encode()).digest()
        ).decode()
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n"
        )
        if "sec-websocket-protocol" in headers:
            resp += f"Sec-WebSocket-Protocol: {headers['sec-websocket-protocol']}\r\n"
        resp += "\r\n"
        writer.write(resp.encode())
        await writer.drain()

        # 3. HUBUNGKAN KE SSH BACKEND
        try:
            target_reader, target_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT
            )
        except Exception as e:
            log.error("Gagal konek ke SSH: %s", e)
            await send_frame(writer, 0x8, b"SSH backend unavailable")
            writer.close()
            return

        # Optimasi socket
        for w in (writer, target_writer):
            sock = w.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    keepcnt = getattr(socket, 'TCP_KEEPCNT', 6)
                    sock.setsockopt(socket.IPPROTO_TCP, keepcnt, 12)
                except Exception:
                    pass

        # 4. TASK HEARTBEAT (kirim Ping setiap 5 detik)
        async def heartbeat():
            while True:
                await asyncio.sleep(5)
                try:
                    await send_frame(writer, 0x9, b"")  # Ping
                except Exception:
                    break

        # 5. TASK: BACA FRAME DARI CLIENT -> TERUSKAN KE SSH
        async def client_to_ssh():
            try:
                while True:
                    opcode, payload = await read_frame(reader)
                    if opcode == 0x8:  # Close
                        log.info("Client mengirim Close frame")
                        # Kirim balik Close
                        await send_frame(writer, 0x8, payload)
                        break
                    elif opcode == 0x9:  # Ping -> balas Pong
                        await send_frame(writer, 0xA, payload)
                    elif opcode == 0xA:  # Pong (abaikan)
                        pass
                    elif opcode in (0x1, 0x2):  # Text atau Binary -> kirim ke SSH
                        target_writer.write(payload)
                        await target_writer.drain()
                    else:
                        log.warning("Opcode tidak dikenal: 0x%X", opcode)
            except (ConnectionResetError, asyncio.IncompleteReadError):
                log.debug("Client putus koneksi saat baca frame")
            except Exception as e:
                log.error("Error di client->ssh: %s", e)
            finally:
                # Tutup target SSH jika belum
                try:
                    target_writer.close()
                except Exception:
                    pass
                # Kirim Close ke client jika belum
                try:
                    await send_frame(writer, 0x8, b"")
                except Exception:
                    pass

        # 6. TASK: BACA DARI SSH -> KIRIM KE CLIENT (BINARY FRAME)
        async def ssh_to_client():
            try:
                while True:
                    data = await target_reader.read(65536)
                    if not data:
                        break
                    await send_frame(writer, 0x2, data)  # Binary frame
            except Exception as e:
                log.debug("Error di ssh->client: %s", e)
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        # Jalankan semua task paralel
        await asyncio.gather(
            client_to_ssh(),
            ssh_to_client(),
            heartbeat(),
            return_exceptions=True
        )

    except Exception as e:
        log.error("Error umum: %s", e)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        log.info("Sesi %s selesai", peer)


# =====================================================================
#  MAIN SERVER
# =====================================================================

async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT, limit=32768)
    log.info("==========================================================================")
    log.info("WS PROXY LENGKAP (FRAME PARSER) AKTIF di %s:%s -> SSH %s:%s",
             LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT)
    log.info("==========================================================================")
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