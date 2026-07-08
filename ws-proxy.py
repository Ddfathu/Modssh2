#!/usr/bin/env python3
"""
WebSocket/HTTP Proxy (Dual Mode: WebSocket + Raw HTTP Proxy).

Mode otomatis:
- Jika request adalah WebSocket upgrade -> handshake 101 + frame parser + filter sampah
- Jika request HTTP biasa (GET/CONNECT/BMOVE) -> respon 200 OK + raw pipe ke SSH

Fitur tetap: Turbo, Buffer Monster, Signal Armor, Heartbeat (hanya untuk WS mode)
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
#  FUNGSI BACA & KIRIM FRAME WEBSOCKET (RFC 6455)
# =====================================================================

async def read_frame(reader: asyncio.StreamReader):
    header = await reader.readexactly(2)
    byte1, byte2 = header[0], header[1]

    fin = (byte1 & 0x80) != 0
    opcode = byte1 & 0x0F
    masked = (byte2 & 0x80) != 0
    payload_len = byte2 & 0x7F

    if payload_len == 126:
        ext = await reader.readexactly(2)
        payload_len = struct.unpack('>H', ext)[0]
    elif payload_len == 127:
        ext = await reader.readexactly(8)
        payload_len = struct.unpack('>Q', ext)[0]

    mask_key = b''
    if masked:
        mask_key = await reader.readexactly(4)

    payload = await reader.readexactly(payload_len)

    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return fin, opcode, payload


async def read_message(reader: asyncio.StreamReader):
    fin, opcode, payload = await read_frame(reader)

    if opcode in (0x8, 0x9, 0xA):
        return opcode, payload

    if fin:
        return opcode, payload

    fragments = [payload]
    while not fin:
        fin, next_opcode, next_payload = await read_frame(reader)
        if next_opcode != 0x0:
            log.warning("Ditemukan opcode %X saat menunggu continuation", next_opcode)
            break
        fragments.append(next_payload)
        if fin:
            break

    full_payload = b''.join(fragments)
    return opcode, full_payload


async def send_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes, fin: bool = True):
    header = bytearray()
    if fin:
        header.append(0x80 | opcode)
    else:
        header.append(opcode)

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
#  FUNGSI PIPE MENTAH (untuk mode HTTP proxy)
# =====================================================================

async def pipe_raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        log.debug("pipe_raw error: %s", e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


# =====================================================================
#  HANDLER UTAMA
# =====================================================================

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    log.info("Koneksi masuk dari %s", peer)

    try:
        # Baca header HTTP
        raw_headers = await reader.read(8192)
        if not raw_headers:
            writer.close()
            return

        # Parse header
        headers = {}
        header_part = raw_headers.split(b"\r\n\r\n", 1)[0]
        lines = header_part.decode(errors="ignore").split("\r\n")
        request_line = lines[0] if lines else ""
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Cek apakah ini WebSocket upgrade
        is_ws = (
            headers.get("upgrade", "").lower() == "websocket"
            and "sec-websocket-key" in headers
        )

        # Hubungkan ke SSH backend
        try:
            target_reader, target_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT
            )
        except Exception as e:
            log.error("Gagal konek ke SSH: %s", e)
            if is_ws:
                await send_frame(writer, 0x8, b"SSH backend unavailable")
            else:
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                await writer.drain()
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

        if is_ws:
            log.info("Mode WebSocket terdeteksi")
            # Lakukan handshake WebSocket
            ws_key = headers.get("sec-websocket-key")
            if not ws_key:
                for line in lines:
                    if "sec-websocket-key" in line.lower():
                        ws_key = line.split(":", 1)[1].strip()
                        break
            if not ws_key:
                ws_key = base64.b64encode(secrets.token_bytes(16)).decode()

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

            # Jalankan mode WebSocket dengan filter sampah
            await handle_websocket_mode(reader, writer, target_reader, target_writer)

        else:
            log.info("Mode HTTP proxy biasa terdeteksi")
            # Kirim respons 200 OK
            # Untuk CONNECT, biasanya 200 Connection Established
            if request_line.startswith("CONNECT"):
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await writer.drain()

            # Jalankan pipe mentah antara client dan SSH
            await asyncio.gather(
                pipe_raw(reader, target_writer),
                pipe_raw(target_reader, writer),
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
#  MODE WEBSOCKET (dengan filter sampah)
# =====================================================================

async def handle_websocket_mode(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_reader: asyncio.StreamReader,
    target_writer: asyncio.StreamWriter,
):
    # Heartbeat ping setiap 5 detik
    async def heartbeat():
        while True:
            await asyncio.sleep(5)
            try:
                await send_frame(writer, 0x9, b"")
            except Exception:
                break

    # Client -> SSH dengan filter sampah
    async def client_to_ssh():
        buffer = b""
        found = False
        max_buffer = 65536

        try:
            while True:
                opcode, payload = await read_message(reader)

                if opcode == 0x8:  # Close
                    log.info("Client mengirim Close frame")
                    await send_frame(writer, 0x8, payload)
                    break
                elif opcode == 0x9:  # Ping
                    await send_frame(writer, 0xA, payload)
                    continue
                elif opcode == 0xA:  # Pong
                    continue
                elif opcode not in (0x1, 0x2):
                    log.warning("Opcode tidak dikenal: 0x%X", opcode)
                    continue

                if not found:
                    buffer += payload
                    idx = buffer.find(b"SSH-")
                    if idx != -1:
                        clean = buffer[idx:]
                        target_writer.write(clean)
                        await target_writer.drain()
                        found = True
                        buffer = b""
                        log.info("SSH- ditemukan, mulai streaming")
                    else:
                        if len(buffer) > max_buffer:
                            log.warning("Buffer sampah melebihi batas, direset")
                            buffer = b""
                else:
                    target_writer.write(payload)
                    await target_writer.drain()

        except (ConnectionResetError, asyncio.IncompleteReadError):
            log.debug("Client putus koneksi di WS mode")
        except Exception as e:
            log.error("Error di client->ssh WS: %s", e)
        finally:
            try:
                target_writer.close()
            except Exception:
                pass
            try:
                await send_frame(writer, 0x8, b"")
            except Exception:
                pass

    # SSH -> Client
    async def ssh_to_client():
        try:
            while True:
                data = await target_reader.read(65536)
                if not data:
                    break
                await send_frame(writer, 0x2, data)
        except Exception as e:
            log.debug("Error di ssh->client WS: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    await asyncio.gather(
        client_to_ssh(),
        ssh_to_client(),
        heartbeat(),
        return_exceptions=True
    )


# =====================================================================
#  MAIN
# =====================================================================

async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT, limit=32768)
    log.info("==========================================================================")
    log.info("WS/HTTP PROXY DUAL MODE AKTIF di %s:%s -> SSH %s:%s",
             LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT)
    log.info("Mode: WebSocket upgrade atau HTTP proxy biasa")
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