#!/usr/bin/env python3
"""
WebSocket <-> SSH Proxy (Enhanced Payload Filter + Full Frame Parser).

Fitur:
- Handshake WebSocket (RFC 6455)
- Parsing frame dengan fragmentasi
- Filter sampah awal: cari "SSH-" di akumulasi payload, buang semua sebelum
- Setelah ketemu, langsung streaming
- Ping/Pong otomatis + heartbeat periodik
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
    """
    Membaca satu frame WebSocket dari reader.
    Return: (fin, opcode, payload)  # payload sudah di-unmask
    """
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
    """
    Membaca satu pesan WebSocket (gabungan fragmentasi).
    Return: (opcode, payload)  # opcode dari frame pertama (0x1/0x2) atau control
    """
    fin, opcode, payload = await read_frame(reader)

    # Control frame tidak boleh difragmentasi
    if opcode in (0x8, 0x9, 0xA):
        return opcode, payload

    if fin:
        return opcode, payload

    # Kumpulkan continuation frame
    fragments = [payload]
    while not fin:
        fin, next_opcode, next_payload = await read_frame(reader)
        if next_opcode != 0x0:  # Harus continuation
            log.warning("Ditemukan opcode %X saat menunggu continuation", next_opcode)
            break
        fragments.append(next_payload)
        if fin:
            break

    full_payload = b''.join(fragments)
    return opcode, full_payload


async def send_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes, fin: bool = True):
    """
    Kirim satu frame WebSocket (tanpa masking, server -> client).
    """
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
                    await send_frame(writer, 0x9, b"")
                except Exception:
                    break

        # 5. TASK: CLIENT -> SSH (dengan filter sampah "SSH-")
        async def client_to_ssh():
            buffer = b""          # akumulasi payload dari frame
            found = False         # apakah sudah ketemu "SSH-"
            max_buffer = 65536    # batas aman

            try:
                while True:
                    opcode, payload = await read_message(reader)

                    # Tangani frame kontrol
                    if opcode == 0x8:  # Close
                        log.info("Client mengirim Close frame")
                        await send_frame(writer, 0x8, payload)
                        break
                    elif opcode == 0x9:  # Ping -> Pong
                        await send_frame(writer, 0xA, payload)
                        continue
                    elif opcode == 0xA:  # Pong (abaikan)
                        continue
                    elif opcode not in (0x1, 0x2):  # Hanya text/binary
                        log.warning("Opcode tidak dikenal: 0x%X", opcode)
                        continue

                    # Payload dari frame data (text/binary)
                    if not found:
                        # Akumulasi sampai ketemu "SSH-"
                        buffer += payload
                        idx = buffer.find(b"SSH-")
                        if idx != -1:
                            # Potong semua sebelum "SSH-"
                            clean = buffer[idx:]
                            target_writer.write(clean)
                            await target_writer.drain()
                            found = True
                            buffer = b""  # kosongkan buffer
                            log.info("SSH- ditemukan, mulai streaming")
                        else:
                            # Jika buffer terlalu besar dan belum ketemu, reset (anggap sampah)
                            if len(buffer) > max_buffer:
                                log.warning("Buffer sampah melebihi batas, direset")
                                buffer = b""
                                # Opsi: tetap lanjutkan tanpa found? Kita bisa anggap found=True agar tidak terus menumpuk
                                # Tapi lebih aman kita set found=True dan kirim buffer terakhir?
                                # Di sini kita reset dan tetap mencari di data berikutnya
                    else:
                        # Sudah found, langsung kirim
                        target_writer.write(payload)
                        await target_writer.drain()

            except (ConnectionResetError, asyncio.IncompleteReadError):
                log.debug("Client putus koneksi")
            except Exception as e:
                log.error("Error di client->ssh: %s", e)
            finally:
                try:
                    target_writer.close()
                except Exception:
                    pass
                try:
                    await send_frame(writer, 0x8, b"")
                except Exception:
                    pass

        # 6. TASK: SSH -> CLIENT (kirim sebagai binary frame)
        async def ssh_to_client():
            try:
                while True:
                    data = await target_reader.read(65536)
                    if not data:
                        break
                    await send_frame(writer, 0x2, data)
            except Exception as e:
                log.debug("Error di ssh->client: %s", e)
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        # Jalankan ketiga task paralel
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
    log.info("WS PROXY ENHANCED (FILTER + FRAME PARSER) AKTIF di %s:%s -> SSH %s:%s",
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