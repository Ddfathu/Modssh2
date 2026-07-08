#!/usr/bin/env python3
"""
TCP Multiplexer Premium ala sslh (Continuous Fragmenter Edition).

Mendengarkan di SATU port publik dengan proteksi timeout, serta menerapkan
trik fragmentasi data balik (Server-to-Client Packet Splitting) secara berkala
untuk meniru ketahanan sistem SSH Premium komersial terhadap sensor operator.
"""

import asyncio
import logging
import os
import signal
import sys

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("MAIN_MUX_PORT", os.environ.get("PORT", "443")))

SSL_TARGET_HOST = os.environ.get("SSL_TARGET_HOST", "127.0.0.1")
SSL_TARGET_PORT = int(os.environ.get("SSL_TARGET_PORT", "2443"))

WS_TARGET_HOST = os.environ.get("WS_MUX_TARGET_HOST", "127.0.0.1")
WS_TARGET_PORT = int(os.environ.get("WS_MUX_TARGET_PORT", "8880"))

TLS_HANDSHAKE_BYTE = 0x16

logging.basicConfig(
    level=logging.INFO,
    format="[mux] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("mux")


# Jalur Upload: Dari HP ke SSH Server (Dialirkan normal tanpa hambatan)
async def pipe_upstream(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    try:
        while True:
            data = await src.read(16384)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        log.debug("pipe upstream error: %s", e)
    finally:
        try:
            dst.close()
        except Exception:
            pass


# 🔥 JALUR DOWNSTREAM PREMIUM: Dari SSH Server ke HP (Dipecah Agresif Biar Kebal)
async def pipe_downstream_premium(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    packet_count = 0
    try:
        while True:
            data = await src.read(32768)
            if not data:
                break
            
            # 100 paket pertama (fase kritis jabat tangan + autentikasi + ping awal) kita pecah total
            if packet_count < 100:
                packet_count += 1
                
                # Potong data menjadi serpihan kecil (per 4 bytes) untuk membingungkan DPI & mengunci HP
                chunk_size = 4
                for i in range(0, len(data), chunk_size):
                    chunk = data[i:i+chunk_size]
                    dst.write(chunk)
                    await dst.drain()
                    # Jeda mikro tanpa memicu timeout untuk memaksa TCP Window bergetar
                    await asyncio.sleep(0.001)
            else:
                # Lewat fase kritis, lepas data dengan kecepatan penuh
                dst.write(data)
                await dst.drain()
                
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        log.debug("pipe downstream error: %s", e)
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    first_byte = b""

    try:
        # Intip byte pertama dengan batas waktu 0.5 detik
        try:
            first_byte = await asyncio.wait_for(reader.read(1), timeout=0.5)
        except asyncio.TimeoutError:
            first_byte = b""

        if first_byte and first_byte[0] == TLS_HANDSHAKE_BYTE:
            target_host, target_port, label = SSL_TARGET_HOST, SSL_TARGET_PORT, "SSL/stunnel"
        else:
            target_host, target_port, label = WS_TARGET_HOST, WS_TARGET_PORT, "WS"

        log.info("Koneksi %s -> %s (%s:%s)", peer, label, target_host, target_port)

        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        except Exception as e:
            log.error("Gagal konek ke backend %s -> %s", label, e)
            writer.close()
            return

        if first_byte:
            target_writer.write(first_byte)
            await target_writer.drain()

        # Jalankan dua arah dengan filter downstream premium
        await asyncio.gather(
            pipe_upstream(reader, target_writer),
            pipe_downstream_premium(target_reader, writer),
        )

    except Exception as e:
        log.error("Error menangani klien %s: %s", peer, e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT, limit=16384)
    log.info(
        "Mux jalan di %s:%s -> SSL:%s | WS:%s (Premium Fragmenter Active)",
        LISTEN_HOST, LISTEN_PORT, SSL_TARGET_PORT, WS_TARGET_PORT,
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
