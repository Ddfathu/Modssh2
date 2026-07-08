FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --- Menginstal dependensi dasar ---
RUN apt-get update && apt-get install -y \
    dropbear \
    stunnel4 \
    openssl \
    sudo \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install cloudflared (untuk Argo Tunnel, jalur WS)
RUN curl -fsSL -o /usr/local/bin/cloudflared \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared

# 🔥 PERBAIKAN: Membuat semua direktori run & konfigurasi yang dibutuhkan secara lengkap
RUN mkdir -p /var/run/dropbear /var/run/stunnel /etc/dropbear /etc/stunnel

# 🔥 PERBAIKAN: Membuat sertifikat SSL untuk Stunnel (Sekarang direktori /etc/stunnel sudah pasti ada)
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=RailwaySSH/CN=localhost" \
    -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem

# 🔥 OPTIMASI: Atur kepemilikan folder agar Stunnel tidak mengalami 'Permission Denied' saat membuat PID
RUN chown -R stunnel4:stunnel4 /var/run/stunnel /etc/stunnel

# Menyalin script utama
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Menyalin script manajemen user (addssh, delssh, listssh, menu)
COPY addssh delssh listssh menu /usr/local/bin/
RUN chmod +x /usr/local/bin/addssh /usr/local/bin/delssh /usr/local/bin/listssh /usr/local/bin/menu

# Menyalin core script proxy & multiplexer kita
COPY ws-proxy.py /usr/local/bin/ws-proxy.py
RUN chmod +x /usr/local/bin/ws-proxy.py

COPY mux.py /usr/local/bin/mux.py
RUN chmod +x /usr/local/bin/mux.py

# Cukup SATU port publik: mux.py yang membedakan SSL vs WS secara otomatis
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
