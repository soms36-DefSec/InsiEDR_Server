#!/bin/sh
set -e

if [ ! -f /etc/nginx/certs/server.crt ] || [ ! -f /etc/nginx/certs/server.key ]; then
    echo "[InsiEDR Nginx] No TLS certificates found in /etc/nginx/certs. Provisioning development self-signed certificate..."
    which openssl >/dev/null 2>&1 || apk add --no-cache openssl
    mkdir -p /etc/nginx/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -subj "/CN=localhost/O=InsiEDR Dev"
    echo "[InsiEDR Nginx] Generated development self-signed certificate in /etc/nginx/certs."
fi

if [ "${INSIEDR_PRESENTATION_MODE:-false}" = "true" ]; then
    sed 's#set \$upstream_backend "http://backend:5000";#set \$upstream_backend "http://presentation-gateway:5000";#' \
        /etc/nginx/nginx.conf > /tmp/nginx-presentation.conf
    echo "[InsiEDR Nginx] Serving isolated scenario website through the main dashboard URL."
    exec nginx -c /tmp/nginx-presentation.conf -g "daemon off;"
fi

exec nginx -g "daemon off;"
