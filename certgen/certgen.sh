#!/usr/bin/env sh
set -eu

DOMAIN="${DOMAIN:-localhost}"
DAYS="${DAYS:-825}"

CERTS_DIR="/certs"
mkdir -p "$CERTS_DIR"

if [ -s "$CERTS_DIR/privkey.pem" ] && [ -s "$CERTS_DIR/fullchain.pem" ]; then
  echo "Cert already exists. Nothing to do."
  exit 0
fi

echo "Generating wildcard *.${DOMAIN} (${DAYS} days)…"
if openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days "$DAYS" \
     -keyout "${CERTS_DIR}/privkey.pem" \
     -out    "${CERTS_DIR}/fullchain.pem" \
     -subj "/CN=*.${DOMAIN}" \
     -addext "subjectAltName=DNS:*.${DOMAIN},DNS:${DOMAIN}" \
     -addext "basicConstraints=CA:false" \
     -addext "keyUsage=digitalSignature,keyEncipherment" \
     -addext "extendedKeyUsage=serverAuth" 2>/dev/null; then
  :
else
  echo "Notice: openssl here doesn’t support -addext; falling back." >&2
  rm -f "${CERTS_DIR}/privkey.pem" "${CERTS_DIR}/fullchain.pem"
  openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days "$DAYS" \
     -keyout "${CERTS_DIR}/privkey.pem" \
     -out    "${CERTS_DIR}/fullchain.pem" \
     -subj "/CN=*.${DOMAIN}"
fi

chmod 600 "${CERTS_DIR}/privkey.pem" || true
[ -s "${CERTS_DIR}/privkey.pem" ] && [ -s "${CERTS_DIR}/fullchain.pem" ] \
  || { echo "Error: files not generated"; exit 1; }

echo "OK -> ${CERTS_DIR}/privkey.pem and ${CERTS_DIR}/fullchain.pem"