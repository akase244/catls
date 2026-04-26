#!/bin/sh
set -e

CERT_DIR="/etc/nginx/certs"

# ルート証明書
ROOTCA_CERT_NAME="snakeoil_root_ca"
ROOTCA_CERT_KEY="${CERT_DIR}/${ROOTCA_CERT_NAME}.key"
ROOTCA_CERT_CRT="${CERT_DIR}/${ROOTCA_CERT_NAME}.crt"
ROOTCA_CERT_CNF="${CERT_DIR}/${ROOTCA_CERT_NAME}.cnf"

# 中間CA証明書
INTERCA_CERT_NAME="snakeoil_intermediate_ca"
INTERCA_CERT_KEY="${CERT_DIR}/${INTERCA_CERT_NAME}.key"
INTERCA_CERT_CRT="${CERT_DIR}/${INTERCA_CERT_NAME}.crt"
INTERCA_CERT_CSR="${CERT_DIR}/${INTERCA_CERT_NAME}.csr"
INTERCA_CERT_CNF="${CERT_DIR}/${INTERCA_CERT_NAME}.cnf"

# サーバー証明書
SERVER_CERT_NAME="snakeoil"
SERVER_CERT_KEY="${CERT_DIR}/${SERVER_CERT_NAME}.key"
SERVER_CERT_CRT="${CERT_DIR}/${SERVER_CERT_NAME}.crt"
SERVER_CERT_CSR="${CERT_DIR}/${SERVER_CERT_NAME}.csr"
SERVER_CERT_CNF="${CERT_DIR}/${SERVER_CERT_NAME}.cnf"

# Nginxが参照するチェーン証明書（サーバー証明書 + 中間CA証明書）
SERVER_CHAIN_CRT="${CERT_DIR}/${SERVER_CERT_NAME}_chain.crt"

mkdir -p "$CERT_DIR"

# ルート証明書の設定
cat > "${ROOTCA_CERT_CNF}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_root_ca

[dn]
C = JP
ST = Tokyo
L = Chiyoda
O = Local Development
CN = Local Development Root CA

[v3_root_ca]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# 中間CA証明書の設定
cat > "${INTERCA_CERT_CNF}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = JP
ST = Tokyo
L = Chiyoda
O = Local Development
CN = Local Development Intermediate CA

[v3_intermediate_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# サーバー証明書の設定
cat > "${SERVER_CERT_CNF}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = JP
ST = Tokyo
L = Chiyoda
O = Local Development
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

if [ ! -f "${ROOTCA_CERT_KEY}" ] || [ ! -f "${ROOTCA_CERT_CRT}" ]; then
  echo "generating root CA certificate..."

  # ルートCAの秘密鍵を作成
  openssl genrsa -out "${ROOTCA_CERT_KEY}" 2048

  # ルートCAの秘密鍵で署名してルート証明書を作成
  openssl req -x509 \
    -key "${ROOTCA_CERT_KEY}" \
    -sha256 \
    -days 3650 \
    -out "${ROOTCA_CERT_CRT}" \
    -config "${ROOTCA_CERT_CNF}"

  chmod 600 "${ROOTCA_CERT_KEY}"
  chmod 644 "${ROOTCA_CERT_CRT}"

  echo "root CA certificate generated"
else
  echo "root CA certificate already exists"
fi

if [ ! -f "${INTERCA_CERT_KEY}" ] || [ ! -f "${INTERCA_CERT_CRT}" ]; then
  echo "generating intermediate CA certificate..."

  # 中間CAの秘密鍵を作成
  openssl genrsa -out "${INTERCA_CERT_KEY}" 2048

  # 中間CA証明書用のCSRを作成
  openssl req -new \
    -key "${INTERCA_CERT_KEY}" \
    -out "${INTERCA_CERT_CSR}" \
    -config "${INTERCA_CERT_CNF}"

  # ルートCAの秘密鍵で署名して中間CA証明書を作成
  openssl x509 -req \
    -in "${INTERCA_CERT_CSR}" \
    -CA "${ROOTCA_CERT_CRT}" \
    -CAkey "${ROOTCA_CERT_KEY}" \
    -CAcreateserial \
    -sha256 \
    -days 1825 \
    -out "${INTERCA_CERT_CRT}" \
    -extfile "${INTERCA_CERT_CNF}" \
    -extensions v3_intermediate_ca

  chmod 600 "${INTERCA_CERT_KEY}"
  chmod 644 "${INTERCA_CERT_CRT}"

  echo "intermediate CA certificate generated"
else
  echo "intermediate CA certificate already exists"
fi

if [ ! -f "${SERVER_CERT_KEY}" ] || [ ! -f "${SERVER_CERT_CRT}" ]; then
  echo "generating server certificate..."

  # サーバー証明書用の秘密鍵を作成
  openssl genrsa -out "${SERVER_CERT_KEY}" 2048

  # サーバー証明書用のCSRを作成
  openssl req -new \
    -key "${SERVER_CERT_KEY}" \
    -out "${SERVER_CERT_CSR}" \
    -config "${SERVER_CERT_CNF}"

  # 中間CAの秘密鍵で署名してサーバー証明書を作成
  openssl x509 -req \
    -in "${SERVER_CERT_CSR}" \
    -CA "${INTERCA_CERT_CRT}" \
    -CAkey "${INTERCA_CERT_KEY}" \
    -CAcreateserial \
    -sha256 \
    -days 365 \
    -out "${SERVER_CERT_CRT}" \
    -extfile "${SERVER_CERT_CNF}" \
    -extensions v3_req

  chmod 600 "${SERVER_CERT_KEY}"
  chmod 644 "${SERVER_CERT_CRT}"

  echo "server certificate generated"
else
  echo "server certificate already exists"
fi

if [ ! -f "${SERVER_CHAIN_CRT}" ]; then
  cat "${SERVER_CERT_CRT}" "${INTERCA_CERT_CRT}" > "${SERVER_CHAIN_CRT}"

  chmod 644 "${SERVER_CHAIN_CRT}"

  echo "chain certificate generated"
else
  echo "chain certificate already exists"
fi

exec "$@"
