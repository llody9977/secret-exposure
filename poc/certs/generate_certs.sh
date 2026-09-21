#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${CERTS_DIR}"

# Reuse an existing CA/leaf pair. Regenerating on every bootstrap would leave a
# running Vault container serving a cert that no longer chains to the new ca.pem
# that bootstrap.py verifies against. 'make reset' does not remove certs; delete
# them by hand to force a fresh CA.
if [ -f ca.pem ] && [ -f ca-key.pem ] && [ -f vault.pem ] && [ -f vault-key.pem ]; then
    echo "Reusing existing lab certificates in ${CERTS_DIR}"
    exit 0
fi

rm -f ca.pem ca-key.pem vault.pem vault-key.pem

echo "Generating Lab CA with OpenSSL 3.6 / Python 3.14 compatible extensions..."

# CA config
cat << 'CONFIG' > ca.ext
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
CONFIG

openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -subj "/CN=Lab Root CA/O=Credential Lab" -out ca.pem -config <(cat /etc/ssl/openssl.cnf 2>/dev/null || true; cat ca.ext) -extensions v3_ca

# Vault Server Key & CSR
openssl genrsa -out vault-key.pem 2048
cat << 'CONFIG' > vault.ext
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = vault
DNS.2 = localhost
IP.1 = 127.0.0.1
CONFIG

openssl req -new -key vault-key.pem -subj "/CN=vault/O=Credential Lab" -out vault.csr
openssl x509 -req -in vault.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out vault.pem -days 365 -extfile vault.ext

rm -f vault.csr vault.ext ca.ext
chmod 600 ca-key.pem vault-key.pem
chmod 644 ca.pem vault.pem

echo "Certificates generated successfully in ${CERTS_DIR}"
