#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/tdx-fake-certs"

mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

echo "Generating fake TDX/SGX certificate chain..."

# Generate Intel SGX Root CA - self-signed
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -new -x509 -key root.key -out root.pem -days 3650 -sha256 \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX Root CA"
echo "Created root.pem (self-signed Intel SGX Root CA)"

# Generate Intel SGX PCK Platform CA - signed by Root CA
cat > platform_ca.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl ecparam -name prime256v1 -genkey -noout -out platform.key
openssl req -new -key platform.key -out platform.csr \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX PCK Platform CA"
openssl x509 -req -in platform.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -out platform.pem -days 3650 -sha256 -extfile platform_ca.cnf -extensions v3_ca
echo "Created platform.pem (Intel SGX PCK Platform CA, signed by Root CA)"

# Create PCK extensions config with SGX OIDs
# OID 1.2.840.113741.1.13.1 is the SGX Extensions OID
cat > pck.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_pck]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# Generate PCK (Provisioning Certification Key) - signed by Platform CA
openssl ecparam -name prime256v1 -genkey -noout -out pck.key
openssl req -new -key pck.key -out pck.csr \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX PCK Certificate"
openssl x509 -req -in pck.csr -CA platform.pem -CAkey platform.key -CAcreateserial \
  -out pck.pem -days 3650 -sha256 -extfile pck.cnf -extensions v3_pck
echo "Created pck.pem (Intel SGX PCK Certificate, signed by Platform CA)"

# Create the issuer chain (Platform CA + Root CA)
cat platform.pem root.pem > pck_issuer_chain.pem
echo "Created pck_issuer_chain.pem (Platform CA + Root CA chain)"

# Create the full chain (PCK + Platform CA + Root CA)
cat pck.pem platform.pem root.pem > pck_chain.pem
echo "Created pck_chain.pem (full certificate chain)"

# Clean up temporary files (keep only the files needed by cvmtool)
rm -f root.key platform.key pck.key root.srl platform.srl platform.csr pck.csr platform_ca.cnf pck.cnf
rm -f root.pem platform.pem

echo ""
echo "Done! Fake TDX/SGX certificates created in ${CERTS_DIR}/"
echo ""
echo "Certificate chain:"
echo "  Intel SGX Root CA (self-signed) -> Intel SGX PCK Platform CA -> Intel SGX PCK Certificate"
echo ""
echo "Files:"
echo "  pck.pem             - PCK certificate only"
echo "  pck_issuer_chain.pem - Platform CA + Root CA"
echo "  pck_chain.pem       - Full chain (PCK + Platform CA + Root CA)"
