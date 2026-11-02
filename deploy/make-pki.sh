#!/usr/bin/env bash
# Private CA for orchestrator <-> inference nodes (mTLS). openssl only.
# Usage: ./make-pki.sh <outdir> <m5_ip> <m970_ip>
# Keep ca.key OFFLINE (USB key / password manager) once certificates are issued.
set -euo pipefail
OUT=${1:?outdir}; M5=${2:?m5 ip}; M970=${3:?m970 ip}
DAYS_CA=1825; DAYS_LEAF=397
umask 077
mkdir -p "$OUT" && cd "$OUT"

ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

if [[ ! -f ca.key ]]; then
  ec ca.key
  openssl req -x509 -new -key ca.key -sha256 -days $DAYS_CA -out ca.crt \
    -subj "/CN=orchestrator private CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

leaf() {  # name, subject CN, extensions
  ec "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -days $DAYS_LEAF -out "$1.crt" -extfile <(printf '%s\n' "$3")
  rm -f "$1.csr"
}
leaf m5         m5.lan       "subjectAltName=IP:$M5,DNS:m5.lan
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature"
leaf m970       m970.lan     "subjectAltName=IP:$M970,DNS:m970.lan
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature"
leaf orchestrator orchestrator "extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature"

chmod 0400 ./*.key; chmod 0444 ./*.crt
for c in m5 m970 orchestrator; do openssl verify -CAfile ca.crt "$c.crt"; done
echo "Next: copy {m5,m970}.{crt,key} + ca.crt to each node's deploy/inference-node/pki/ as server.{crt,key}"
echo "      copy orchestrator.{crt,key} + ca.crt to /etc/claude-orchestrator/pki/ (chown 10001, chmod 0400)"
