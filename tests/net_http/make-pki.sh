#!/usr/bin/env bash
# The net.http evidence's test PKI (ADR-0050 §16): generated afresh for every
# run, into the directory given, and never committed -- no private key of any
# kind lives in the repository.
#
#   ca.pem / ca.key          the evidence trust anchor (`--allow-evidence-trust`)
#   rogue.pem / rogue.key    a second authority nothing trusts
#   origin.{pem,key}         origin.test and rebind.test, signed by the anchor, valid now
#   other.{pem,key}          other.test, signed by the anchor: the wrong name
#   alt.{pem,key}            alt.origin.test, signed by the anchor: a second origin
#   expired.{pem,key}        origin.test, signed by the anchor, expired in 2020
#   rogue-origin.{pem,key}   origin.test, signed by the rogue authority
#   selfsigned.{pem,key}     origin.test, signed by itself
#
# `openssl ca` rather than `openssl x509 -not_after`: dates in the past need
# OpenSSL 3.4's x509 options otherwise, and CI's runners have 3.0.
set -euo pipefail
out=${1:?usage: make-pki.sh <directory>}
mkdir -p "$out"
cd "$out"

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

for ca in ca rogue; do
  key "$ca.key"
  openssl req -x509 -new -key "$ca.key" -sha256 -days 3650 \
    -subj "/CN=DireWolf net.http evidence $ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$ca.pem" 2>/dev/null
done

mkdir -p db
: >db/index.txt
echo 1000 >db/serial
cat >ca.cnf <<'EOF'
[ca]
default_ca = evidence
[evidence]
dir = .
database = db/index.txt
serial = db/serial
new_certs_dir = db
default_md = sha256
policy = anything
unique_subject = no
copy_extensions = none
[anything]
commonName = supplied
EOF

# leaf <name> <signing authority> <dns names, comma-separated> <not before> <not after>
leaf() {
  key "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=${3%%,*}" -out "$1.csr" 2>/dev/null
  san=$(printf '%s' "$3" | sed 's/[^,][^,]*/DNS:&/g')
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" >"$1.ext"
  openssl ca -batch -config ca.cnf -cert "$2.pem" -keyfile "$2.key" -in "$1.csr" \
    -out "$1.pem" -startdate "$4" -enddate "$5" -extfile "$1.ext" -notext 2>/dev/null
}

# origin.test also answers for the evidence's rebinding name.
leaf origin ca origin.test,rebind.test 20250101000000Z 20991231000000Z
leaf other ca other.test 20250101000000Z 20991231000000Z
leaf alt ca alt.origin.test 20250101000000Z 20991231000000Z
leaf expired ca origin.test 20200101000000Z 20200102000000Z
leaf rogue-origin rogue origin.test 20250101000000Z 20991231000000Z

key selfsigned.key
openssl req -x509 -new -key selfsigned.key -sha256 -days 3650 -subj "/CN=origin.test" \
  -addext "subjectAltName=DNS:origin.test" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -out selfsigned.pem 2>/dev/null

echo "pki ready: $out"
