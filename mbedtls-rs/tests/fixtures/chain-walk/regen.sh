#!/usr/bin/env bash
# Regenerate long-lived P-256 certificates; private keys never leave the temporary directory.
set -euo pipefail
fixture_directory=$(cd -- "$(dirname -- "$0")" && pwd)
working_directory=$(mktemp -d)
trap 'rm -rf -- "$working_directory"' EXIT
cd "$working_directory"
cat > ca.ext <<'EXT'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXT
cat > leaf.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXT
for name in r1 r2 intermediate leaf leaf-r1 leaf-r2; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key"
done
for number in 1 2; do
    openssl req -new -x509 -key "r$number.key" -sha256 -days 36500 \
        -set_serial "$number" -subj "/CN=Chain Walk R$number" -out "r$number.pem" \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash'
done
issue() {
    local name=$1 subject=$2 issuer=$3 serial=$4 extensions=$5
    openssl req -new -key "$name.key" -subj "/CN=Chain Walk $subject" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" \
        -set_serial "$serial" -sha256 -days 36500 -extfile "$extensions" -out "$name.pem"
}
# Reuse R2's key and subject, changing only its issuer/signature and serial.
cp r2.key r2-by-r1.key
issue r2-by-r1 R2 r1 3 ca.ext
issue intermediate I r2 4 ca.ext
issue leaf L intermediate 5 leaf.ext
issue leaf-r1 L1 r1 6 leaf.ext
issue leaf-r2 L2 r2 7 leaf.ext
for name in r1 r2 r2-by-r1 intermediate leaf leaf-r1 leaf-r2; do
    openssl x509 -in "$name.pem" -outform DER -out "$fixture_directory/$name.der"
done
