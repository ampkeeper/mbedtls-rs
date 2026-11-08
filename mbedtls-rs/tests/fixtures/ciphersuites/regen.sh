#!/usr/bin/env bash
# RSA credentials for the TLS 1.2 suite-negotiation regression test only.
set -euo pipefail
fixture_directory=$(cd -- "$(dirname -- "$0")" && pwd)
working_directory=$(mktemp -d)
trap 'rm -rf -- "$working_directory"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$working_directory/key.pem"
openssl req -new -x509 -key "$working_directory/key.pem" -sha256 -days 36500 \
    -set_serial 1 -subj '/CN=mbedtls-rs.local' -addext 'subjectAltName=DNS:mbedtls-rs.local' \
    -out "$working_directory/cert.pem"
openssl x509 -in "$working_directory/cert.pem" -outform DER -out "$fixture_directory/rsa-cert.der"
openssl pkcs8 -topk8 -nocrypt -in "$working_directory/key.pem" -outform DER -out "$fixture_directory/rsa-key.der"
