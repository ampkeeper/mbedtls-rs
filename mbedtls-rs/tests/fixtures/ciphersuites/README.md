# Ciphersuite fixtures

Run `./regen.sh` to regenerate the RSA-2048 self-signed server certificate and
PKCS#8 private key, valid for 36,500 days. The key is public test material only.
The ECDSA tests reuse the existing `../cert.der` and `../key.der` P-256 credentials.

The default host TLS bundle enables RSA key exchanges. Tests first handshake
successfully with these RSA credentials and default client suites, then check
that an ECDHE-ECDSA-only allowlist fails with the server's
`MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE` at suite negotiation.

The host's compiled TLS 1.2 ECDHE-ECDSA suite table enables these 19 suites
(all names have the prefix `TLS-ECDHE-ECDSA-WITH-`):

- CHACHA20-POLY1305-SHA256
- AES-128-CBC-SHA and AES-256-CBC-SHA
- AES-128-CBC-SHA256 and AES-256-CBC-SHA384
- AES-128-GCM-SHA256 and AES-256-GCM-SHA384
- AES-128-CCM and AES-256-CCM
- AES-128-CCM-8 and AES-256-CCM-8
- CAMELLIA-128-CBC-SHA256 and CAMELLIA-256-CBC-SHA384
- CAMELLIA-128-GCM-SHA256 and CAMELLIA-256-GCM-SHA384
- ARIA-128-CBC-SHA256 and ARIA-256-CBC-SHA384
- ARIA-128-GCM-SHA256 and ARIA-256-GCM-SHA384

The test allowlist uses AES-128-GCM-SHA256, AES-256-GCM-SHA384, and
CHACHA20-POLY1305-SHA256. It handshakes with the full list and with each suite
alone, proving all three are usable in this build.
