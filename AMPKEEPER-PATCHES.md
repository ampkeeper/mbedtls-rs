# Vendored mbedtls-rs

Source: <https://github.com/esp-rs/mbedtls-rs>

Pinned upstream commit: `3847098439f7f58972852164e9c21fc3ec4194ce`

Pinned Mbed TLS submodule commit: `ffb280bb63c78bfec1e1ab55040671768c85c923`

The populated Mbed TLS source is included so feature-specific C libraries and
bindings can be generated without fetching a Git submodule. As in the published
`mbedtls-rs-sys` crate, its `framework/`, `programs/`, and `tests/` directories
are omitted.

AmpKeeper adds the opt-in `ecp-restartable` feature. It enables
`MBEDTLS_ECP_RESTARTABLE`, rebuilds the C library and bindings, limits ECC work
to one Mbed TLS operation per poll, resumes `CRYPTO_IN_PROGRESS` handshakes via
a cooperative self-wake, and restricts key agreement to P-256 so X25519 cannot
bypass the budget. The async client reports the first yield and the completed
handshake's total yield count, TLS version, and ciphersuite at INFO level.

AmpKeeper also adds an optional client maximum TLS version setting. All changes
are feature-gated or default to upstream behavior when unused.

AmpKeeper adds `Session::new_recoverable`, which returns the owned transport on
TLS setup failure. This lets the firmware explicitly abort its Embassy socket
instead of depending on drop semantics after TCP has connected.

Mbed TLS 3.6 currently wires restartable ECC into its SSL state machine only
for TLS 1.2 ECDHE-ECDSA client handshakes. A diagnostic client must therefore
set `max_version` to `Some(TlsVersion::Tls1_2)`; if TLS 1.3 is negotiated, the
feature still builds successfully but no cooperative crypto yields are expected.
