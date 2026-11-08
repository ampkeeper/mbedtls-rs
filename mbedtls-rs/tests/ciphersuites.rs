mod support;

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use mbedtls_rs::blocking::Session;
use mbedtls_rs::sys::{
    MbedtlsError, MBEDTLS_ERR_SSL_BAD_INPUT_DATA, MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
};
use mbedtls_rs::{
    Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig, SessionConfig,
    SessionError, TlsReference, TlsVersion, X509,
};
use support::{tls, TcpEndpoint, SERIAL};

const ECDSA_CERTIFICATE: &[u8] = include_bytes!("fixtures/cert.der");
const ECDSA_KEY: &[u8] = include_bytes!("fixtures/key.der");
const RSA_CERTIFICATE: &[u8] = include_bytes!("fixtures/ciphersuites/rsa-cert.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/ciphersuites/rsa-key.der");

// Each of these TLS 1.2 ECDHE-ECDSA suites is enabled by the default host bundle.
const ECDSA_SUITES: &[i32] = &[
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as i32,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as i32,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 as i32,
];

fn handshake(
    tls_reference: TlsReference<'_>,
    ciphersuites: Option<&[i32]>,
    rsa: bool,
) -> (Result<(), SessionError>, Result<(), SessionError>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (certificate, key) = if rsa {
        (RSA_CERTIFICATE, RSA_KEY)
    } else {
        (ECDSA_CERTIFICATE, ECDSA_KEY)
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let config = SessionConfig::Server(ServerSessionConfig::new(Credentials {
                certificate: Certificate::new_no_copy(certificate).unwrap(),
                private_key: PrivateKey::new(X509::DER(key), None).unwrap(),
            }));
            let mut session = Session::new(tls_reference, TcpEndpoint(stream), &config).unwrap();
            session.connect()
        });
        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let owned_suites = ciphersuites.map(<[i32]>::to_vec);
        // Drop the configuration before the handshake, as real callers may do.
        let mut session = {
            let config = SessionConfig::Client(ClientSessionConfig {
                ca_chain: Some(Certificate::new_no_copy(certificate).unwrap()),
                server_name: Some(c"mbedtls-rs.local"),
                max_version: Some(TlsVersion::Tls1_2),
                ciphersuites: owned_suites.as_deref(),
                ..ClientSessionConfig::new()
            });
            Session::new(tls_reference, TcpEndpoint(stream), &config).unwrap()
        };
        let client_result = session.connect();
        (client_result, server.join().unwrap())
    })
}

#[test]
fn ecdsa_allowlist_handshakes_with_ecdsa_credentials() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let tls = tls();
    let (client, server) = handshake(tls.reference(), Some(ECDSA_SUITES), false);
    assert_eq!(client, Ok(()));
    assert_eq!(server, Ok(()));
    // Also demonstrate that every offered suite is actually enabled on this host.
    for suite in ECDSA_SUITES {
        let (client, server) = handshake(tls.reference(), Some(&[*suite]), false);
        assert_eq!(client, Ok(()));
        assert_eq!(server, Ok(()));
    }
}

#[test]
fn ecdsa_allowlist_rejects_rsa_at_suite_negotiation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let tls = tls();
    // Prove RSA credentials and RSA suite negotiation work with defaults first.
    let (client, server) = handshake(tls.reference(), None, true);
    assert_eq!(client, Ok(()));
    assert_eq!(server, Ok(()));
    let (client, server) = handshake(tls.reference(), Some(ECDSA_SUITES), true);
    let expected = SessionError::MbedTls(MbedtlsError::new(MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE));
    assert_eq!(server, Err(expected));
    assert!(client.is_err());
}

#[test]
fn invalid_allowlists_fail_at_session_creation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let tls = tls();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for ciphersuites in [&[][..], &[0][..], &[ECDSA_SUITES[0], 0][..]] {
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let config = SessionConfig::Client(ClientSessionConfig {
            ciphersuites: Some(ciphersuites),
            ..ClientSessionConfig::new()
        });
        let error = Session::new(tls.reference(), TcpEndpoint(stream), &config)
            .err()
            .unwrap();
        let expected = SessionError::MbedTls(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
        assert_eq!(error, expected);
    }
}

#[test]
fn none_keeps_the_default_handshake() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let tls = tls();
    assert_eq!(ClientSessionConfig::new().ciphersuites, None);
    let (client, server) = handshake(tls.reference(), None, false);
    assert_eq!(client, Ok(()));
    assert_eq!(server, Ok(()));
}
