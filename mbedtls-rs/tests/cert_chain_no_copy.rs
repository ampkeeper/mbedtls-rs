use mbedtls_rs::sys::{MbedtlsError, MBEDTLS_ERR_X509_BAD_INPUT_DATA};
use mbedtls_rs::{verify_chain, Certificate, SessionError};

const R1: &[u8] = include_bytes!("fixtures/chain-walk/r1.der");
const R2: &[u8] = include_bytes!("fixtures/chain-walk/r2.der");

#[test]
fn both_roots_are_present_in_order() {
    let roots = [R1, R2];
    let trust = Certificate::new_no_copy_chain(&roots).unwrap();
    let leaves: [&[u8]; 2] = [
        include_bytes!("fixtures/chain-walk/leaf-r1.der"),
        include_bytes!("fixtures/chain-walk/leaf-r2.der"),
    ];
    for (index, leaf) in leaves.iter().enumerate() {
        let chain = Certificate::new_no_copy(leaf).unwrap();
        assert_eq!(verify_chain(&chain, &trust), Ok(index));
    }
}

#[test]
fn empty_trust_list_is_rejected() {
    let error = Certificate::new_no_copy_chain(&[]).unwrap_err();
    let expected = SessionError::MbedTls(MbedtlsError::new(MBEDTLS_ERR_X509_BAD_INPUT_DATA));
    assert_eq!(error, expected);
}

#[test]
fn invalid_second_der_rejects_the_entire_chain() {
    let roots = [R1, b"invalid DER"];
    assert!(Certificate::new_no_copy_chain(&roots).is_err());
}

#[test]
fn subject_formats_into_caller_buffer_and_rejects_small_buffers() {
    let certificate = Certificate::new_no_copy(R1).unwrap();
    let mut buffer = [0; 128];
    let subject = certificate.subject(&mut buffer).unwrap();
    assert_eq!(subject, "CN=Chain Walk R1");
    assert!(certificate.subject(&mut []).is_err());
    assert!(certificate.subject(&mut [0; 1]).is_err());
}
