use mbedtls_rs::sys::{MbedtlsError, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED};
use mbedtls_rs::{verify_chain, Certificate};

const R1: &[u8] = include_bytes!("fixtures/chain-walk/r1.der");
const R2: &[u8] = include_bytes!("fixtures/chain-walk/r2.der");
const CROSS_SIGN: &[u8] = include_bytes!("fixtures/chain-walk/r2-by-r1.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/chain-walk/intermediate.der");
const LEAF: &[u8] = include_bytes!("fixtures/chain-walk/leaf.der");

#[test]
fn trusted_r2_ends_the_walk_even_with_r1_first_and_a_cross_sign_served() {
    let roots = [R1, R2];
    let trust = Certificate::new_no_copy_chain(&roots).unwrap();
    for served in [
        &[LEAF, INTERMEDIATE, CROSS_SIGN][..],
        &[LEAF, INTERMEDIATE][..],
    ] {
        let chain = Certificate::new_no_copy_chain(served).unwrap();
        assert_eq!(verify_chain(&chain, &trust), Ok(1));
    }
}

#[test]
fn r1_requires_the_r2_cross_sign() {
    let roots = [R1];
    let trust = Certificate::new_no_copy_chain(&roots).unwrap();
    let served = [LEAF, INTERMEDIATE, CROSS_SIGN];
    let chain = Certificate::new_no_copy_chain(&served).unwrap();
    assert_eq!(verify_chain(&chain, &trust), Ok(0));
    let served = [LEAF, INTERMEDIATE];
    let chain = Certificate::new_no_copy_chain(&served).unwrap();
    let expected = MbedtlsError::new(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
    assert_eq!(verify_chain(&chain, &trust), Err(expected));
}
