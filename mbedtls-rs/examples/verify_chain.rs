//! Host-only chain checker, using only std and the crate's existing dev dependencies.
//! Usage: cargo run -p mbedtls-rs --example verify_chain -- \
//!   --trust root.der [--trust another-root.der] --chain served.pem [--drop substring]...
//! PEM blocks may be surrounded by openssl s_client output. Subjects use Mbed TLS's
//! format (for example `CN=Chain Walk R2`); --drop removes all matching certificates.

use std::ffi::CString;
use std::path::PathBuf;

use mbedtls_rs::{verify_chain, Certificate, X509};

fn run() -> Result<String, Box<dyn std::error::Error>> {
    let mut trust_paths = Vec::<PathBuf>::new();
    let mut chain_path = None;
    let mut drop_subjects = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("missing option value")?;
        match argument.as_str() {
            "--trust" => trust_paths.push(value.into()),
            "--chain" => chain_path = Some(PathBuf::from(value)),
            "--drop" => drop_subjects.push(value),
            _ => return Err(format!("unknown option: {argument}").into()),
        }
    }
    if trust_paths.is_empty() {
        return Err("at least one --trust root.der is required".into());
    }
    let trust_ders = trust_paths
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    let trust_slices = trust_ders.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let trust = Certificate::new_no_copy_chain(&trust_slices)?;
    let served = std::fs::read_to_string(chain_path.ok_or("--chain served.pem is required")?)?;
    let mut filtered = String::new();
    let mut remaining = served.as_str();
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = remaining.find(BEGIN) {
        remaining = &remaining[start..];
        let end = remaining.find(END).ok_or("unterminated PEM certificate")? + END.len();
        let certificate_pem = &remaining[..end];
        let certificate_string = CString::new(certificate_pem)?;
        let certificate = Certificate::new(X509::PEM(&certificate_string))?;
        let mut subject_buffer = [0; 4096];
        let subject = certificate.subject(&mut subject_buffer)?;
        if !drop_subjects
            .iter()
            .any(|substring| subject.contains(substring))
        {
            filtered.push_str(certificate_pem);
            filtered.push('\n');
        }
        remaining = &remaining[end..];
    }
    if filtered.is_empty() {
        return Err("no certificates remain in the served chain".into());
    }
    let filtered = CString::new(filtered)?;
    let chain = Certificate::new(X509::PEM(&filtered))?;
    let anchor_index = verify_chain(&chain, &trust)?;
    let anchor = Certificate::new_no_copy(trust_slices[anchor_index])?;
    let mut subject_buffer = [0; 4096];
    Ok(anchor.subject(&mut subject_buffer)?.to_owned())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(subject) => {
            println!("PASS anchor={subject}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            println!("FAIL {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
