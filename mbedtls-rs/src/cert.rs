use core::ffi::CStr;
use core::marker::PhantomData;

use super::sys::*;
use super::{MRc, SessionError};

/// Holds a reference to a PEM or DER-encoded X509 certificate or private key.
///
/// # Examples
/// Initialize with a PEM certificate
/// (`ignore`d: the examples include user-provided certificate files)
/// ```ignore
/// let x509 = X509::PEM(CStr::from_bytes_with_nul(concat!(include_str!("cert.pem"), "\0").as_bytes()).unwrap());
/// ```
///
/// Initialize with a DER certificate
/// ```ignore
/// let x509 = X509::DER(include_bytes!("cert.der"));
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum X509<'a> {
    PEM(&'a CStr),
    DER(&'a [u8]),
}

/// A parsed X509 certificate or certificate chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate<'d> {
    pub(crate) crt: MRc<mbedtls_x509_crt>,
    _t: PhantomData<&'d ()>,
}

impl Certificate<'static> {
    /// Parse an X509 certificate into RAM by making a copy
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in PEM or DER format
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// certificate in a PEM format, and vice-versa.
    pub fn new(x509: X509<'_>) -> Result<Self, MbedtlsError> {
        let mut crt: MRc<mbedtls_x509_crt> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_X509_ALLOC_FAILED))?;

        match x509 {
            X509::PEM(str) => merr!(unsafe {
                mbedtls_x509_crt_parse(
                    crt.as_mut_ptr(),
                    str.as_ptr() as *const _,
                    str.count_bytes() + 1,
                )
            }),
            X509::DER(bytes) => merr!(unsafe {
                mbedtls_x509_crt_parse_der(crt.as_mut_ptr(), bytes.as_ptr(), bytes.len())
            }),
        }?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

impl<'d> Certificate<'d> {
    /// Parse an X509 certificate without making a copy in RAM. This requires that the underlying data
    /// lives for the lifetime of the certificate.
    /// Note: This is currently only supported for DER encoded certificates
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in DER format only
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing.
    /// [TlsError::InvalidFormat] will be returned if a PEM encoded certificate is passed.
    pub fn new_no_copy(x509_der: &'d [u8]) -> Result<Self, SessionError> {
        let mut crt: MRc<mbedtls_x509_crt> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_X509_ALLOC_FAILED))?;

        merr!(unsafe {
            mbedtls_x509_crt_parse_der_nocopy(crt.as_mut_ptr(), x509_der.as_ptr(), x509_der.len())
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }

    /// Parse a chain of DER certificates without copying their data into RAM.
    /// Every DER and the slice of DER references must outlive the certificate.
    /// Certificates are appended in the supplied order.
    ///
    /// # Errors
    /// Returns an error for an empty list, allocation failure, or any invalid DER.
    /// A parse error frees the entire partially parsed chain.
    pub fn new_no_copy_chain(x509_ders: &'d [&'d [u8]]) -> Result<Self, SessionError> {
        if x509_ders.is_empty() {
            return Err(MbedtlsError::new(MBEDTLS_ERR_X509_BAD_INPUT_DATA).into());
        }
        let mut crt: MRc<mbedtls_x509_crt> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_X509_ALLOC_FAILED))?;
        for x509_der in x509_ders {
            // SAFETY: `crt` owns an initialized chain and each DER remains alive
            // for `'d`. Mbed TLS appends nodes and MRc frees them on any error.
            merr!(unsafe {
                mbedtls_x509_crt_parse_der_nocopy(
                    crt.as_mut_ptr(),
                    x509_der.as_ptr(),
                    x509_der.len(),
                )
            })?;
        }
        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }

    /// Format the first certificate's subject into the caller's buffer.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or the subject is not UTF-8.
    pub fn subject<'buffer>(
        &self,
        buffer: &'buffer mut [u8],
    ) -> Result<&'buffer str, MbedtlsError> {
        // SAFETY: the subject belongs to this live parsed certificate, and the
        // output buffer is writable for its stated length for this call.
        let length = merr!(unsafe {
            mbedtls_x509_dn_gets(buffer.as_mut_ptr().cast(), buffer.len(), &self.crt.subject)
        })? as usize;
        core::str::from_utf8(&buffer[..length])
            .map_err(|_| MbedtlsError::new(MBEDTLS_ERR_X509_BAD_INPUT_DATA))
    }
}

/// Verify a leaf-first chain and return the zero-based index of its selected trust anchor.
/// Hostname matching is omitted; date checks follow the build's wall-clock configuration.
///
/// # Errors
/// Returns the Mbed TLS verification error, or `MBEDTLS_ERR_X509_BAD_INPUT_DATA`
/// if verification succeeds without identifying an entry in `trust_anchors`.
pub fn verify_chain(
    chain: &Certificate<'_>,
    trust_anchors: &Certificate<'_>,
) -> Result<usize, MbedtlsError> {
    struct SelectedAnchor {
        depth: core::ffi::c_int,
        certificate: *mut mbedtls_x509_crt,
    }

    unsafe extern "C" fn record_anchor(
        context: *mut core::ffi::c_void,
        certificate: *mut mbedtls_x509_crt,
        depth: core::ffi::c_int,
        _flags: *mut u32,
    ) -> core::ffi::c_int {
        // SAFETY: verify passes our exclusively borrowed local SelectedAnchor
        // to this synchronous callback. The certificate belongs to the input
        // chain or trust list and remains alive until verification completes.
        let selected = unsafe { &mut *context.cast::<SelectedAnchor>() };
        if depth > selected.depth {
            selected.depth = depth;
            selected.certificate = certificate;
        }
        0
    }

    let mut selected = SelectedAnchor {
        depth: -1,
        certificate: core::ptr::null_mut(),
    };
    let mut flags = 0;
    // SAFETY: both initialized certificate lists remain alive throughout this
    // synchronous, read-only verification. No CRL or hostname is requested.
    // The callback context and flags are valid exclusive locals for the call.
    merr!(unsafe {
        mbedtls_x509_crt_verify(
            &*chain.crt as *const _ as *mut _,
            &*trust_anchors.crt as *const _ as *mut _,
            core::ptr::null_mut(),
            core::ptr::null(),
            &mut flags,
            Some(record_anchor),
            &mut selected as *mut SelectedAnchor as *mut _,
        )
    })?;

    if !selected.certificate.is_null() {
        // SAFETY: the recorded certificate and linked trust-list nodes belong
        // to the still-live inputs. Parsed raw DER buffers are valid for raw.len
        // bytes. We only read them, stopping before dereferencing a null node.
        unsafe {
            let selected_raw = &(*selected.certificate).raw;
            let selected_der = core::slice::from_raw_parts(selected_raw.p, selected_raw.len);
            let mut anchor = &*trust_anchors.crt as *const mbedtls_x509_crt;
            let mut index = 0;
            while !anchor.is_null() {
                let raw = &(*anchor).raw;
                if core::slice::from_raw_parts(raw.p, raw.len) == selected_der {
                    return Ok(index);
                }
                anchor = (*anchor).next;
                index += 1;
            }
        }
    }
    Err(MbedtlsError::new(MBEDTLS_ERR_X509_BAD_INPUT_DATA))
}

/// A parsed private key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrivateKey(pub(crate) MRc<mbedtls_pk_context>);

impl PrivateKey {
    /// Parse an X509 private key into RAM and returns a wrapped pointer if successful.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The X509 private key in DER or PEM format
    /// * `password` - The optional password if the private key is password protected
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// private key in a PEM format, and vice-versa.
    pub fn new(x509: X509<'_>, password: Option<&str>) -> Result<Self, SessionError> {
        let mut pk: MRc<mbedtls_pk_context> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_PK_ALLOC_FAILED))?;

        #[allow(clippy::unnecessary_cast)]
        let (ptr, len) = match x509 {
            X509::PEM(str) => (str.as_ptr() as *const u8, str.count_bytes() + 1),
            X509::DER(bytes) => (bytes.as_ptr(), bytes.len()),
        };

        let (password_ptr, password_len) = if let Some(password) = password {
            (password.as_ptr(), password.len())
        } else {
            (core::ptr::null(), 0)
        };

        merr!(unsafe {
            mbedtls_pk_parse_key(
                pk.as_mut_ptr(),
                ptr as _,
                len,
                password_ptr,
                password_len,
                None,
                core::ptr::null_mut(),
            )
        })?;

        Ok(Self(pk))
    }
}
