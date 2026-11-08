use core::convert::Infallible;
use std::net::TcpStream;
use std::sync::Mutex;

use mbedtls_rs::blocking::io::{ErrorKind, ErrorType, Read, Write};
use mbedtls_rs::Tls;
use rand::{Rng, TryCryptoRng, TryRng};

pub static SERIAL: Mutex<()> = Mutex::new(());

pub fn tls() -> Tls<'static> {
    // A zero-sized RNG with a static lifetime lets tests use the safe constructor.
    Tls::new(Box::leak(Box::new(StdRng))).unwrap()
}

pub struct StdRng;

impl TryRng for StdRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::rng().next_u64())
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        rand::rng().fill_bytes(destination);
        Ok(())
    }
}

impl TryCryptoRng for StdRng {}

pub struct TcpEndpoint(pub TcpStream);

fn io_error_kind(error: std::io::Error) -> ErrorKind {
    match error.kind() {
        std::io::ErrorKind::BrokenPipe => ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionAborted => ErrorKind::ConnectionAborted,
        std::io::ErrorKind::ConnectionReset => ErrorKind::ConnectionReset,
        std::io::ErrorKind::Interrupted => ErrorKind::Interrupted,
        std::io::ErrorKind::NotConnected => ErrorKind::NotConnected,
        std::io::ErrorKind::TimedOut => ErrorKind::TimedOut,
        _ => ErrorKind::Other,
    }
}

impl ErrorType for TcpEndpoint {
    type Error = ErrorKind;
}

impl Read for TcpEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        std::io::Read::read(&mut self.0, buffer).map_err(io_error_kind)
    }
}

impl Write for TcpEndpoint {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        std::io::Write::write(&mut self.0, buffer).map_err(io_error_kind)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        std::io::Write::flush(&mut self.0).map_err(io_error_kind)
    }
}
