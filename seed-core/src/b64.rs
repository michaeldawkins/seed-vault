use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{Result, SeedError};

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| SeedError::Malformed(format!("base64url: {e}")))
}

/// A random, URL-safe one-time value.
pub fn random_token(bytes: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    encode(&buf)
}
