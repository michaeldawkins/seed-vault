//! Keys and identifiers.
//!
//! Every key is P-256 and signs with ES256, because the Mac's Secure Enclave
//! only offers P-256 (Slice 0 doc, section 6). Identifiers are `did:key`.
//!
//! [`Signer`] is the seam for hardware: a Secure Enclave, TPM or cloud KMS
//! signer implements the same trait and never exposes its private key.
//! [`SoftwareKey`] keeps the key in memory and is for tests, demos and
//! short-lived working keys only.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::{b64, Result, SeedError};

/// Multicodec prefix for a compressed P-256 public key (0x1200), as an unsigned varint.
const P256_PUB_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// Anything that can sign with a P-256 key and name its own identifier.
pub trait Signer {
    /// The `did:key` identifier of this key.
    fn did(&self) -> String;
    /// ES256 signature over `message`, as 64 raw bytes (r || s).
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

/// A P-256 key held in memory. Not for long-lived agent or owner keys in real use.
pub struct SoftwareKey {
    secret: SigningKey,
}

impl SoftwareKey {
    pub fn generate() -> Self {
        SoftwareKey {
            secret: SigningKey::random(&mut rand_core::OsRng),
        }
    }

    /// Restore a key from its exported secret (base64url of the 32-byte scalar).
    pub fn from_secret(text: &str) -> Result<Self> {
        let bytes = b64::decode(text)?;
        let secret = SigningKey::from_slice(&bytes)
            .map_err(|_| SeedError::Malformed("secret key is not a valid P-256 scalar".into()))?;
        Ok(SoftwareKey { secret })
    }

    pub fn export_secret(&self) -> String {
        b64::encode(&self.secret.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.secret.verifying_key()
    }
}

impl Signer for SoftwareKey {
    fn did(&self) -> String {
        did_for(&self.verifying_key())
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.secret.sign(message);
        signature.to_bytes().to_vec()
    }
}

/// The `did:key` for a P-256 public key (compressed point, multicodec 0x1200, base58btc).
pub fn did_for(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(true);
    let mut bytes = P256_PUB_MULTICODEC.to_vec();
    bytes.extend_from_slice(point.as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// Read the public key out of a P-256 `did:key`.
pub fn resolve(did: &str) -> Result<VerifyingKey> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| SeedError::Malformed(format!("not a did:key: {did}")))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| SeedError::Malformed("did:key is not base58".into()))?;
    let point = bytes
        .strip_prefix(&P256_PUB_MULTICODEC)
        .ok_or_else(|| SeedError::Malformed("did:key is not a P-256 key".into()))?;
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| SeedError::Malformed("did:key holds an invalid P-256 point".into()))
}

/// Check an ES256 signature made by the key behind `did`.
pub fn verify(did: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let key = resolve(did)?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| SeedError::BadSignature("signature has the wrong shape".into()))?;
    key.verify(message, &signature)
        .map_err(|_| SeedError::BadSignature(format!("signature does not match {did}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_round_trip_and_signature() {
        let key = SoftwareKey::generate();
        let did = key.did();
        assert!(
            did.starts_with("did:key:zDn"),
            "P-256 did:key starts with zDn, got {did}"
        );
        assert_eq!(resolve(&did).unwrap(), key.verifying_key());
        let sig = key.sign(b"hello");
        verify(&did, b"hello", &sig).unwrap();
        assert!(verify(&did, b"hellO", &sig).is_err());
        let restored = SoftwareKey::from_secret(&key.export_secret()).unwrap();
        assert_eq!(restored.did(), did);
    }
}
