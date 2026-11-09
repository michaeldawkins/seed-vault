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
    /// A hardware signer can fail (chip locked, helper missing); then nothing is signed.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
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

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.secret.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

/// A key held outside this process, such as in the Mac's Secure Enclave,
/// reached through a small helper program that never reveals the private key.
///
/// Helper protocol (see `enclave/` in this repository):
/// - `HELPER public KEY_FILE` prints the public key, base64url of the 65-byte
///   uncompressed point;
/// - `HELPER sign KEY_FILE` reads the message on stdin and prints the raw
///   64-byte ES256 signature as base64url.
///
/// `KEY_FILE` holds whatever the helper needs to find its key; for the Secure
/// Enclave it is a blob only that one chip can use.
pub struct ExternalSigner {
    program: std::path::PathBuf,
    key_file: std::path::PathBuf,
    did: String,
}

impl ExternalSigner {
    pub fn open(
        program: impl Into<std::path::PathBuf>,
        key_file: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        let program = program.into();
        let key_file = key_file.into();
        let out = run_helper(&program, &["public".as_ref(), key_file.as_os_str()], None)?;
        let point = b64::decode(out.trim())?;
        let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| {
            SeedError::Malformed("the key helper returned an invalid public key".into())
        })?;
        Ok(ExternalSigner {
            did: did_for(&key),
            program,
            key_file,
        })
    }
}

impl Signer for ExternalSigner {
    fn did(&self) -> String {
        self.did.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let out = run_helper(
            &self.program,
            &["sign".as_ref(), self.key_file.as_os_str()],
            Some(message),
        )?;
        let signature = b64::decode(out.trim())?;
        // Never hand on a signature the key did not make.
        verify(&self.did, message, &signature)?;
        Ok(signature)
    }
}

fn run_helper(
    program: &std::path::Path,
    args: &[&std::ffi::OsStr],
    input: Option<&[u8]>,
) -> Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            SeedError::Io(format!(
                "cannot start key helper {}: {e}",
                program.display()
            ))
        })?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        if let Some(bytes) = input {
            stdin.write_all(bytes)?;
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(SeedError::Io(format!(
            "key helper failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| SeedError::Malformed("key helper output is not text".into()))
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
        let sig = key.sign(b"hello").unwrap();
        verify(&did, b"hello", &sig).unwrap();
        assert!(verify(&did, b"hellO", &sig).is_err());
        let restored = SoftwareKey::from_secret(&key.export_secret()).unwrap();
        assert_eq!(restored.did(), did);
    }
}
