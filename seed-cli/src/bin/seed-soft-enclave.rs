//! A stand-in for the Secure Enclave helper, for tests and for machines
//! without a security chip. It speaks exactly the same protocol as
//! `enclave/seed-enclave.swift`, but its key file holds a SOFTWARE key.
//! Never use it for an agent that matters.
//!
//!   seed-soft-enclave create KEY_FILE   make a key, print its public key
//!   seed-soft-enclave public KEY_FILE   print the public key
//!   seed-soft-enclave sign KEY_FILE     sign stdin, print the signature
//!
//! Public key: base64url of the 65-byte uncompressed P-256 point.
//! Signature: base64url of the raw 64-byte ES256 signature (r || s).

use std::io::Read;
use std::process::ExitCode;

use seed_core::b64;
use seed_core::keys::{Signer, SoftwareKey};

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("seed-soft-enclave: {e}");
            ExitCode::FAILURE
        }
    }
}

fn public(key: &SoftwareKey) -> String {
    b64::encode(key.verifying_key().to_encoded_point(false).as_bytes())
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, file) = match args.as_slice() {
        [c, f] => (c.as_str(), f.as_str()),
        _ => return Err("usage: seed-soft-enclave create|public|sign KEY_FILE".into()),
    };
    let load = || -> Result<SoftwareKey, String> {
        let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
        SoftwareKey::from_secret(text.trim()).map_err(|e| e.to_string())
    };
    match command {
        "create" => {
            if std::path::Path::new(file).exists() {
                return Err(format!("{file} already exists; not overwriting a key"));
            }
            let key = SoftwareKey::generate();
            std::fs::write(file, key.export_secret()).map_err(|e| e.to_string())?;
            Ok(public(&key))
        }
        "public" => Ok(public(&load()?)),
        "sign" => {
            let key = load()?;
            let mut message = Vec::new();
            std::io::stdin()
                .read_to_end(&mut message)
                .map_err(|e| e.to_string())?;
            Ok(b64::encode(&key.sign(&message).map_err(|e| e.to_string())?))
        }
        other => Err(format!("unknown command '{other}'")),
    }
}
