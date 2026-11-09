//! Compact JWS with ES256. The signer is named in `kid` as `did:key:…#…`.

use serde_json::{json, Value};

use crate::keys::{self, Signer};
use crate::{b64, Result, SeedError};

/// Sign `payload` as a compact JWS. `typ` names the media type, such as `vc+jwt`.
pub fn sign(signer: &dyn Signer, typ: &str, payload: &Value) -> Result<String> {
    let did = signer.did();
    let fragment = did.trim_start_matches("did:key:");
    let header = json!({"alg": "ES256", "typ": typ, "kid": format!("{did}#{fragment}")});
    let signing_input = format!(
        "{}.{}",
        b64::encode(serde_json::to_string(&header)?.as_bytes()),
        b64::encode(serde_json::to_string(payload)?.as_bytes())
    );
    let signature = signer.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64::encode(&signature)))
}

/// A JWS whose signature has been checked.
#[derive(Debug, Clone)]
pub struct Verified {
    pub typ: String,
    pub signer: String,
    pub payload: Value,
}

/// Check the signature and return who signed and what.
pub fn verify(token: &str) -> Result<Verified> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SeedError::Malformed(
            "a signed card has three dot-separated parts".into(),
        ));
    };
    let header: Value = serde_json::from_slice(&b64::decode(h)?)?;
    if header["alg"] != "ES256" {
        return Err(SeedError::Malformed(
            "only ES256 signatures are accepted".into(),
        ));
    }
    let kid = header["kid"]
        .as_str()
        .ok_or_else(|| SeedError::Malformed("signature names no key".into()))?;
    let signer = kid.split('#').next().unwrap_or_default().to_string();
    keys::verify(&signer, format!("{h}.{p}").as_bytes(), &b64::decode(s)?)?;
    let payload: Value = serde_json::from_slice(&b64::decode(p)?)?;
    Ok(Verified {
        typ: header["typ"].as_str().unwrap_or_default().to_string(),
        signer,
        payload,
    })
}
