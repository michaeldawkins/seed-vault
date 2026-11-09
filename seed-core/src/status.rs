//! Withdrawal lists, following the W3C Bitstring Status List: one bit per
//! card, GZIP-compressed, multibase base64url (prefix `u`).

use std::io::{Read, Write};

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use crate::cards::{Card, CardKind};
use crate::keys::Signer;
use crate::{b64, Result, SeedError};

/// The spec's minimum list size (16 KB), which hides how many cards exist.
pub const MIN_BITS: usize = 131_072;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    bytes: Vec<u8>,
}

impl Default for StatusList {
    fn default() -> Self {
        StatusList {
            bytes: vec![0; MIN_BITS / 8],
        }
    }
}

impl StatusList {
    pub fn len(&self) -> usize {
        self.bytes.len() * 8
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Bit order: index 0 is the left-most bit of the first byte.
    pub fn get(&self, index: usize) -> Result<bool> {
        let byte = self
            .bytes
            .get(index / 8)
            .ok_or_else(|| SeedError::Invalid("status index is outside the list".into()))?;
        Ok(byte & (0x80 >> (index % 8)) != 0)
    }

    pub fn set(&mut self, index: usize, withdrawn: bool) -> Result<()> {
        let byte = self
            .bytes
            .get_mut(index / 8)
            .ok_or_else(|| SeedError::Invalid("status index is outside the list".into()))?;
        if withdrawn {
            *byte |= 0x80 >> (index % 8);
        } else {
            *byte &= !(0x80 >> (index % 8));
        }
        Ok(())
    }

    pub fn encode(&self) -> String {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&self.bytes).expect("in-memory gzip");
        format!("u{}", b64::encode(&gz.finish().expect("in-memory gzip")))
    }

    pub fn decode(text: &str) -> Result<StatusList> {
        let body = text
            .strip_prefix('u')
            .ok_or_else(|| SeedError::Malformed("encoded list must start with 'u'".into()))?;
        let mut bytes = Vec::new();
        GzDecoder::new(&b64::decode(body)?[..])
            .read_to_end(&mut bytes)
            .map_err(|_| SeedError::Malformed("encoded list is not gzip".into()))?;
        Ok(StatusList { bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusListSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub status_purpose: String,
    pub encoded_list: String,
}

/// Sign a withdrawal list as a card. Its `id` is the address receivers fetch.
pub fn sign_list(
    signer: &dyn Signer,
    url: &str,
    list: &StatusList,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Result<String> {
    let subject = StatusListSubject {
        id: format!("{url}#list"),
        kind: "BitstringStatusList".into(),
        status_purpose: "revocation".into(),
        encoded_list: list.encode(),
    };
    let mut card = Card::new(
        CardKind::StatusList,
        &signer.did(),
        valid_from,
        valid_until,
        &subject,
        None,
    )?;
    card.id = url.into();
    card.sign(signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_survive_encoding() {
        let mut list = StatusList::default();
        list.set(0, true).unwrap();
        list.set(4242, true).unwrap();
        let decoded = StatusList::decode(&list.encode()).unwrap();
        assert!(decoded.get(0).unwrap());
        assert!(decoded.get(4242).unwrap());
        assert!(!decoded.get(4243).unwrap());
        assert_eq!(decoded.len(), MIN_BITS);
    }
}
