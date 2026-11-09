//! Receipts: who did what, under which mandate, when, and the outcome.
//! Receipts name the action and a record identifier, never the content.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::Signer;
use crate::{jws, Result, SeedError};

pub const RECEIPT_MEDIA_TYPE: &str = "seed-receipt+jwt";
pub const POLICY_VERSION: &str = "seed-door.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every check passed and the action ran.
    Allowed,
    /// A check failed; nothing ran.
    Refused,
    /// Every check passed but the action itself failed; nothing was changed.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Parties {
    pub owner: Option<String>,
    pub agent: Option<String>,
    pub working_key: Option<String>,
    pub mandate: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub at: DateTime<Utc>,
    pub door: String,
    pub outcome: Outcome,
    /// For a refusal or failure: the machine name of the check that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_check: Option<String>,
    /// Plain-language reason.
    pub reason: String,
    pub action: Option<String>,
    pub organisation: Option<String>,
    /// The identifier of the record created or read, never its content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    pub parties: Parties,
    pub policy_version: String,
}

/// A receipt plus the door's signature over it, so the agent's side can keep a
/// copy that proves what the door decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signed: String,
}

impl Receipt {
    pub fn sign(self, door_key: &dyn Signer) -> Result<SignedReceipt> {
        let signed = jws::sign(door_key, RECEIPT_MEDIA_TYPE, &serde_json::to_value(&self)?)?;
        Ok(SignedReceipt {
            receipt: self,
            signed,
        })
    }

    /// Check a receipt the door handed over. Returns it with the door's key identifier.
    pub fn verify(token: &str) -> Result<(String, Receipt)> {
        let verified = jws::verify(token)?;
        if verified.typ != RECEIPT_MEDIA_TYPE {
            return Err(SeedError::Malformed("not a receipt".into()));
        }
        Ok((verified.signer, serde_json::from_value(verified.payload)?))
    }
}
