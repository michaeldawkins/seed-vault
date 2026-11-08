//! What an agent sends to a door: the challenge answer, the request and the
//! card chain, all signed by its short-lived working key.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keys::Signer;
use crate::{jws, Result, SeedError};

pub const PRESENTATION_MEDIA_TYPE: &str = "seed-presentation+jwt";

/// The door's one-time question. Its name (`audience`) is signed into the answer,
/// so an answer cannot be replayed at a different door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
}

/// What the agent wants to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// A short action name, such as `draft_invoice`.
    pub action: String,
    /// The organisation whose books it wants to touch.
    pub organisation: String,
    /// The amount involved, in euro cents, if any. Checked against the mandate's limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<i64>,
    /// The action's input. Passed to the action; never copied into receipts.
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresentationPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub nonce: String,
    pub aud: String,
    pub iat: DateTime<Utc>,
    pub request: Request,
    /// Signed cards: working key card(s), mandate card, agent identity card.
    pub cards: Vec<String>,
}

/// Answer a challenge. `cards` is the chain from the holder.
pub fn present(
    working_key: &dyn Signer,
    nonce: &str,
    audience: &str,
    request: Request,
    cards: Vec<String>,
    now: DateTime<Utc>,
) -> Result<String> {
    let payload = PresentationPayload {
        kind: "SeedPresentation".into(),
        nonce: nonce.into(),
        aud: audience.into(),
        iat: now,
        request,
        cards,
    };
    jws::sign(
        working_key,
        PRESENTATION_MEDIA_TYPE,
        &serde_json::to_value(payload)?,
    )
}

/// Check the presentation's own signature. Returns the signer and the payload.
pub fn open(token: &str) -> Result<(String, PresentationPayload)> {
    let verified = jws::verify(token)?;
    if verified.typ != PRESENTATION_MEDIA_TYPE {
        return Err(SeedError::Malformed("not a presentation".into()));
    }
    Ok((verified.signer, serde_json::from_value(verified.payload)?))
}
