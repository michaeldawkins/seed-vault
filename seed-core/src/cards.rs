//! The cards. Each is a W3C Verifiable Credential (data model 2.0), secured as
//! a compact JWS with media type `vc+jwt`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keys::Signer;
use crate::{jws, Result, SeedError};

pub const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const SEED_CONTEXT: &str = "https://beingexponential.com/ns/seed/v1";
pub const CARD_MEDIA_TYPE: &str = "vc+jwt";

/// Actions no mandate can ever grant. Money needs a second, human signature
/// through Ledger Desk's own approval channel; an agent key alone never moves it.
pub const NEVER_GRANTABLE: &[&str] = &[
    "pay_invoice",
    "send_payment",
    "release_payment",
    "change_bank_details",
    "issue_cards",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardKind {
    OwnerIdentity,
    AgentIdentity,
    Mandate,
    WorkingKey,
    StatusList,
}

impl CardKind {
    pub fn type_name(self) -> &'static str {
        match self {
            CardKind::OwnerIdentity => "SeedOwnerIdentityCard",
            CardKind::AgentIdentity => "SeedAgentIdentityCard",
            CardKind::Mandate => "SeedMandateCard",
            CardKind::WorkingKey => "SeedWorkingKeyCard",
            CardKind::StatusList => "BitstringStatusListCredential",
        }
    }

    pub fn plain(self) -> &'static str {
        match self {
            CardKind::OwnerIdentity => "owner identity card",
            CardKind::AgentIdentity => "agent identity card",
            CardKind::Mandate => "mandate card",
            CardKind::WorkingKey => "working key card",
            CardKind::StatusList => "withdrawal list",
        }
    }

    const ALL: [CardKind; 5] = [
        CardKind::OwnerIdentity,
        CardKind::AgentIdentity,
        CardKind::Mandate,
        CardKind::WorkingKey,
        CardKind::StatusList,
    ];
}

/// Where to look up whether a card has been withdrawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub status_purpose: String,
    pub status_list_index: String,
    pub status_list_credential: String,
}

impl StatusEntry {
    pub fn revocation(list_url: &str, index: usize) -> Self {
        StatusEntry {
            id: format!("{list_url}#{index}"),
            kind: "BitstringStatusListEntry".into(),
            status_purpose: "revocation".into(),
            status_list_index: index.to_string(),
            status_list_credential: list_url.into(),
        }
    }

    pub fn index(&self) -> Result<usize> {
        self.status_list_index
            .parse()
            .map_err(|_| SeedError::Malformed("status list index is not a number".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub credential_subject: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<StatusEntry>,
}

impl Card {
    pub fn new(
        kind: CardKind,
        issuer: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        subject: &impl Serialize,
        status: Option<StatusEntry>,
    ) -> Result<Card> {
        if valid_until <= valid_from {
            return Err(SeedError::Invalid("a card must end after it starts".into()));
        }
        Ok(Card {
            context: vec![VC_CONTEXT.into(), SEED_CONTEXT.into()],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            types: vec!["VerifiableCredential".into(), kind.type_name().into()],
            issuer: issuer.into(),
            valid_from,
            valid_until,
            credential_subject: serde_json::to_value(subject)?,
            credential_status: status,
        })
    }

    pub fn kind(&self) -> Option<CardKind> {
        CardKind::ALL
            .into_iter()
            .find(|k| self.types.iter().any(|t| t == k.type_name()))
    }

    pub fn subject_id(&self) -> &str {
        self.credential_subject["id"].as_str().unwrap_or_default()
    }

    pub fn subject<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        Ok(serde_json::from_value(self.credential_subject.clone())?)
    }

    /// Sign this card. The signer must be the issuer.
    pub fn sign(&self, signer: &dyn Signer) -> Result<String> {
        if signer.did() != self.issuer {
            return Err(SeedError::Invalid("only the issuer can sign a card".into()));
        }
        jws::sign(signer, CARD_MEDIA_TYPE, &serde_json::to_value(self)?)
    }

    /// Check a signed card: the signature is real and was made by the named issuer.
    pub fn verify(token: &str) -> Result<Card> {
        let verified = jws::verify(token)?;
        if verified.typ != CARD_MEDIA_TYPE {
            return Err(SeedError::Malformed("not a signed card".into()));
        }
        let card: Card = serde_json::from_value(verified.payload)?;
        if card.issuer != verified.signer {
            return Err(SeedError::BadSignature(
                "card was signed by someone other than its issuer".into(),
            ));
        }
        Ok(card)
    }
}

/// "This key is Michael."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSubject {
    pub id: String,
    pub name: String,
    pub country: String,
    pub law: String,
}

/// "This agent key belongs to an agent of Michael's."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSubject {
    pub id: String,
    pub name: String,
    pub acts_for: String,
    pub built_by: String,
    pub model: String,
    pub machine: String,
}

/// Who answers for an agent: "No accountable principal, no entry."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Accountable {
    pub name: String,
    pub country: String,
    pub law: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// At most this many uses of each allowed action per calendar day (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_day: Option<u32>,
    /// No single action above this amount, in euro cents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_cents: Option<i64>,
}

/// What the agent may do, for whom, within which limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MandateSubject {
    pub id: String,
    pub answers_for: Accountable,
    pub on_behalf_of: String,
    pub may_do: Vec<String>,
    pub may_never: Vec<String>,
    pub limits: Limits,
    pub purpose: String,
    pub can_pass_on: bool,
}

impl MandateSubject {
    /// The rules a mandate must meet before anyone signs it.
    pub fn check(&self) -> Result<()> {
        if self.may_do.is_empty() {
            return Err(SeedError::Invalid(
                "a mandate must allow at least one action".into(),
            ));
        }
        if self.purpose.trim().is_empty() {
            return Err(SeedError::Invalid(
                "a mandate must state its purpose".into(),
            ));
        }
        if self.on_behalf_of.trim().is_empty() {
            return Err(SeedError::Invalid(
                "a mandate must name the organisation".into(),
            ));
        }
        if let Some(a) = self.may_do.iter().find(|a| self.may_never.contains(a)) {
            return Err(SeedError::Invalid(format!(
                "'{a}' is both allowed and forbidden"
            )));
        }
        if let Some(a) = self
            .may_do
            .iter()
            .find(|a| NEVER_GRANTABLE.contains(&a.as_str()))
        {
            return Err(SeedError::Invalid(format!(
                "'{a}' can never be granted to an agent: money and card issuing need a human"
            )));
        }
        if self.can_pass_on {
            return Err(SeedError::Invalid(
                "passing rights on to other agents is not supported in this version".into(),
            ));
        }
        Ok(())
    }
}

/// "This short-lived key acts for me, within my mandate, for a few hours."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkingKeySubject {
    pub id: String,
    pub mandate: String,
}

/// Parse a signed card and require a particular kind.
pub fn verify_kind(token: &str, kind: CardKind) -> Result<Card> {
    let card = Card::verify(token)?;
    if card.kind() != Some(kind) {
        return Err(SeedError::Malformed(format!("expected a {}", kind.plain())));
    }
    Ok(card)
}
