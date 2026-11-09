//! The holder side: the owner's vault with their agents, mandates, withdrawal
//! list and receipts, saved as one JSON file.
//!
//! Keys in this file are software keys. That is fine for a demo and for tests.
//! It is NOT fine for real use: the design requires the owner key on the phone's
//! security chip and agent keys in the Secure Enclave, TPM or a KMS. The
//! [`crate::keys::Signer`] trait is where those plug in.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::cards::{
    Accountable, AgentSubject, Card, CardKind, Limits, MandateSubject, OwnerSubject, StatusEntry,
    WorkingKeySubject,
};
use crate::keys::{Signer, SoftwareKey};
use crate::presentation::{self, Challenge, Request};
use crate::receipt::{Receipt, SignedReceipt};
use crate::status::{self, StatusList};
use crate::{Result, SeedError};

/// How long a signed withdrawal list stays valid before the owner must re-sign it.
pub const STATUS_LIST_DAYS: i64 = 30;
/// Default lifetime of a working key.
pub const WORKING_KEY_HOURS: i64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Owner {
    pub did: String,
    /// Software key. Real use needs a hardware key; see the module notes.
    pub secret: String,
    pub name: String,
    pub country: String,
    pub law: String,
    pub identity_card: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateEntry {
    pub id: String,
    pub card: String,
    pub status_index: usize,
    pub withdrawn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub name: String,
    pub did: String,
    /// Software key, if this vault holds it. `None` once the key lives in hardware.
    pub secret: Option<String>,
    pub identity_card: String,
    pub identity_status_index: usize,
    pub mandates: Vec<MandateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub format: String,
    pub owner: Owner,
    pub status_list_url: String,
    pub status_list: String,
    pub status_list_card: String,
    pub next_status_index: usize,
    pub agents: Vec<Agent>,
    pub receipts: Vec<SignedReceipt>,
}

/// The terms of a new mandate, before signing.
#[derive(Debug, Clone)]
pub struct MandateTerms {
    pub organisation: String,
    pub may_do: Vec<String>,
    pub may_never: Vec<String>,
    pub limits: Limits,
    pub purpose: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl Vault {
    pub fn create(
        name: &str,
        country: &str,
        law: &str,
        status_list_url: &str,
        now: DateTime<Utc>,
    ) -> Result<Vault> {
        let key = SoftwareKey::generate();
        let did = key.did();
        let subject = OwnerSubject {
            id: did.clone(),
            name: name.into(),
            country: country.into(),
            law: law.into(),
        };
        let identity = Card::new(
            CardKind::OwnerIdentity,
            &did,
            now,
            now + Duration::days(365 * 3),
            &subject,
            None,
        )?;
        let list = StatusList::default();
        let mut vault = Vault {
            format: "seed-vault.v1".into(),
            owner: Owner {
                did,
                secret: key.export_secret(),
                name: name.into(),
                country: country.into(),
                law: law.into(),
                identity_card: identity.sign(&key)?,
            },
            status_list_url: status_list_url.into(),
            status_list: list.encode(),
            status_list_card: String::new(),
            next_status_index: 0,
            agents: Vec::new(),
            receipts: Vec::new(),
        };
        vault.resign_status_list(now)?;
        Ok(vault)
    }

    pub fn owner_key(&self) -> Result<SoftwareKey> {
        SoftwareKey::from_secret(&self.owner.secret)
    }

    fn take_status_index(&mut self) -> usize {
        let index = self.next_status_index;
        self.next_status_index += 1;
        index
    }

    /// Re-sign the withdrawal list (after a withdrawal, or before it expires).
    pub fn resign_status_list(&mut self, now: DateTime<Utc>) -> Result<()> {
        let list = StatusList::decode(&self.status_list)?;
        self.status_list_card = status::sign_list(
            &self.owner_key()?,
            &self.status_list_url,
            &list,
            now - Duration::minutes(1),
            now + Duration::days(STATUS_LIST_DAYS),
        )?;
        Ok(())
    }

    /// Add one of the owner's own agents, with a new key and an identity card.
    pub fn add_agent(
        &mut self,
        name: &str,
        built_by: &str,
        model: &str,
        machine: &str,
        now: DateTime<Utc>,
    ) -> Result<&Agent> {
        if self.agents.iter().any(|a| a.name == name) {
            return Err(SeedError::Invalid(format!(
                "there is already an agent called '{name}'"
            )));
        }
        let key = SoftwareKey::generate();
        let index = self.take_status_index();
        let subject = AgentSubject {
            id: key.did(),
            name: name.into(),
            acts_for: self.owner.did.clone(),
            built_by: built_by.into(),
            model: model.into(),
            machine: machine.into(),
        };
        let card = Card::new(
            CardKind::AgentIdentity,
            &self.owner.did,
            now,
            now + Duration::days(365),
            &subject,
            Some(StatusEntry::revocation(&self.status_list_url, index)),
        )?;
        let identity_card = card.sign(&self.owner_key()?)?;
        self.agents.push(Agent {
            name: name.into(),
            did: key.did(),
            secret: Some(key.export_secret()),
            identity_card,
            identity_status_index: index,
            mandates: Vec::new(),
        });
        Ok(self.agents.last().expect("just pushed"))
    }

    /// Add an agent whose key lives elsewhere (Secure Enclave, TPM, KMS).
    /// The vault learns only its identifier and never holds its private key.
    pub fn add_external_agent(
        &mut self,
        name: &str,
        agent_did: &str,
        built_by: &str,
        model: &str,
        machine: &str,
        now: DateTime<Utc>,
    ) -> Result<&Agent> {
        crate::keys::resolve(agent_did)?;
        if self.agents.iter().any(|a| a.name == name) {
            return Err(SeedError::Invalid(format!(
                "there is already an agent called '{name}'"
            )));
        }
        let index = self.take_status_index();
        let subject = AgentSubject {
            id: agent_did.into(),
            name: name.into(),
            acts_for: self.owner.did.clone(),
            built_by: built_by.into(),
            model: model.into(),
            machine: machine.into(),
        };
        let card = Card::new(
            CardKind::AgentIdentity,
            &self.owner.did,
            now,
            now + Duration::days(365),
            &subject,
            Some(StatusEntry::revocation(&self.status_list_url, index)),
        )?;
        let identity_card = card.sign(&self.owner_key()?)?;
        self.agents.push(Agent {
            name: name.into(),
            did: agent_did.into(),
            secret: None,
            identity_card,
            identity_status_index: index,
            mandates: Vec::new(),
        });
        Ok(self.agents.last().expect("just pushed"))
    }

    /// Everything one agent needs to visit doors, and nothing more: its
    /// identity card and its live mandates. No owner key, no other agents.
    pub fn export_kit(&self, name: &str, now: DateTime<Utc>) -> Result<AgentKit> {
        let agent = self.agent(name)?;
        Ok(AgentKit {
            format: "seed-agent-kit.v1".into(),
            agent: agent.name.clone(),
            agent_did: agent.did.clone(),
            owner_did: self.owner.did.clone(),
            identity_card: agent.identity_card.clone(),
            mandates: agent
                .mandates
                .iter()
                .filter(|m| !m.withdrawn)
                .map(|m| KitMandate {
                    id: m.id.clone(),
                    card: m.card.clone(),
                })
                .collect(),
            exported_at: now,
        })
    }

    pub fn agent(&self, name: &str) -> Result<&Agent> {
        self.agents
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| SeedError::NotFound(format!("no agent called '{name}'")))
    }

    /// Sign a mandate card for one agent.
    pub fn issue_mandate(&mut self, agent_name: &str, terms: MandateTerms) -> Result<MandateEntry> {
        let agent_did = self.agent(agent_name)?.did.clone();
        let subject = MandateSubject {
            id: agent_did,
            answers_for: Accountable {
                name: self.owner.name.clone(),
                country: self.owner.country.clone(),
                law: self.owner.law.clone(),
            },
            on_behalf_of: terms.organisation,
            may_do: terms.may_do,
            may_never: terms.may_never,
            limits: terms.limits,
            purpose: terms.purpose,
            can_pass_on: false,
        };
        subject.check()?;
        let index = self.take_status_index();
        let card = Card::new(
            CardKind::Mandate,
            &self.owner.did,
            terms.valid_from,
            terms.valid_until,
            &subject,
            Some(StatusEntry::revocation(&self.status_list_url, index)),
        )?;
        let entry = MandateEntry {
            id: card.id.clone(),
            card: card.sign(&self.owner_key()?)?,
            status_index: index,
            withdrawn: false,
        };
        self.agents
            .iter_mut()
            .find(|a| a.name == agent_name)
            .expect("checked above")
            .mandates
            .push(entry.clone());
        Ok(entry)
    }

    /// The kill switch: put a mandate on the withdrawal list and re-sign it.
    /// Receivers see it on their next check.
    pub fn withdraw(&mut self, mandate_id: &str, now: DateTime<Utc>) -> Result<()> {
        let entry = self
            .agents
            .iter_mut()
            .flat_map(|a| a.mandates.iter_mut())
            .find(|m| m.id == mandate_id || m.id.ends_with(mandate_id))
            .ok_or_else(|| SeedError::NotFound(format!("no mandate '{mandate_id}'")))?;
        entry.withdrawn = true;
        let index = entry.status_index;
        let mut list = StatusList::decode(&self.status_list)?;
        list.set(index, true)?;
        self.status_list = list.encode();
        self.resign_status_list(now)
    }

    /// Find a mandate by its full id or the end of it.
    pub fn mandate(&self, mandate_id: &str) -> Result<(&Agent, &MandateEntry)> {
        self.agents
            .iter()
            .flat_map(|a| a.mandates.iter().map(move |m| (a, m)))
            .find(|(_, m)| m.id == mandate_id || m.id.ends_with(mandate_id))
            .ok_or_else(|| SeedError::NotFound(format!("no mandate '{mandate_id}'")))
    }

    /// The agent's side: make a short-lived working key for one mandate.
    /// The working key lives only in memory.
    pub fn working_key(
        &self,
        mandate_id: &str,
        hours: i64,
        now: DateTime<Utc>,
    ) -> Result<(SoftwareKey, String)> {
        let (agent, mandate) = self.mandate(mandate_id)?;
        let secret = agent.secret.as_ref().ok_or_else(|| {
            SeedError::Invalid(
                "this agent's key is not in this vault; ask the agent's own signer".into(),
            )
        })?;
        let agent_key = SoftwareKey::from_secret(secret)?;
        working_key_for(&agent_key, &mandate.id, hours, now)
    }

    /// The cards an agent shows at a door, apart from its working key card.
    pub fn chain(&self, mandate_id: &str) -> Result<Vec<String>> {
        let (agent, mandate) = self.mandate(mandate_id)?;
        Ok(vec![mandate.card.clone(), agent.identity_card.clone()])
    }

    /// Answer a door's challenge in one step (working key, chain, signature).
    pub fn answer(
        &self,
        mandate_id: &str,
        challenge: &Challenge,
        request: Request,
        now: DateTime<Utc>,
    ) -> Result<String> {
        let (key, card) = self.working_key(mandate_id, WORKING_KEY_HOURS, now)?;
        let mut cards = vec![card];
        cards.extend(self.chain(mandate_id)?);
        presentation::present(
            &key,
            &challenge.nonce,
            &challenge.audience,
            request,
            cards,
            now,
        )
    }

    /// Keep the door's copy of a receipt, after checking the door signed it.
    pub fn keep_receipt(&mut self, receipt: SignedReceipt) -> Result<()> {
        let (_, checked) = Receipt::verify(&receipt.signed)?;
        if checked != receipt.receipt {
            return Err(SeedError::BadSignature(
                "receipt does not match its signature".into(),
            ));
        }
        self.receipts.push(receipt);
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Vault> {
        let vault: Vault = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if vault.format != "seed-vault.v1" {
            return Err(SeedError::Malformed(format!(
                "unknown vault format '{}'",
                vault.format
            )));
        }
        Ok(vault)
    }
}

/// An agent key signs a working key card for a fresh in-memory key.
pub fn working_key_for(
    agent_key: &dyn Signer,
    mandate_id: &str,
    hours: i64,
    now: DateTime<Utc>,
) -> Result<(SoftwareKey, String)> {
    let working = SoftwareKey::generate();
    let card = Card::new(
        CardKind::WorkingKey,
        &agent_key.did(),
        now - Duration::seconds(5),
        now + Duration::hours(hours),
        &WorkingKeySubject {
            id: working.did(),
            mandate: mandate_id.into(),
        },
        None,
    )?;
    let token = card.sign(agent_key)?;
    Ok((working, token))
}

/// One mandate inside an agent kit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitMandate {
    pub id: String,
    pub card: String,
}

/// What travels to the agent's machine: its identity card and live mandates.
/// It holds no secret at all. The agent key stays in its hardware signer and
/// the owner key stays in the owner's vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKit {
    pub format: String,
    pub agent: String,
    pub agent_did: String,
    pub owner_did: String,
    pub identity_card: String,
    pub mandates: Vec<KitMandate>,
    pub exported_at: DateTime<Utc>,
}

impl AgentKit {
    /// Find a mandate by its full id or the end of it.
    pub fn mandate(&self, mandate_id: &str) -> Result<&KitMandate> {
        self.mandates
            .iter()
            .find(|m| m.id == mandate_id || m.id.ends_with(mandate_id))
            .ok_or_else(|| SeedError::NotFound(format!("no mandate '{mandate_id}' in this kit")))
    }

    /// Answer a door's challenge with a hardware (or any other) agent signer.
    pub fn answer(
        &self,
        agent_key: &dyn Signer,
        mandate_id: &str,
        challenge: &Challenge,
        request: Request,
        now: DateTime<Utc>,
    ) -> Result<String> {
        if agent_key.did() != self.agent_did {
            return Err(SeedError::Invalid(format!(
                "this signer is {}, but the kit belongs to {}",
                agent_key.did(),
                self.agent_did
            )));
        }
        let mandate = self.mandate(mandate_id)?;
        let (key, card) = working_key_for(agent_key, &mandate.id, WORKING_KEY_HOURS, now)?;
        let cards = vec![card, mandate.card.clone(), self.identity_card.clone()];
        presentation::present(
            &key,
            &challenge.nonce,
            &challenge.audience,
            request,
            cards,
            now,
        )
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<AgentKit> {
        let kit: AgentKit = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if kit.format != "seed-agent-kit.v1" {
            return Err(SeedError::Malformed(format!(
                "unknown agent kit format '{}'",
                kit.format
            )));
        }
        Ok(kit)
    }
}
