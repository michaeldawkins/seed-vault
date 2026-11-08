//! An in-memory door environment: the reference implementation the
//! conformance cases run against, and the engine behind `seed demo`.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, NaiveDate, Utc};

use crate::door::DoorStores;
use crate::presentation::Challenge;
use crate::receipt::SignedReceipt;

#[derive(Default)]
pub struct MemoryStores {
    pub challenges: HashMap<String, (Challenge, bool)>,
    pub known_owners: HashSet<String>,
    pub acceptances: HashSet<(String, String)>,
    pub uses: HashMap<(String, String, NaiveDate), u32>,
    pub status_lists: HashMap<String, String>,
    pub unreachable: HashSet<String>,
    pub receipts: Vec<SignedReceipt>,
}

impl DoorStores for MemoryStores {
    fn save_challenge(&mut self, challenge: &Challenge) {
        self.challenges
            .insert(challenge.nonce.clone(), (challenge.clone(), false));
    }

    fn consume_challenge(&mut self, nonce: &str, audience: &str, now: DateTime<Utc>) -> bool {
        match self.challenges.get_mut(nonce) {
            Some((challenge, used))
                if !*used && challenge.audience == audience && now <= challenge.expires_at =>
            {
                *used = true;
                true
            }
            _ => false,
        }
    }

    fn is_known_owner(&self, owner: &str) -> bool {
        self.known_owners.contains(owner)
    }

    fn organisation_accepts(&self, organisation: &str, owner: &str) -> bool {
        self.acceptances
            .contains(&(organisation.to_string(), owner.to_string()))
    }

    fn uses_on(&self, mandate: &str, action: &str, day: NaiveDate) -> u32 {
        *self
            .uses
            .get(&(mandate.to_string(), action.to_string(), day))
            .unwrap_or(&0)
    }

    fn record_use(&mut self, mandate: &str, action: &str, day: NaiveDate) {
        *self
            .uses
            .entry((mandate.to_string(), action.to_string(), day))
            .or_default() += 1;
    }

    fn fetch_status_list(&self, url: &str) -> Option<String> {
        if self.unreachable.contains(url) {
            return None;
        }
        self.status_lists.get(url).cloned()
    }

    fn save_receipt(&mut self, receipt: &SignedReceipt) {
        self.receipts.push(receipt.clone());
    }
}
