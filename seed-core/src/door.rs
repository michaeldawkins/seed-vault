//! The door: checks a card chain before an agent may act, then writes a receipt.
//!
//! Check order (stops at the first failure):
//!  1. signature      every signature is real
//!  2. audience       the answer was meant for this door
//!  3. challenge      the one-time number is fresh and unused (no replay)
//!  4. chain          working key → agent key → owner links up, and the owner is known
//!     (a working key that signs another working key is "cannot_pass_on")
//!  5. time           nothing has expired or is not yet valid
//!  6. withdrawal     nothing is on its owner's withdrawal list (unreachable list: refuse)
//!  7. action         the action is in "may do", not in "may never", for this organisation
//!  8. limits         the daily count and amount limits are not used up
//!  9. acceptance     the organisation accepts this owner
//!
//! Steps 1 and 4 to 9 are the Slice 0 doc's checks 1 to 7. Steps 2 and 3 are the
//! challenge from its handshake, checked as soon as the signatures are known good.

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;

use crate::b64;
use crate::cards::{
    AgentSubject, Card, CardKind, MandateSubject, WorkingKeySubject, NEVER_GRANTABLE,
};
use crate::keys::Signer;
use crate::presentation::{self, Challenge, Request};
use crate::receipt::{Outcome, Parties, Receipt, SignedReceipt, POLICY_VERSION};
use crate::status::StatusList;

/// How far apart two clocks may be before the door stops trusting times.
pub const CLOCK_MARGIN_SECONDS: i64 = 30;
/// Actions that create a document with money in it. They must state their amount,
/// so the mandate's amount limit can be checked; the action runner must then
/// refuse when the real amount differs from the stated one.
pub const AMOUNT_ACTIONS: &[&str] = &["draft_invoice", "draft_quote", "draft_purchase"];
/// How long a challenge stays answerable.
pub const CHALLENGE_SECONDS: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Signature,
    Audience,
    Replay,
    Chain,
    CannotPassOn,
    Expired,
    NotYetValid,
    Withdrawn,
    CannotCheck,
    Forbidden,
    NotPermitted,
    WrongOrganisation,
    LimitReached,
    NotAccepted,
    ActionFailed,
}

impl Check {
    pub fn code(self) -> &'static str {
        match self {
            Check::Signature => "bad_signature",
            Check::Audience => "wrong_audience",
            Check::Replay => "replay",
            Check::Chain => "chain_broken",
            Check::CannotPassOn => "cannot_pass_on",
            Check::Expired => "expired",
            Check::NotYetValid => "not_yet_valid",
            Check::Withdrawn => "withdrawn",
            Check::CannotCheck => "cannot_check",
            Check::Forbidden => "forbidden",
            Check::NotPermitted => "not_permitted",
            Check::WrongOrganisation => "wrong_organisation",
            Check::LimitReached => "limit_reached",
            Check::NotAccepted => "not_accepted",
            Check::ActionFailed => "action_failed",
        }
    }

    pub fn plain(self) -> &'static str {
        match self {
            Check::Signature => "a signature is not real",
            Check::Audience => "the answer was meant for another door",
            Check::Replay => "the one-time number was already used, expired or never issued here",
            Check::Chain => "the chain does not lead back to a known owner",
            Check::CannotPassOn => "a working key tried to hand its rights to another key",
            Check::Expired => "a card has expired",
            Check::NotYetValid => "a card is not valid yet",
            Check::Withdrawn => "the owner has withdrawn a card",
            Check::CannotCheck => "the withdrawal list could not be checked, so the door says no",
            Check::Forbidden => "the action is on the 'may never' list",
            Check::NotPermitted => "the action is not on the 'may do' list",
            Check::WrongOrganisation => "the mandate is for another organisation",
            Check::LimitReached => "the mandate's limit is used up",
            Check::NotAccepted => "this organisation has not accepted this owner",
            Check::ActionFailed => "every check passed, but the action itself failed",
        }
    }
}

/// What a door needs from its surroundings. Ledger Desk implements this over
/// its own database; [`crate::reference::MemoryStores`] keeps it in memory.
pub trait DoorStores {
    fn save_challenge(&mut self, challenge: &Challenge);
    /// Mark a challenge used. True only if it was issued here, is unexpired and unused.
    fn consume_challenge(&mut self, nonce: &str, audience: &str, now: DateTime<Utc>) -> bool;
    fn is_known_owner(&self, owner: &str) -> bool;
    fn organisation_accepts(&self, organisation: &str, owner: &str) -> bool;
    fn uses_on(&self, mandate: &str, action: &str, day: NaiveDate) -> u32;
    fn record_use(&mut self, mandate: &str, action: &str, day: NaiveDate);
    /// Fetch a signed withdrawal list. `None` means it could not be reached.
    fn fetch_status_list(&self, url: &str) -> Option<String>;
    fn save_receipt(&mut self, receipt: &SignedReceipt);
}

/// A chain that passed every check.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub request: Request,
    pub owner: String,
    pub agent: String,
    pub working_key: String,
    pub mandate_id: String,
    pub mandate: MandateSubject,
}

#[derive(Debug, Clone)]
pub struct Refusal {
    pub check: Check,
    pub detail: String,
    pub request: Option<Request>,
    pub parties: Parties,
}

macro_rules! refusal {
    ($check:expr, $detail:expr, $request:expr, $parties:expr $(,)?) => {
        Refusal {
            check: $check,
            detail: $detail,
            request: Option::<&Request>::cloned($request),
            parties: $parties.clone(),
        }
    };
}

pub struct Door<S: DoorStores> {
    pub audience: String,
    key: Box<dyn Signer>,
    pub stores: S,
}

impl<S: DoorStores> Door<S> {
    pub fn new(audience: impl Into<String>, key: Box<dyn Signer>, stores: S) -> Self {
        Door {
            audience: audience.into(),
            key,
            stores,
        }
    }

    /// The door's own identifier, which signs receipts.
    pub fn did(&self) -> String {
        self.key.did()
    }

    /// Step 2 of the handshake: a one-time number and the door's name.
    pub fn challenge(&mut self, now: DateTime<Utc>) -> Challenge {
        let challenge = Challenge {
            nonce: b64::random_token(24),
            audience: self.audience.clone(),
            expires_at: now + Duration::seconds(CHALLENGE_SECONDS),
        };
        self.stores.save_challenge(&challenge);
        challenge
    }

    /// Steps 4 to 6: check, act through `act`, and write a receipt either way.
    /// `act` returns the identifier of the record it touched, or an error text.
    pub fn handle(
        &mut self,
        presentation: &str,
        now: DateTime<Utc>,
        act: impl FnOnce(&Admitted) -> Result<Option<String>, String>,
    ) -> SignedReceipt {
        let receipt = match self.admit(presentation, now) {
            Err(refusal) => self.receipt(
                now,
                Outcome::Refused,
                Some(refusal.check),
                format!("{}: {}", refusal.check.plain(), refusal.detail),
                refusal.request.as_ref(),
                None,
                refusal.parties,
            ),
            Ok(admitted) => {
                let parties = parties_of(&admitted);
                match act(&admitted) {
                    Ok(record) => {
                        self.stores.record_use(
                            &admitted.mandate_id,
                            &admitted.request.action,
                            now.date_naive(),
                        );
                        self.receipt(
                            now,
                            Outcome::Allowed,
                            None,
                            format!("allowed under the mandate: {}", admitted.mandate.purpose),
                            Some(&admitted.request),
                            record,
                            parties,
                        )
                    }
                    Err(error) => self.receipt(
                        now,
                        Outcome::Failed,
                        Some(Check::ActionFailed),
                        format!("{}: {error}", Check::ActionFailed.plain()),
                        Some(&admitted.request),
                        None,
                        parties,
                    ),
                }
            }
        };
        let signed = receipt
            .sign(self.key.as_ref())
            .expect("door key signs its receipts");
        self.stores.save_receipt(&signed);
        signed
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt(
        &self,
        now: DateTime<Utc>,
        outcome: Outcome,
        check: Option<Check>,
        reason: String,
        request: Option<&Request>,
        record: Option<String>,
        parties: Parties,
    ) -> Receipt {
        Receipt {
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            at: now,
            door: self.audience.clone(),
            outcome,
            failed_check: check.map(|c| c.code().to_string()),
            reason,
            action: request.map(|r| r.action.clone()),
            organisation: request.map(|r| r.organisation.clone()),
            record,
            parties,
            policy_version: POLICY_VERSION.into(),
        }
    }

    /// Run every check in order. Does not act and does not write a receipt.
    #[allow(clippy::result_large_err)]
    pub fn admit(&mut self, presentation: &str, now: DateTime<Utc>) -> Result<Admitted, Refusal> {
        let mut parties = Parties::default();

        // 1. Signatures.
        let (presenter, payload) = presentation::open(presentation).map_err(|e| {
            refusal!(
                Check::Signature,
                format!("presentation: {e}"),
                None,
                &parties
            )
        })?;
        let request = payload.request.clone();
        parties.working_key = Some(presenter.clone());
        let mut cards = Vec::new();
        for token in &payload.cards {
            let card = Card::verify(token)
                .map_err(|e| refusal!(Check::Signature, e.to_string(), Some(&request), &parties))?;
            cards.push(card);
        }

        // 2. Audience.
        if payload.aud != self.audience {
            return Err(refusal!(
                Check::Audience,
                format!(
                    "it names '{}', this door is '{}'",
                    payload.aud, self.audience
                ),
                Some(&request),
                &parties,
            ));
        }

        // 3. Challenge.
        if !self
            .stores
            .consume_challenge(&payload.nonce, &self.audience, now)
        {
            return Err(refusal!(
                Check::Replay,
                "ask for a new challenge".into(),
                Some(&request),
                &parties
            ));
        }

        // 4. Chain.
        let of_kind = |kind: CardKind| cards.iter().filter(move |c| c.kind() == Some(kind));
        let working_cards: Vec<&Card> = of_kind(CardKind::WorkingKey).collect();
        if working_cards.len() > 1 {
            return Err(refusal!(
                Check::CannotPassOn,
                "only the agent key may create working keys".into(),
                Some(&request),
                &parties,
            ));
        }
        let one = |kind: CardKind| -> Result<&Card, String> {
            let mut found = of_kind(kind);
            match (found.next(), found.next()) {
                (Some(card), None) => Ok(card),
                (None, _) => Err(format!("no {}", kind.plain())),
                _ => Err(format!("more than one {}", kind.plain())),
            }
        };
        macro_rules! bad {
            ($what:expr) => {
                refusal!(Check::Chain, $what.to_string(), Some(&request), &parties)
            };
        }
        let working = one(CardKind::WorkingKey).map_err(|e| bad!(e))?;
        let mandate_card = one(CardKind::Mandate).map_err(|e| bad!(e))?;
        let agent_card = one(CardKind::AgentIdentity).map_err(|e| bad!(e))?;
        let working_subject: WorkingKeySubject = working.subject().map_err(|e| bad!(e))?;
        let mandate: MandateSubject = mandate_card.subject().map_err(|e| bad!(e))?;
        let agent: AgentSubject = agent_card.subject().map_err(|e| bad!(e))?;
        if working_subject.id != presenter {
            return Err(bad!(
                "the presentation was not signed by the working key on the card"
            ));
        }
        if working_subject.mandate != mandate_card.id {
            return Err(bad!("the working key belongs to a different mandate"));
        }
        if agent.id != mandate.id {
            return Err(bad!(
                "the mandate is for a different agent than the identity card"
            ));
        }
        if working.issuer != agent.id {
            return Err(bad!(
                "the working key was not made by the agent named on the mandate"
            ));
        }
        parties.agent = Some(agent.id.clone());
        parties.mandate = Some(mandate_card.id.clone());
        if agent.acts_for != mandate_card.issuer || agent_card.issuer != mandate_card.issuer {
            return Err(bad!(
                "the agent identity and the mandate name different owners"
            ));
        }
        if !self.stores.is_known_owner(&mandate_card.issuer) {
            return Err(bad!(
                "the mandate was signed by a key this door does not know as an owner"
            ));
        }
        parties.owner = Some(mandate_card.issuer.clone());
        parties.purpose = Some(mandate.purpose.clone());

        // 5. Time.
        let margin = Duration::seconds(CLOCK_MARGIN_SECONDS);
        if (payload.iat - now).abs() > margin + Duration::seconds(CHALLENGE_SECONDS) {
            return Err(refusal!(
                Check::NotYetValid,
                "the clocks differ too much".into(),
                Some(&request),
                &parties
            ));
        }
        for card in [working, mandate_card, agent_card] {
            let label = card.kind().map(CardKind::plain).unwrap_or("card");
            if now + margin < card.valid_from {
                return Err(refusal!(
                    Check::NotYetValid,
                    format!(
                        "the {label} starts {}",
                        card.valid_from.format("%d-%m-%Y %H:%M UTC")
                    ),
                    Some(&request),
                    &parties,
                ));
            }
            if now - margin >= card.valid_until {
                return Err(refusal!(
                    Check::Expired,
                    format!(
                        "the {label} ended {}",
                        card.valid_until.format("%d-%m-%Y %H:%M UTC")
                    ),
                    Some(&request),
                    &parties,
                ));
            }
        }

        // 6. Withdrawal. The mandate and agent identity must point to a list.
        for card in [mandate_card, agent_card] {
            let label = card.kind().map(CardKind::plain).unwrap_or("card");
            let entry = card.credential_status.as_ref().ok_or_else(|| {
                refusal!(
                    Check::CannotCheck,
                    format!("the {label} has no withdrawal list"),
                    Some(&request),
                    &parties
                )
            })?;
            macro_rules! cannot {
                ($why:expr) => {
                    refusal!(
                        Check::CannotCheck,
                        $why.to_string(),
                        Some(&request),
                        &parties
                    )
                };
            }
            let token = self
                .stores
                .fetch_status_list(&entry.status_list_credential)
                .ok_or_else(|| cannot!("the withdrawal list could not be reached"))?;
            let list_card = Card::verify(&token)
                .map_err(|_| cannot!("the withdrawal list is not validly signed"))?;
            if list_card.kind() != Some(CardKind::StatusList)
                || list_card.issuer != card.issuer
                || list_card.id != entry.status_list_credential
            {
                return Err(cannot!(
                    "the withdrawal list is not the owner's list for this card"
                ));
            }
            if now + margin < list_card.valid_from || now - margin >= list_card.valid_until {
                return Err(cannot!("the withdrawal list is out of date"));
            }
            let encoded = list_card.credential_subject["encodedList"]
                .as_str()
                .unwrap_or_default();
            let list = StatusList::decode(encoded)
                .map_err(|_| cannot!("the withdrawal list cannot be read"))?;
            let index = entry
                .index()
                .map_err(|_| cannot!("the card's list position cannot be read"))?;
            if list
                .get(index)
                .map_err(|_| cannot!("the card's list position is outside the list"))?
            {
                return Err(refusal!(
                    Check::Withdrawn,
                    format!("the {label} was withdrawn by its owner"),
                    Some(&request),
                    &parties,
                ));
            }
        }

        // 7. Action.
        let action = request.action.as_str();
        if NEVER_GRANTABLE.contains(&action) || mandate.may_never.iter().any(|a| a == action) {
            return Err(refusal!(
                Check::Forbidden,
                format!("'{action}'"),
                Some(&request),
                &parties
            ));
        }
        if !mandate.may_do.iter().any(|a| a == action) {
            return Err(refusal!(
                Check::NotPermitted,
                format!("'{action}'"),
                Some(&request),
                &parties
            ));
        }
        if request.organisation != mandate.on_behalf_of {
            return Err(refusal!(
                Check::WrongOrganisation,
                format!(
                    "asked for '{}', mandate covers '{}'",
                    request.organisation, mandate.on_behalf_of
                ),
                Some(&request),
                &parties,
            ));
        }

        // 8. Limits.
        if let (Some(max), Some(amount)) = (mandate.limits.max_amount_cents, request.amount_cents) {
            if amount > max {
                return Err(refusal!(
                    Check::LimitReached,
                    format!("{} is above the {} limit", euro(amount), euro(max)),
                    Some(&request),
                    &parties,
                ));
            }
        }
        if mandate.limits.max_amount_cents.is_some()
            && request.amount_cents.is_none()
            && AMOUNT_ACTIONS.contains(&action)
        {
            return Err(refusal!(
                Check::LimitReached,
                "the mandate has an amount limit, so the request must state its amount".into(),
                Some(&request),
                &parties,
            ));
        }
        if let Some(max) = mandate.limits.max_per_day {
            let used = self
                .stores
                .uses_on(&mandate_card.id, action, now.date_naive());
            if used >= max {
                return Err(refusal!(
                    Check::LimitReached,
                    format!("{used} of {max} '{action}' already used today"),
                    Some(&request),
                    &parties,
                ));
            }
        }

        // 9. Acceptance.
        if !self
            .stores
            .organisation_accepts(&request.organisation, &mandate_card.issuer)
        {
            return Err(refusal!(
                Check::NotAccepted,
                format!(
                    "'{}' has not accepted this owner's agents",
                    request.organisation
                ),
                Some(&request),
                &parties,
            ));
        }

        Ok(Admitted {
            request,
            owner: mandate_card.issuer.clone(),
            agent: agent.id,
            working_key: presenter,
            mandate_id: mandate_card.id.clone(),
            mandate,
        })
    }
}

fn parties_of(admitted: &Admitted) -> Parties {
    Parties {
        owner: Some(admitted.owner.clone()),
        agent: Some(admitted.agent.clone()),
        working_key: Some(admitted.working_key.clone()),
        mandate: Some(admitted.mandate_id.clone()),
        purpose: Some(admitted.mandate.purpose.clone()),
    }
}

/// Euro cents as "€1,210.00".
pub fn euro(cents: i64) -> String {
    let whole = (cents / 100).abs().to_string();
    let mut grouped = String::new();
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let sign = if cents < 0 { "-" } else { "" };
    format!("{sign}€{grouped}.{:02}", (cents % 100).abs())
}

/// Read a door-side value out of `details` as text, for action runners.
pub fn detail_text<'a>(details: &'a Value, key: &str) -> Option<&'a str> {
    details.get(key).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    #[test]
    fn euro_reads_naturally() {
        assert_eq!(super::euro(121_000), "€1,210.00");
        assert_eq!(super::euro(500_000), "€5,000.00");
        assert_eq!(super::euro(12_345_678), "€123,456.78");
        assert_eq!(super::euro(5), "€0.05");
    }
}
