//! The shared conformance cases from the Slice 0 doc, section 5.
//!
//! Seed Vault and every door (Ledger Desk's included) must give exactly these
//! answers. A door proves it by implementing [`Harness`] and calling
//! [`run_all`]; the reference door does the same in this crate's tests.

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};

use crate::cards::Limits;
use crate::door::Check;
use crate::keys::{Signer, SoftwareKey};
use crate::presentation::{self, Challenge, Request};
use crate::receipt::{Outcome, Receipt};
use crate::vault::{working_key_for, MandateTerms, Vault};

pub const ORGANISATION: &str = "org-michael";
pub const STATUS_URL: &str = "https://seed.example/status/michael";
/// Gross amount of the sample draft: 1 × €1,000.00 + 21% VAT.
pub const SAMPLE_AMOUNT_CENTS: i64 = 121_000;

/// A fixed "now" inside the sample mandate's validity (01-02-2027 to 30-04-2027).
pub fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 2, 10, 10, 0, 0).unwrap()
}

/// What a door must offer so the cases can drive it.
pub trait Harness {
    /// Register an owner from their signed owner identity card.
    fn register_owner(&mut self, owner_identity_card: &str);
    fn accept_owner(&mut self, organisation: &str, owner: &str);
    fn publish_status_list(&mut self, url: &str, signed_list: &str);
    fn make_unreachable(&mut self, url: &str);
    fn challenge(&mut self, now: DateTime<Utc>) -> Challenge;
    /// Hand the presentation to the door; it acts if allowed and returns the receipt.
    fn submit(&mut self, presentation: &str, now: DateTime<Utc>) -> Receipt;
    /// Every receipt the door has stored.
    fn receipts(&self) -> Vec<Receipt>;
    /// Let the door add what its own action needs (Ledger adds a contact).
    fn prepare_details(&mut self, details: Value) -> Value {
        details
    }
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub number: u32,
    pub name: &'static str,
    pub expected: String,
    pub got: String,
    pub passed: bool,
}

struct World {
    vault: Vault,
    mandate: String,
}

fn sample_details() -> Value {
    json!({
        "invoice_date": "2027-02-10",
        "due_date": "2027-03-12",
        "lines": [{"description": "Conformance sample services", "quantity": "1", "unit_price": "1000.00", "vat_rate": "21"}]
    })
}

fn world(h: &mut dyn Harness, accept: bool, tweak: impl FnOnce(&mut MandateTerms)) -> World {
    let now = fixed_now();
    let mut vault = Vault::create(
        "Michael J. Dawkins",
        "NL",
        "Dutch law",
        STATUS_URL,
        now - Duration::days(30),
    )
    .expect("vault");
    vault
        .add_agent(
            "invoice-drafter",
            "Michael J. Dawkins",
            "local model",
            "Mac mini",
            now - Duration::days(30),
        )
        .expect("agent");
    let mut terms = MandateTerms {
        organisation: ORGANISATION.into(),
        may_do: vec!["read_invoices".into(), "draft_invoice".into()],
        may_never: vec![
            "send_invoice".into(),
            "pay_invoice".into(),
            "change_bank_details".into(),
            "issue_cards".into(),
        ],
        limits: Limits {
            max_per_day: Some(20),
            max_amount_cents: Some(500_000),
        },
        purpose: "prepare monthly invoices for review".into(),
        valid_from: Utc.with_ymd_and_hms(2027, 2, 1, 0, 0, 0).unwrap(),
        valid_until: Utc.with_ymd_and_hms(2027, 4, 30, 23, 59, 59).unwrap(),
    };
    tweak(&mut terms);
    let mandate = vault
        .issue_mandate("invoice-drafter", terms)
        .expect("mandate")
        .id;
    vault.resign_status_list(now).expect("status list");
    h.register_owner(&vault.owner.identity_card);
    if accept {
        h.accept_owner(ORGANISATION, &vault.owner.did);
    }
    h.publish_status_list(STATUS_URL, &vault.status_list_card);
    World { vault, mandate }
}

fn draft(h: &mut dyn Harness) -> Request {
    Request {
        action: "draft_invoice".into(),
        organisation: ORGANISATION.into(),
        amount_cents: Some(SAMPLE_AMOUNT_CENTS),
        details: h.prepare_details(sample_details()),
    }
}

fn other(action: &str) -> Request {
    Request {
        action: action.into(),
        organisation: ORGANISATION.into(),
        amount_cents: None,
        details: json!({}),
    }
}

fn answer(h: &mut dyn Harness, w: &World, request: Request) -> String {
    let challenge = h.challenge(fixed_now());
    w.vault
        .answer(&w.mandate, &challenge, request, fixed_now())
        .expect("answer")
}

/// Present with a custom card list, signed by `key`.
fn present_with(
    h: &mut dyn Harness,
    key: &dyn Signer,
    request: Request,
    cards: Vec<String>,
    audience: Option<&str>,
) -> String {
    let challenge = h.challenge(fixed_now());
    let aud = audience.map(str::to_string).unwrap_or(challenge.audience);
    presentation::present(key, &challenge.nonce, &aud, request, cards, fixed_now())
        .expect("present")
}

fn agent_key(w: &World) -> SoftwareKey {
    let secret = w.vault.agents[0]
        .secret
        .as_ref()
        .expect("software agent key");
    SoftwareKey::from_secret(secret).expect("agent key")
}

/// Change one character in the middle of a signed card's signature.
fn tamper(token: &str) -> String {
    let sig_start = token.rfind('.').expect("jws") + 1;
    let mut chars: Vec<char> = token.chars().collect();
    let i = sig_start + (chars.len() - sig_start) / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn describe(r: &Receipt) -> String {
    match (&r.outcome, &r.failed_check) {
        (Outcome::Allowed, _) => "allowed".into(),
        (Outcome::Refused, Some(c)) => format!("refused: {c}"),
        (Outcome::Failed, Some(c)) => format!("failed: {c}"),
        (o, _) => format!("{o:?}"),
    }
}

fn refused(check: Check) -> String {
    format!("refused: {}", check.code())
}

/// Run every case against fresh doors from `make`.
pub fn run_all(make: &mut dyn FnMut() -> Box<dyn Harness>) -> Vec<CaseResult> {
    let mut results = Vec::new();
    let mut refusal_receipts_ok = true;
    let now = fixed_now();

    let mut case = |number: u32,
                    name: &'static str,
                    expected: String,
                    run: &dyn Fn(&mut dyn Harness) -> Receipt,
                    results: &mut Vec<CaseResult>,
                    refusal_ok: &mut bool| {
        let mut h = make();
        let receipt = run(h.as_mut());
        let got = describe(&receipt);
        let stored = h.receipts().iter().any(|r| r == &receipt);
        if receipt.outcome != Outcome::Allowed && !(stored && receipt.failed_check.is_some()) {
            *refusal_ok = false;
        }
        let leaks = serde_json::to_string(&receipt)
            .unwrap_or_default()
            .contains("Conformance sample services");
        let passed = got == expected && stored && !leaks;
        let got = if !stored {
            format!("{got} (receipt not stored)")
        } else if leaks {
            format!("{got} (receipt leaks content)")
        } else {
            got
        };
        results.push(CaseResult {
            number,
            name,
            expected,
            got,
            passed,
        });
    };

    case(
        1,
        "Valid chain, allowed action, within limits",
        "allowed".into(),
        &|h| {
            let w = world(h, true, |_| {});
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        2,
        "Signature on the mandate altered by one character",
        refused(Check::Signature),
        &|h| {
            let w = world(h, true, |_| {});
            let (key, wk) = w.vault.working_key(&w.mandate, 4, now).unwrap();
            let mut chain = w.vault.chain(&w.mandate).unwrap();
            chain[0] = tamper(&chain[0]);
            let req = draft(h);
            let p = present_with(h, &key, req, [vec![wk], chain].concat(), None);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        3,
        "Mandate signed by an unknown key",
        refused(Check::Chain),
        &|h| {
            let _real = world(h, true, |_| {});
            // An outsider builds a complete, well-formed chain from their own key.
            let mut fake = Vault::create(
                "Michael J. Dawkins",
                "NL",
                "Dutch law",
                "https://seed.example/status/fake",
                now - Duration::days(1),
            )
            .unwrap();
            fake.add_agent("invoice-drafter", "x", "x", "x", now - Duration::days(1))
                .unwrap();
            let terms = MandateTerms {
                organisation: ORGANISATION.into(),
                may_do: vec!["draft_invoice".into()],
                may_never: vec![],
                limits: Limits::default(),
                purpose: "forged".into(),
                valid_from: now - Duration::days(1),
                valid_until: now + Duration::days(30),
            };
            let mandate = fake.issue_mandate("invoice-drafter", terms).unwrap().id;
            fake.resign_status_list(now).unwrap();
            h.publish_status_list("https://seed.example/status/fake", &fake.status_list_card);
            let challenge = h.challenge(now);
            let req = draft(h);
            let p = fake.answer(&mandate, &challenge, req, now).unwrap();
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        4,
        "Working key expired one minute ago",
        refused(Check::Expired),
        &|h| {
            let w = world(h, true, |_| {});
            let issued = now - Duration::hours(4) - Duration::seconds(60);
            let (key, wk) = working_key_for(&agent_key(&w), &w.mandate, 4, issued).unwrap();
            let chain = w.vault.chain(&w.mandate).unwrap();
            let req = draft(h);
            let p = present_with(h, &key, req, [vec![wk], chain].concat(), None);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        5,
        "Mandate on the withdrawal list",
        refused(Check::Withdrawn),
        &|h| {
            let mut w = world(h, true, |_| {});
            let id = w.mandate.clone();
            w.vault.withdraw(&id, now).unwrap();
            h.publish_status_list(STATUS_URL, &w.vault.status_list_card);
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        6,
        "Withdrawal list unreachable",
        refused(Check::CannotCheck),
        &|h| {
            let w = world(h, true, |_| {});
            h.make_unreachable(STATUS_URL);
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        7,
        "Action \"pay invoice\"",
        refused(Check::Forbidden),
        &|h| {
            let w = world(h, true, |_| {});
            let p = answer(h, &w, other("pay_invoice"));
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        8,
        "Action not listed anywhere (\"delete contact\")",
        refused(Check::NotPermitted),
        &|h| {
            let w = world(h, true, |_| {});
            let p = answer(h, &w, other("delete_contact"));
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        9,
        "21st draft of the day",
        refused(Check::LimitReached),
        &|h| {
            let w = world(h, true, |_| {});
            for i in 0..20 {
                let req = draft(h);
                let p = answer(h, &w, req);
                let r = h.submit(&p, now);
                assert_eq!(
                    r.outcome,
                    Outcome::Allowed,
                    "draft {} of 20 should be allowed: {}",
                    i + 1,
                    r.reason
                );
            }
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        10,
        "Valid answer replayed with an old one-time number",
        refused(Check::Replay),
        &|h| {
            let w = world(h, true, |_| {});
            let req = draft(h);
            let p = answer(h, &w, req);
            let first = h.submit(&p, now);
            assert_eq!(
                first.outcome,
                Outcome::Allowed,
                "first use should pass: {}",
                first.reason
            );
            h.submit(&p, now + Duration::seconds(5))
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        11,
        "Valid answer meant for another door",
        refused(Check::Audience),
        &|h| {
            let w = world(h, true, |_| {});
            let (key, wk) = w.vault.working_key(&w.mandate, 4, now).unwrap();
            let chain = w.vault.chain(&w.mandate).unwrap();
            let req = draft(h);
            let p = present_with(
                h,
                &key,
                req,
                [vec![wk], chain].concat(),
                Some("another-door"),
            );
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        12,
        "Working key tries to create a new working key for another agent",
        refused(Check::CannotPassOn),
        &|h| {
            let w = world(h, true, |_| {});
            let (first_key, first_card) = w.vault.working_key(&w.mandate, 4, now).unwrap();
            let (second_key, second_card) =
                working_key_for(&first_key, &w.mandate, 4, now).unwrap();
            let chain = w.vault.chain(&w.mandate).unwrap();
            let req = draft(h);
            let p = present_with(
                h,
                &second_key,
                req,
                [vec![second_card, first_card], chain].concat(),
                None,
            );
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        13,
        "Valid chain, but the organisation hasn't accepted this owner",
        refused(Check::NotAccepted),
        &|h| {
            let w = world(h, false, |_| {});
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        14,
        "Mandate valid from a date still in the future",
        refused(Check::NotYetValid),
        &|h| {
            let w = world(h, true, |t| t.valid_from = now + Duration::days(10));
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    // Added beyond the Slice 0 list: the amount limit and "one visit, one organisation".
    case(
        16,
        "Added: draft above the €5,000 amount limit",
        refused(Check::LimitReached),
        &|h| {
            let w = world(h, true, |t| t.limits.max_amount_cents = Some(100_000));
            let req = draft(h);
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    case(
        17,
        "Added: mandate used for another organisation's books",
        refused(Check::WrongOrganisation),
        &|h| {
            let w = world(h, true, |_| {});
            let mut req = draft(h);
            req.organisation = "org-someone-else".into();
            let p = answer(h, &w, req);
            h.submit(&p, now)
        },
        &mut results,
        &mut refusal_receipts_ok,
    );

    results.push(CaseResult {
        number: 15,
        name: "Every refusal above has a receipt naming the failed check",
        expected: "all refusals receipted".into(),
        got: if refusal_receipts_ok {
            "all refusals receipted".into()
        } else {
            "a refusal had no stored receipt".into()
        },
        passed: refusal_receipts_ok,
    });
    results.sort_by_key(|r| r.number);
    results
}

/// A plain table of results.
pub fn report(results: &[CaseResult]) -> String {
    let mut out = String::new();
    for r in results {
        out.push_str(&format!(
            "{} {:>2}. {} — expected {}, got {}\n",
            if r.passed { "PASS" } else { "FAIL" },
            r.number,
            r.name,
            r.expected,
            r.got
        ));
    }
    let passed = results.iter().filter(|r| r.passed).count();
    out.push_str(&format!("{passed} of {} cases pass\n", results.len()));
    out
}

/// The reference door, in memory, for running the cases without any receiver.
pub mod memory {
    use super::*;
    use crate::door::Door;
    use crate::reference::MemoryStores;

    pub struct MemoryHarness {
        pub door: Door<MemoryStores>,
    }

    impl Default for MemoryHarness {
        fn default() -> Self {
            MemoryHarness {
                door: Door::new(
                    "seed-reference-door",
                    Box::new(SoftwareKey::generate()),
                    MemoryStores::default(),
                ),
            }
        }
    }

    impl Harness for MemoryHarness {
        fn register_owner(&mut self, owner_identity_card: &str) {
            let card = crate::cards::verify_kind(
                owner_identity_card,
                crate::cards::CardKind::OwnerIdentity,
            )
            .expect("owner identity card");
            assert_eq!(
                card.issuer,
                card.subject_id(),
                "owner cards are self-signed"
            );
            self.door.stores.known_owners.insert(card.issuer);
        }
        fn accept_owner(&mut self, organisation: &str, owner: &str) {
            self.door
                .stores
                .acceptances
                .insert((organisation.into(), owner.into()));
        }
        fn publish_status_list(&mut self, url: &str, signed_list: &str) {
            self.door
                .stores
                .status_lists
                .insert(url.into(), signed_list.into());
        }
        fn make_unreachable(&mut self, url: &str) {
            self.door.stores.unreachable.insert(url.into());
        }
        fn challenge(&mut self, now: DateTime<Utc>) -> Challenge {
            self.door.challenge(now)
        }
        fn submit(&mut self, presentation: &str, now: DateTime<Utc>) -> Receipt {
            self.door
                .handle(presentation, now, |admitted| {
                    Ok(Some(format!("draft-{}", admitted.request.action)))
                })
                .receipt
        }
        fn receipts(&self) -> Vec<Receipt> {
            self.door
                .stores
                .receipts
                .iter()
                .map(|r| r.receipt.clone())
                .collect()
        }
    }
}
