//! `seed`: the standalone Seed Vault holder, for owners and their agents.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use seed_core::cards::{verify_kind, AgentSubject, CardKind, Limits, MandateSubject};
use seed_core::conformance::{self, memory::MemoryHarness, Harness};
use seed_core::door::{euro, Door};
use seed_core::keys::SoftwareKey;
use seed_core::presentation::Request;
use seed_core::receipt::Outcome;
use seed_core::reference::MemoryStores;
use seed_core::vault::{MandateTerms, Vault};
use serde_json::json;

const HELP: &str = "seed — Seed Vault holder (Slice 1: agent mandate cards)

Usage:
  seed init --name NAME --country CC --law LAW [--status-url URL]
  seed agent add NAME --model MODEL --machine MACHINE [--built-by WHO]
  seed mandate issue AGENT --org ORG --may-do a,b [--may-never c,d]
                     [--max-per-day N] [--max-amount EUROS] --purpose TEXT
                     --from DD-MM-YYYY --until DD-MM-YYYY
  seed mandate withdraw MANDATE_ID
  seed status-list [--out FILE]     write the signed withdrawal list to publish
  seed chain MANDATE_ID             print the cards an agent shows at a door
  seed visit --door URL --mandate ID --org ORG --action ACTION
             [--amount EUROS] [--details FILE.json]
                                    act as the agent: knock, answer, keep the receipt
  seed show                         what is in the vault, in plain words
  seed owner-card                   print your owner identity card, to register at a door
  seed receipts                     every receipt this vault keeps
  seed demo                         run the whole story once, in memory
  seed conformance                  run the shared test cases on the reference door

Options:
  --vault PATH   vault file (default: $SEED_VAULT or ./seed-vault.json)

Keys in the vault file are software keys, fine for trying things out.
Real use needs the owner key on a phone chip and agent keys in a Secure Enclave.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("seed: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    words: Vec<String>,
    flags: HashMap<String, String>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Result<Args, String> {
        let mut words = Vec::new();
        let mut flags = HashMap::new();
        let mut it = raw.into_iter();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                flags.insert(name.to_string(), value);
            } else {
                words.push(a);
            }
        }
        Ok(Args { words, flags })
    }
    fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }
    fn need(&self, name: &str) -> Result<&str, String> {
        self.flag(name)
            .ok_or_else(|| format!("--{name} is required"))
    }
    fn word(&self, i: usize, what: &str) -> Result<&str, String> {
        self.words
            .get(i)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {what}"))
    }
    fn vault_path(&self) -> PathBuf {
        self.flag("vault")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("SEED_VAULT").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("seed-vault.json"))
    }
}

fn list(text: Option<&str>) -> Vec<String> {
    text.map(|t| {
        t.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn date(text: &str, end_of_day: bool) -> Result<DateTime<Utc>, String> {
    let d = NaiveDate::parse_from_str(text, "%d-%m-%Y")
        .map_err(|_| format!("'{text}' is not a DD-MM-YYYY date"))?;
    let t = if end_of_day {
        d.and_hms_opt(23, 59, 59)
    } else {
        d.and_hms_opt(0, 0, 0)
    }
    .expect("valid time");
    Ok(Utc.from_utc_datetime(&t))
}

fn day(t: &DateTime<Utc>) -> String {
    t.format("%d-%m-%Y").to_string()
}

fn short(id: &str) -> &str {
    id.rsplit(':').next().unwrap_or(id).get(..8).unwrap_or(id)
}

fn run(raw: Vec<String>) -> Result<(), String> {
    let args = Args::parse(raw)?;
    let path = args.vault_path();
    let now = Utc::now();
    let load = || Vault::load(&path).map_err(|e| format!("{e} (vault: {})", path.display()));
    let e = |e: seed_core::SeedError| e.to_string();
    match args.words.first().map(String::as_str) {
        None | Some("help") => println!("{HELP}"),
        Some("init") => {
            if path.exists() {
                return Err(format!(
                    "{} already exists; nothing changed",
                    path.display()
                ));
            }
            let url = args
                .flag("status-url")
                .unwrap_or("https://beingexponential.com/seed/status/owner");
            let vault = Vault::create(
                args.need("name")?,
                args.need("country")?,
                args.need("law")?,
                url,
                now,
            )
            .map_err(e)?;
            vault.save(&path).map_err(e)?;
            println!(
                "Vault created at {}.\nYour owner identifier: {}",
                path.display(),
                vault.owner.did
            );
        }
        Some("agent") if args.word(1, "agent command")? == "add" => {
            let mut vault = load()?;
            let name = args.word(2, "agent name")?.to_string();
            let built_by = args
                .flag("built-by")
                .unwrap_or(&vault.owner.name)
                .to_string();
            let agent = vault
                .add_agent(
                    &name,
                    &built_by,
                    args.need("model")?,
                    args.need("machine")?,
                    now,
                )
                .map_err(e)?;
            println!("Agent '{name}' added. Its identifier: {}", agent.did);
            vault.save(&path).map_err(e)?;
        }
        Some("mandate") => match args.word(1, "mandate command")? {
            "issue" => {
                let mut vault = load()?;
                let agent = args.word(2, "agent name")?.to_string();
                let max_amount_cents = match args.flag("max-amount") {
                    Some(v) => Some(
                        (v.parse::<f64>()
                            .map_err(|_| "--max-amount must be a number of euros")?
                            * 100.0)
                            .round() as i64,
                    ),
                    None => None,
                };
                let max_per_day = match args.flag("max-per-day") {
                    Some(v) => Some(
                        v.parse::<u32>()
                            .map_err(|_| "--max-per-day must be a whole number")?,
                    ),
                    None => None,
                };
                let terms = MandateTerms {
                    organisation: args.need("org")?.into(),
                    may_do: list(args.flag("may-do")),
                    may_never: list(args.flag("may-never")),
                    limits: Limits {
                        max_per_day,
                        max_amount_cents,
                    },
                    purpose: args.need("purpose")?.into(),
                    valid_from: date(args.need("from")?, false)?,
                    valid_until: date(args.need("until")?, true)?,
                };
                let entry = vault.issue_mandate(&agent, terms).map_err(e)?;
                vault.save(&path).map_err(e)?;
                println!("Mandate signed for '{agent}'. Its id: {}", entry.id);
            }
            "withdraw" => {
                let mut vault = load()?;
                vault
                    .withdraw(args.word(2, "mandate id")?, now)
                    .map_err(e)?;
                vault.save(&path).map_err(e)?;
                println!("Withdrawn. Publish the new list with `seed status-list --out FILE` so doors see it.");
            }
            other => return Err(format!("unknown mandate command '{other}'")),
        },
        Some("status-list") => {
            let vault = load()?;
            match args.flag("out") {
                Some(out) => {
                    std::fs::write(out, &vault.status_list_card).map_err(|e| e.to_string())?;
                    println!(
                        "Signed withdrawal list written to {out}. Publish it at {}",
                        vault.status_list_url
                    );
                }
                None => println!("{}", vault.status_list_card),
            }
        }
        Some("chain") => {
            let vault = load()?;
            let cards = vault.chain(args.word(1, "mandate id")?).map_err(e)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"cards": cards})).expect("json")
            );
        }
        Some("show") => show(&load()?),
        Some("owner-card") => println!("{}", load()?.owner.identity_card),
        Some("visit") => {
            let mut vault = load()?;
            visit(&mut vault, &args)?;
            vault.save(&path).map_err(e)?;
        }
        Some("receipts") => {
            for r in &load()?.receipts {
                let r = &r.receipt;
                println!(
                    "{}  {:?}  {}  {}",
                    r.at.format("%d-%m-%Y %H:%M"),
                    r.outcome,
                    r.action.as_deref().unwrap_or("-"),
                    r.reason
                );
            }
        }
        Some("demo") => demo().map_err(e)?,
        Some("conformance") => {
            let results = conformance::run_all(&mut || {
                Box::new(MemoryHarness::default()) as Box<dyn Harness>
            });
            print!("{}", conformance::report(&results));
            if !results.iter().all(|r| r.passed) {
                return Err("some cases failed".into());
            }
        }
        Some(other) => return Err(format!("unknown command '{other}'; try `seed help`")),
    }
    Ok(())
}

/// The agent side of the handshake against a door's HTTP routes.
fn visit(vault: &mut Vault, args: &Args) -> Result<(), String> {
    let door = args.need("door")?.trim_end_matches('/');
    let org = args.need("org")?;
    let amount_cents = match args.flag("amount") {
        Some(v) => Some(
            (v.parse::<f64>()
                .map_err(|_| "--amount must be a number of euros")?
                * 100.0)
                .round() as i64,
        ),
        None => None,
    };
    let details = match args.flag("details") {
        Some(file) => {
            serde_json::from_str(&std::fs::read_to_string(file).map_err(|e| e.to_string())?)
                .map_err(|e| format!("{file}: {e}"))?
        }
        None => json!({}),
    };
    let post = |route: &str, body: serde_json::Value| -> Result<serde_json::Value, String> {
        match ureq::post(&format!("{door}{route}")).send_json(body) {
            Ok(r) => r.into_json().map_err(|e| e.to_string()),
            Err(ureq::Error::Status(_, r)) => {
                let v: serde_json::Value = r.into_json().unwrap_or_default();
                Err(format!(
                    "the door said no: {}",
                    v["error"].as_str().unwrap_or("unknown")
                ))
            }
            Err(e) => Err(format!("could not reach the door: {e}")),
        }
    };
    let challenge: seed_core::presentation::Challenge = serde_json::from_value(post(
        "/api/seed/challenge",
        json!({"organization_id": org}),
    )?)
    .map_err(|e| e.to_string())?;
    let request = Request {
        action: args.need("action")?.into(),
        organisation: org.into(),
        amount_cents,
        details,
    };
    let answer = vault
        .answer(args.need("mandate")?, &challenge, request, Utc::now())
        .map_err(|e| e.to_string())?;
    let visit = post("/api/seed/present", json!({"presentation": answer}))?;
    let receipt: seed_core::receipt::Receipt =
        serde_json::from_value(visit["receipt"].clone()).map_err(|e| e.to_string())?;
    let signed = visit["signed_receipt"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    println!("{:?}: {}", receipt.outcome, receipt.reason);
    if let Some(record) = &receipt.record {
        println!("record: {record}");
    }
    vault
        .keep_receipt(seed_core::receipt::SignedReceipt { receipt, signed })
        .map_err(|e| format!("the door's receipt did not check out: {e}"))?;
    Ok(())
}

fn show(vault: &Vault) {
    println!(
        "Owner: {} ({}, {})",
        vault.owner.name, vault.owner.country, vault.owner.law
    );
    println!("  identifier {}", vault.owner.did);
    println!("  withdrawal list published at {}", vault.status_list_url);
    if vault.agents.is_empty() {
        println!("No agents yet.");
    }
    for agent in &vault.agents {
        let subject: Option<AgentSubject> =
            verify_kind(&agent.identity_card, CardKind::AgentIdentity)
                .ok()
                .and_then(|c| c.subject().ok());
        let machine = subject
            .map(|s| format!("{} on {}", s.model, s.machine))
            .unwrap_or_default();
        println!("\nAgent '{}': {machine}", agent.name);
        for m in &agent.mandates {
            let Ok(card) = verify_kind(&m.card, CardKind::Mandate) else {
                continue;
            };
            let Ok(s) = card.subject::<MandateSubject>() else {
                continue;
            };
            println!(
                "  mandate {}{}: for {}, may do {}, may never {}, {} to {}",
                short(&m.id),
                if m.withdrawn { " (WITHDRAWN)" } else { "" },
                s.on_behalf_of,
                s.may_do.join(", "),
                if s.may_never.is_empty() {
                    "-".into()
                } else {
                    s.may_never.join(", ")
                },
                day(&card.valid_from),
                day(&card.valid_until)
            );
            let mut limits = Vec::new();
            if let Some(n) = s.limits.max_per_day {
                limits.push(format!("at most {n} per action per day"));
            }
            if let Some(c) = s.limits.max_amount_cents {
                limits.push(format!("nothing above {}", euro(c)));
            }
            if !limits.is_empty() {
                println!("    limits: {}", limits.join("; "));
            }
            println!("    purpose: {}", s.purpose);
        }
    }
    println!("\n{} receipt(s) kept.", vault.receipts.len());
}

/// The Slice 1 story, end to end, in memory.
fn demo() -> seed_core::Result<()> {
    let now = Utc::now();
    let say = |s: &str| println!("{s}");
    say("1. Michael creates his vault and an agent that runs on the Mac mini.");
    let mut vault = Vault::create(
        "Michael J. Dawkins",
        "NL",
        "Dutch law",
        "https://seed.example/status/michael",
        now,
    )?;
    vault.add_agent(
        "invoice-drafter",
        "Michael J. Dawkins",
        "local model",
        "Mac mini",
        now,
    )?;
    say("2. He signs a mandate: may read and draft invoices for his organisation, may never send or pay,");
    say("   at most 20 drafts a day, nothing above €5,000, valid for 90 days.");
    let mandate = vault
        .issue_mandate(
            "invoice-drafter",
            MandateTerms {
                organisation: "org-michael".into(),
                may_do: vec!["read_invoices".into(), "draft_invoice".into()],
                may_never: vec![
                    "send_invoice".into(),
                    "pay_invoice".into(),
                    "change_bank_details".into(),
                ],
                limits: Limits {
                    max_per_day: Some(20),
                    max_amount_cents: Some(500_000),
                },
                purpose: "prepare monthly invoices for review".into(),
                valid_from: now - Duration::minutes(1),
                valid_until: now + Duration::days(90),
            },
        )?
        .id;

    say("3. A door (standing in for Ledger Desk) knows Michael and accepts his agents for his organisation.");
    let mut stores = MemoryStores::default();
    stores.known_owners.insert(vault.owner.did.clone());
    stores
        .acceptances
        .insert(("org-michael".into(), vault.owner.did.clone()));
    stores.status_lists.insert(
        vault.status_list_url.clone(),
        vault.status_list_card.clone(),
    );
    let mut door = Door::new(
        "ledger-desk-demo-door",
        Box::new(SoftwareKey::generate()),
        stores,
    );

    let draft = Request {
        action: "draft_invoice".into(),
        organisation: "org-michael".into(),
        amount_cents: Some(121_000),
        details: json!({"lines": [{"description": "Consulting", "quantity": "1", "unit_price": "1000.00", "vat_rate": "21"}]}),
    };
    let visit = |door: &mut Door<MemoryStores>,
                 vault: &mut Vault,
                 request: Request|
     -> seed_core::Result<()> {
        let challenge = door.challenge(now);
        let answer = vault.answer(&mandate, &challenge, request, now)?;
        let receipt = door.handle(&answer, now, |_| Ok(Some("invoice-draft-0001".into())));
        let r = &receipt.receipt;
        let verdict = match r.outcome {
            Outcome::Allowed => "ALLOWED",
            Outcome::Refused => "REFUSED",
            Outcome::Failed => "FAILED",
        };
        println!("   → {verdict}: {}", r.reason);
        vault.keep_receipt(receipt)?;
        Ok(())
    };

    say("4. The agent drafts an invoice of €1,210.00.");
    visit(&mut door, &mut vault, draft.clone())?;
    say("5. A sneaky email talks the agent into paying an invoice.");
    visit(
        &mut door,
        &mut vault,
        Request {
            action: "pay_invoice".into(),
            ..draft.clone()
        },
    )?;
    say("6. Michael pulls the mandate back, and publishes his withdrawal list.");
    vault.withdraw(&mandate, now)?;
    door.stores.status_lists.insert(
        vault.status_list_url.clone(),
        vault.status_list_card.clone(),
    );
    say("7. The agent tries to draft again.");
    visit(&mut door, &mut vault, draft)?;
    println!(
        "\nBoth sides kept {} receipts each. None of them contains the invoice's content.",
        vault.receipts.len()
    );
    Ok(())
}
