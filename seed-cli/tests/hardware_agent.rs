//! An agent whose key lives outside the vault, behind a signing helper.
//! The test uses `seed-soft-enclave`, which speaks the same protocol as the
//! Secure Enclave helper, so the whole path is exercised except the chip itself.

use std::path::PathBuf;
use std::process::Command;

use chrono::{Duration, Utc};
use seed_core::cards::Limits;
use seed_core::door::Door;
use seed_core::keys::{ExternalSigner, Signer, SoftwareKey};
use seed_core::presentation::Request;
use seed_core::receipt::Outcome;
use seed_core::reference::MemoryStores;
use seed_core::vault::{AgentKit, MandateTerms, Vault};
use serde_json::json;

/// The signing helper under test. Defaults to the software stand-in; on a Mac,
/// set SEED_TEST_SIGNER to the built `enclave/seed-enclave` to use the real chip.
fn helper() -> String {
    std::env::var("SEED_TEST_SIGNER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_seed-soft-enclave").to_string())
}
const SEED: &str = env!("CARGO_BIN_EXE_seed");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seed-hw-{name}-{}", uuid_ish()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uuid_ish() -> String {
    seed_core::b64::random_token(8)
}

fn new_hardware_key(dir: &std::path::Path) -> (PathBuf, ExternalSigner) {
    let key_file = dir.join("agent.key");
    let out = Command::new(helper())
        .args(["create", key_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let signer = ExternalSigner::open(helper(), &key_file).unwrap();
    (key_file, signer)
}

fn terms() -> MandateTerms {
    let now = Utc::now();
    MandateTerms {
        organisation: "org-michael".into(),
        may_do: vec!["read_invoices".into(), "draft_invoice".into()],
        may_never: vec!["pay_invoice".into()],
        limits: Limits {
            max_per_day: Some(20),
            max_amount_cents: Some(500_000),
        },
        purpose: "prepare monthly invoices for review".into(),
        valid_from: now - Duration::minutes(1),
        valid_until: now + Duration::days(30),
    }
}

fn door_for(vault: &Vault) -> Door<MemoryStores> {
    let mut stores = MemoryStores::default();
    stores.known_owners.insert(vault.owner.did.clone());
    stores
        .acceptances
        .insert(("org-michael".into(), vault.owner.did.clone()));
    stores.status_lists.insert(
        vault.status_list_url.clone(),
        vault.status_list_card.clone(),
    );
    Door::new("test-door", Box::new(SoftwareKey::generate()), stores)
}

fn draft() -> Request {
    Request {
        action: "draft_invoice".into(),
        organisation: "org-michael".into(),
        amount_cents: Some(121_000),
        details: json!({}),
    }
}

#[test]
fn an_agent_with_a_hardware_key_visits_with_a_kit_that_holds_no_secrets() {
    let dir = scratch("kit");
    let now = Utc::now();
    let (_key_file, signer) = new_hardware_key(&dir);
    assert!(signer.did().starts_with("did:key:zDn"));

    let mut vault = Vault::create(
        "Fictional Owner",
        "NL",
        "Dutch law",
        "https://seed.example/s",
        now,
    )
    .unwrap();
    let agent = vault
        .add_external_agent(
            "drafter",
            &signer.did(),
            "Fictional Owner",
            "local model",
            "Mac mini",
            now,
        )
        .unwrap();
    assert!(agent.secret.is_none());
    let mandate = vault.issue_mandate("drafter", terms()).unwrap().id;

    // The vault itself cannot act for this agent: the key is not there.
    let mut door = door_for(&vault);
    let challenge = door.challenge(now);
    assert!(vault.answer(&mandate, &challenge, draft(), now).is_err());

    // The kit travels to the agent's machine and carries no secret at all.
    let kit_path = dir.join("kit.json");
    vault
        .export_kit("drafter", now)
        .unwrap()
        .save(&kit_path)
        .unwrap();
    let text = std::fs::read_to_string(&kit_path).unwrap();
    assert!(
        !text.contains(&vault.owner.secret),
        "owner key must never leave the vault"
    );
    assert!(!text.contains("secret"));
    let kit = AgentKit::load(&kit_path).unwrap();

    let answer = kit
        .answer(&signer, &mandate, &challenge, draft(), now)
        .unwrap();
    let receipt = door.handle(&answer, now, |_| Ok(Some("draft-1".into())));
    assert_eq!(
        receipt.receipt.outcome,
        Outcome::Allowed,
        "{}",
        receipt.receipt.reason
    );

    // The card, not the agent, decides: paying is refused.
    let challenge = door.challenge(now);
    let pay = Request {
        action: "pay_invoice".into(),
        ..draft()
    };
    let answer = kit.answer(&signer, &mandate, &challenge, pay, now).unwrap();
    assert_eq!(
        door.handle(&answer, now, |_| Ok(None)).receipt.outcome,
        Outcome::Refused
    );

    // Kill switch still works for hardware agents.
    vault.withdraw(&mandate, now).unwrap();
    door.stores.status_lists.insert(
        vault.status_list_url.clone(),
        vault.status_list_card.clone(),
    );
    let challenge = door.challenge(now);
    let answer = kit
        .answer(&signer, &mandate, &challenge, draft(), now)
        .unwrap();
    let refused = door.handle(&answer, now, |_| Ok(None));
    assert_eq!(refused.receipt.outcome, Outcome::Refused);

    // A different key cannot use this agent's kit.
    let (_, other) = new_hardware_key(&scratch("other"));
    let challenge = door.challenge(now);
    assert!(kit
        .answer(&other, &mandate, &challenge, draft(), now)
        .is_err());

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_helper_that_returns_a_wrong_signature_is_caught() {
    let dir = scratch("liar");
    let (key_file, signer) = new_hardware_key(&dir);
    // Swap the key behind the helper's back: the public key no longer matches.
    std::fs::remove_file(&key_file).unwrap();
    std::fs::write(&key_file, SoftwareKey::generate().export_secret()).unwrap();
    assert!(signer.sign(b"hello").is_err());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_cli_adds_a_hardware_agent_and_exports_its_kit() {
    let dir = scratch("cli");
    let vault = dir.join("vault.json");
    let (key_file, signer) = new_hardware_key(&dir);
    let seed = |args: &[&str]| {
        let out = Command::new(SEED)
            .arg("--vault")
            .arg(&vault)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    seed(&[
        "init",
        "--name",
        "Fictional Owner",
        "--country",
        "NL",
        "--law",
        "Dutch law",
    ]);
    let did = seed(&[
        "key-id",
        "--signer",
        &helper(),
        "--key-file",
        key_file.to_str().unwrap(),
    ]);
    assert_eq!(did.trim(), signer.did());
    let added = seed(&[
        "agent",
        "add",
        "drafter",
        "--model",
        "m",
        "--machine",
        "Mac mini",
        "--key-did",
        did.trim(),
    ]);
    assert!(added.contains("hardware key"), "{added}");
    seed(&[
        "mandate",
        "issue",
        "drafter",
        "--org",
        "org-michael",
        "--may-do",
        "draft_invoice",
        "--purpose",
        "test",
        "--from",
        "01-01-2026",
        "--until",
        "31-12-2030",
    ]);
    let kit = dir.join("kit.json");
    seed(&["agent", "export", "drafter", "--out", kit.to_str().unwrap()]);
    let kit = AgentKit::load(&kit).unwrap();
    assert_eq!(kit.agent_did, signer.did());
    assert_eq!(kit.mandates.len(), 1);
    std::fs::remove_dir_all(dir).ok();
}
