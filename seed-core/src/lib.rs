//! Seed Vault core.
//!
//! A holder (a person, or an agent acting for one) keeps signed **cards**.
//! A receiver (a **door**, such as Ledger Desk's agent door) checks a chain of
//! cards before it lets an agent act, and both sides keep a **receipt**.
//!
//! Slice 1 scope: agent mandate cards. Owner key → agent identity card →
//! mandate card → short-lived working key → presentation at a door.
//!
//! Formats follow W3C Verifiable Credentials 2.0 (secured as JOSE, ES256),
//! `did:key` identifiers for P-256 keys, and the W3C Bitstring Status List for
//! withdrawals. Versions are pinned in `docs/standards.md` and still need an
//! external conformance check before real use.

pub mod b64;
pub mod cards;
pub mod conformance;
pub mod door;
pub mod error;
pub mod jws;
pub mod keys;
pub mod presentation;
pub mod receipt;
pub mod reference;
pub mod status;
pub mod vault;

pub use error::SeedError;
pub type Result<T> = std::result::Result<T, SeedError>;
