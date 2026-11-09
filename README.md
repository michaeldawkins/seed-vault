# Seed Vault

A personal vault that hands out signed **cards** instead of raw data. This is
Slice 1: **agent mandate cards**. An owner signs a card that says what one of
their agents may do, for whom, within which limits and until when. Any
receiver (a "door") checks the chain before it lets the agent act, and both
sides keep a receipt. The owner can pull the card back at any time.

Seed Vault is its own product. It connects to Ledger Desk, or to any other
receiver, only through the open card format and the handshake. Ledger Desk's
side lives in `crates/ledger-seed-door` of the Ledger Desk repository.

## Status (09-11-2026)

| | |
|---|---|
| Designed | Yes: see the design docs in the project files (01-11 and 07-11-2026) |
| Built | `seed-core` library, `seed` command-line holder, reference door, agent kits, and a Secure Enclave helper that signs with the Mac mini's chip (tested on the mini 09-11-2026) |
| Tested | 17 conformance cases (the 15 from the Slice 0 doc plus 2) pass here and in Ledger Desk's door |
| Running for real | **No.** The owner key is still a software key; withdrawal lists are not published anywhere yet |
| Proven with a real agent | **Partly.** The chip signs and the tests pass with it; a live visit to a running Ledger Desk door is still to do |

## Pieces

- **seed-core**: card formats, signing (ES256 / P-256), `did:key` identifiers,
  withdrawal lists, presentations, the door's checks, receipts, the vault file
  and the shared conformance cases.
- **seed-cli**: the `seed` command for owners and agents, plus `seed-soft-enclave`,
  a software stand-in for the hardware key helper (tests only).
- **enclave**: `seed-enclave`, the Secure Enclave helper for Macs. See
  [enclave/README.md](enclave/README.md).

## Try it

```sh
cargo run -p seed-cli -- demo          # the whole story once, in memory
cargo run -p seed-cli -- conformance   # the 17 shared cases on the reference door

seed init --name "Michael J. Dawkins" --country NL --law "Dutch law"
seed agent add invoice-drafter --model "local model" --machine "Mac mini"
seed mandate issue invoice-drafter --org org-michael \
  --may-do read_invoices,draft_invoice --may-never send_invoice,pay_invoice \
  --max-per-day 20 --max-amount 5000 --purpose "prepare monthly invoices for review" \
  --from 01-02-2027 --until 30-04-2027
seed show
seed mandate withdraw <mandate id>
seed status-list --out status.jwt    # publish this file at your list address
```

## Rules the code enforces

- A mandate can only narrow rights. Paying, sending payments, changing bank
  details and issuing cards can never be granted to an agent, whatever the
  owner writes; money needs a human's second signature.
- Working keys live for hours and only in memory. A working key cannot make
  another working key.
- The door checks the withdrawal list on every visit and says no when it
  cannot reach it.
- Receipts name the action and the record id, never the content.

## Not done yet

- Hardware keys: agent keys can live behind any helper program that speaks
  the protocol in `enclave/README.md`; the Secure Enclave helper works on the
  Mac mini. The owner key is still a software key in the vault file,
  which is for trying things out only.
- Owner key recovery through trusted people.
- Build (attestation) cards.
- Publishing the withdrawal list at a real address.
- An external check of the formats against the W3C test suites (see `docs/standards.md`).
