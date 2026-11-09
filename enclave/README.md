# seed-enclave: the agent key in the Mac's Secure Enclave

**Status: written, not yet run on a Mac.** The Rust side (the signer that
calls this helper, the agent kit, and the visit) is built and tested with
`seed-soft-enclave`, a stand-in that speaks the same protocol. The Swift
helper itself still needs its first run on real hardware.

## What it does

The agent's private key is made inside the Mac's Secure Enclave and never
leaves it. The agent can ask the chip to sign, but nobody, the agent included,
can read the key. The key file on disk is an encrypted handle that only this
Mac's chip can use.

The owner key stays in the owner's vault. The agent's machine only gets a
**kit**: its identity card and its live mandate cards. The kit holds no
secret.

## Steps on the Mac mini

```sh
# 1. Build the helper (needs: xcode-select --install)
enclave/build.sh

# 2. Make the agent key inside the chip
enclave/seed-enclave create ~/.seed/drafter.key

# 3. Read its identifier
seed key-id --signer enclave/seed-enclave --key-file ~/.seed/drafter.key

# 4. In the owner's vault: add the agent by that identifier, sign a mandate,
#    and export the kit
seed agent add drafter --model "local model" --machine "Mac mini" --key-did did:key:zDn...
seed mandate issue drafter --org ORG --may-do read_invoices,draft_invoice \
     --may-never pay_invoice,send_invoice --max-per-day 20 --max-amount 5000 \
     --purpose "prepare monthly invoices for review" --from 01-02-2027 --until 30-04-2027
seed agent export drafter --out drafter-kit.json

# 5. On the agent's side: visit a door with the kit and the chip
seed visit --door http://127.0.0.1:1429 --kit drafter-kit.json \
     --signer enclave/seed-enclave --key-file ~/.seed/drafter.key \
     --mandate MANDATE_ID --org ORG --action draft_invoice --amount 1210
```

Receipts from a kit visit are kept next to the kit, in
`drafter-kit.json.receipts.jsonl`, each one checked against the door's
signature first.

## Protocol (for other key homes: TPM, KMS, YubiKey)

Any program can stand in for `seed-enclave` if it speaks this:

| Command | Input | Output |
| --- | --- | --- |
| `create KEY_FILE` | none | base64url of the 65-byte uncompressed P-256 public key |
| `public KEY_FILE` | none | same |
| `sign KEY_FILE` | the message on stdin | base64url of the raw 64-byte ES256 signature |

Seed Vault checks every signature against the public key before using it,
so a helper that signs with the wrong key is caught at once.

## To verify on first run

- CryptoKit Secure Enclave keys work from an unsigned command-line tool,
  without extra entitlements.
- `AfterFirstUnlockThisDeviceOnly` lets an unattended agent sign after the
  Mac has been unlocked once since start-up.
