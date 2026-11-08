# Standards used, and what still needs checking

Described from knowledge as of mid-2026. Before real use, each line needs a
check against the current published version and, where one exists, its test suite.

| Standard | How it is used here | Check still needed |
|---|---|---|
| W3C Verifiable Credentials Data Model 2.0 | Shape of every card: `@context`, `type`, `issuer`, `validFrom`, `validUntil`, `credentialSubject`, `credentialStatus` | Run the cards through a VC 2.0 validator |
| W3C VC-JOSE-COSE | Cards are compact JWS with `typ: vc+jwt`, the credential as payload | Confirm the media type and header rules |
| JWS ES256 (RFC 7515/7518) | All signatures: P-256, SHA-256, raw r‖s | Interop test with another JOSE library |
| W3C `did:key` (P-256, multicodec 0x1200) | Identifiers for owners, agents, working keys, doors | Compare with the did:key test vectors |
| W3C Bitstring Status List | Withdrawal lists: GZIP, multibase base64url, 131,072 bits, index 0 = leftmost bit | Compare with the spec's examples |
| Own formats | Presentation (`seed-presentation+jwt`) and receipt (`seed-receipt+jwt`) | Consider OpenID4VP for the presentation and ISO/IEC 27560 for receipts in a later slice |

Custom card types (`SeedOwnerIdentityCard`, `SeedAgentIdentityCard`,
`SeedMandateCard`, `SeedWorkingKeyCard`) use the context
`https://beingexponential.com/ns/seed/v1`, which does not exist yet and should
be published before anyone outside relies on it.
