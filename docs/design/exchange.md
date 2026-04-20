# Exchange Protocol: ESSR Authenticated Encryption + Credential Exchange

ESSR (Encrypt-Sender-Sign-Receiver) provides authenticated encryption for point-to-point messaging between KELS identities. The exchange protocol layers IPEX-style credential negotiation on top. Implemented in `lib/exchange` (`kels-exchange`).

## ESSR Construction

Four UnForgeability properties:
- **TUF-PTXT/TUF-CTXT** — third party can't forge plaintext or ciphertext
- **RUF-PTXT** — receiver can't forge sender attribution (sender prefix inside ciphertext)
- **RUF-CTXT** — attacker can't strip/replace signature (recipient in signed plaintext)

### Seal

```
SEAL(inner, sender_serial, recipient_prefix, recipient_encap_key, sender_signing_key):
  1. inner_json = serialize(EssrInner { sender, topic, payload })
  2. (kem_ciphertext, shared_secret) = recipient_encap_key.encapsulate()
  3. aes_key = blake3::derive_key("kels/exchange/v1/protocols/essr", &shared_secret)
  4. nonce = random_12_bytes()
  5. encrypted = AES-GCM-256-encrypt(aes_key, nonce, inner_json)
  6. envelope = EssrEnvelope { said, sender, sender_serial, recipient, kem_ciphertext, encrypted, nonce, created_at }
  7. derive envelope SAID
  8. signature = ML-DSA-sign(sender_signing_key, envelope.said)
  9. return SignedEssrEnvelope { envelope, signature }
```

### Open

```
OPEN(signed_envelope, recipient_decap_key, sender_verification_key):
  1. verify envelope SAID
  2. ML-DSA-verify(sender_verification_key, envelope.said, signature)
  3. shared_secret = recipient_decap_key.decapsulate(kem_ciphertext)
  4. aes_key = blake3::derive_key("kels/exchange/v1/protocols/essr", &shared_secret)
  5. inner_json = AES-GCM-256-decrypt(aes_key, nonce, encrypted)
  6. inner = deserialize(inner_json)
  7. assert inner.sender == envelope.sender
  8. return inner
```

The caller is responsible for verifying the sender's KEL and extracting the verification key at `sender_serial` before calling `open`. The `open` function itself is purely cryptographic.

## Types

### EssrInner (encrypted)

```rust
pub struct EssrInner {
    pub sender: String,    // sender KEL prefix (inside ciphertext = RUF-PTXT)
    pub topic: String,     // e.g. "kels/exchange/v1/topics/exchange" — tells recipient how to parse payload
    pub payload: Vec<u8>,  // opaque content
}
```

The `topic` field enables protocol multiplexing: the mail service never sees it (it's encrypted), but the recipient uses it to dispatch the payload to the correct handler.

### EssrEnvelope (signed plaintext)

```rust
pub struct EssrEnvelope {
    pub said: String,
    pub sender: String,           // plaintext, for routing
    pub sender_serial: u64,       // establishment event serial at signing time
    pub recipient: String,        // signed plaintext = anti-KCI
    pub kem_ciphertext: String,   // CESR ML-KEM ciphertext
    pub encrypted_payload: String,// url-safe base64 no-pad AES-GCM-256 ciphertext
    pub nonce: String,            // CESR-encoded AES-GCM nonce (code 1AAN)
    pub created_at: StorageDatetime,
}
```

### SignedEssrEnvelope

```rust
pub struct SignedEssrEnvelope {
    pub envelope: EssrEnvelope,
    pub signature: String,        // CESR ML-DSA signature over envelope SAID
}
```

## Key Publication

ML-KEM encapsulation keys are published as SADStore pointer chains with kind `kels/sad/v1/keys/mlkem`. The SADStore replicates them network-wide via gossip.

**Publication flow:**
1. Generate ML-KEM keypair (768 or 1024, matched to signing key strength)
2. Store decapsulation key seed locally as CESR qb64 (`~/.kels-cli/keys/{prefix}/kem.key`)
3. Create `EncapsulationKeyPublication` SAD object, upload to SADStore
4. Create `SadPointer` chain (v0 inception + v1 with content_said), submit signed

**Discovery:** Anyone computes the pointer prefix offline via `compute_sad_pointer_prefix(kel_prefix, "kels/sad/v1/keys/mlkem")`, then queries any SADStore node for the latest record.

**Rotation:** Append a new version to the pointer chain with updated content_said. The tip record is always the current key.

### EncapsulationKeyPublication

```rust
pub struct EncapsulationKeyPublication {
    pub said: String,
    pub algorithm: String,          // "ML-KEM-768" or "ML-KEM-1024"
    pub encapsulation_key: String,  // CESR-encoded
}
```

## Exchange Messages

IPEX-style credential exchange layered on ESSR. All exchange messages use topic `kels/exchange/v1/topics/exchange`.

### Kinds

| Kind | Purpose | May start thread? |
|------|---------|-------------------|
| Apply | "I want credential of type X" | Yes |
| Offer | "I can issue credential X under these terms" | Yes |
| Agree | "I accept your offer" | No (references Offer) |
| Grant | "Here is the credential" | Yes (direct grant) |
| Admit | "Received and verified" | No (references Grant) |
| Reject | "Rejected" | No (references any) |

### ExchangeMessage (chained)

The first message in a thread is the v0 inception — its prefix becomes the thread identifier. Subsequent messages chain via `previous`.

```rust
pub struct ExchangeMessage {
    pub said: String,
    pub prefix: String,           // thread identifier
    pub previous: Option<String>, // SAID of prior message
    pub message_number: u64,      // sequence within thread
    pub kind: ExchangeKind,
    pub sender: String,
    pub recipient: String,
    pub created_at: StorageDatetime,
    pub nonce: String,
    pub payload: ExchangePayload,
}
```

### Payloads

| Kind | Key fields |
|------|------------|
| Apply | `schema`, optional `policy`, optional `disclosure` |
| Offer | `schema`, `policy`, optional `credential_preview`, optional `rules` |
| Agree | `offer` (SAID of accepted offer) |
| Grant | `credential`, `schema`, `policy`, optional `edge_schemas`/`edge_policies` |
| Admit | `grant` (SAID of acknowledged grant) |
| Reject | optional `reason` |

## End-to-End Flows

### Direct Grant (no negotiation)
1. Sender looks up recipient's ML-KEM key via SADStore
2. Wraps credential in `Grant` message, ESSR-seals, submits to mail service
3. Recipient fetches from source node, ESSR-opens, verifies credential, sends `Admit`

### Issuance with Negotiation
1. Holder sends `Apply` (schema request) via ESSR mail
2. Issuer receives, replies with `Offer` (terms)
3. Holder sends `Agree`
4. Issuer sends `Grant` with full credential
5. Holder verifies, sends `Admit`

### Presentation
1. Verifier sends `Apply` requesting credential by schema
2. Holder applies disclosure, sends `Grant` with disclosed view
3. Verifier verifies against KEL, sends `Admit`

## Crypto Primitives

All cryptographic operations use post-quantum algorithms:
- **ML-KEM-768/1024** — key encapsulation (via `cesr` crate)
- **ML-DSA-65/87** — digital signatures (via `cesr` crate)
- **AES-GCM-256** — authenticated encryption (via `kels_core::crypto::aead`)
- **Blake3** — key derivation with context `"kels/exchange/v1/protocols/essr"` (via `kels_core::crypto::aead::derive_aes_key`)

Algorithm strength pairing: ML-DSA-65 pairs with ML-KEM-768; ML-DSA-87 pairs with ML-KEM-1024.
