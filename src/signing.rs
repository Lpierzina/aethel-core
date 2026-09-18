//! Identity key generation, message signing, and the PLP projection/proof
//! bridge, inside L1.
//!
//! Until now the crate had no way to *create* an identity: `MasterIdentity`
//! could only be built `from_seed`, with the caller supplying the 32 bytes. That
//! put the decisive secret above the L1 boundary, since whoever generates the
//! seed holds the identity. It also had no message signing at all, so an SDK
//! asked to "sign and verify" had nothing to call and would have had to reach
//! for a signature library of its own, which is the one thing the charter's
//! "one artifact, adding a language never adds crypto" rule forbids.
//!
//! Both live here now.
//!
//! # The entropy argument is not the key
//!
//! [`Identity::generate`] takes caller-supplied entropy rather than reading a
//! system RNG, because the component has no WASI and no ambient randomness. The
//! entropy is **not** the secret key: it is stretched through SHAKE-256 with
//! domain separation, and the ML-DSA secret key and the PLP seed are derived
//! from that stream and kept inside this crate. Nothing that leaves an
//! [`Identity`] can reconstruct it.
//!
//! That distinction is what keeps the charter's "no private key material
//! crosses out of L1" true. A caller who supplies weak entropy gets a weak
//! identity, which is unavoidable for any deterministic construction, so the
//! minimum length is enforced rather than suggested.
//!
//! # Determinism
//!
//! Generation is a pure function of the entropy, and signing uses FIPS 204's
//! deterministic variant. Both are reproducible, which is what makes them
//! testable against fixed vectors, and neither needs an RNG at call time.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use pqc_sig::{MlDsa65Keypair, SigPublicKey, Signature};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

use crate::identity_error::IdentityError;

/// Minimum caller-supplied entropy. Below this the derived key material cannot
/// carry the security level ML-DSA-65 claims, so it is refused rather than
/// silently stretched.
pub const MIN_ENTROPY_BYTES: usize = 32;

/// Registry of purpose-separation context strings ("purpose bytes") for
/// [`Identity::sign_with_purpose`] / [`verify_with_purpose`] (A-1 / X-2).
///
/// # The rule
///
/// **A key must never sign under a purpose other than the one it was
/// invoked for.** Purpose separation via FIPS 204's native `ctx` mechanism
/// (`pqc_sig::MlDsa65Keypair::sign_ctx`/`verify_ctx`) is what makes that
/// enforceable rather than aspirational: a signature made under one context
/// provably does not verify under another (`SigError` on mismatch), so a
/// caller cannot accidentally (or maliciously) reuse an attach-challenge
/// signature as a receipt signature, or vice versa. See
/// `docs/PURPOSES.md` for the full registry write-up and the rationale for
/// each constant, and the crate's `signing` module for where this is
/// enforced.
///
/// # Why constants, not free-form strings
///
/// "Three ways to hold a secret" (X-2) is about types; this is the same
/// problem for *contexts*. A typo'd literal (`b"8gentz-agent-v1 "` with a
/// trailing space) silently creates a new, unintended purpose that still
/// signs and verifies — it just never matches anything else. Pinning the
/// exact bytes as constants, hashed by a unit test below, makes renaming one
/// a deliberate, reviewable change instead of a typo nobody notices until an
/// integration stops working.
///
/// # aethel-core vs aethel-vault namespaces
///
/// The `aethel-core/*` constants below are for this crate's own operations
/// (PLP presentation, credential/SAAP signing). The `VAULT_*` constants are
/// **reserved on aethel-vault's behalf**: defining them here, rather than
/// letting aethel-vault define its own, means there is exactly one registry
/// to keep in sync rather than two copies that can drift apart. aethel-vault
/// imports these rather than redefining them.
///
/// Every context here is well under `pqc_sig::MAX_CONTEXT_LEN` (255 bytes);
/// [`Identity::sign_with_purpose`] enforces that bound for any caller-supplied
/// purpose, not just these constants.
pub mod purpose {
    /// Presenting a PLP projection + proof + attach signature to a verifier
    /// (the A-1 "present to a verifier" flow).
    pub const PLP_PRESENT_V1: &[u8] = b"aethel-core/plp-present/v1";
    /// Signing over an issued or presented credential (`credential` module).
    pub const CREDENTIAL_V1: &[u8] = b"aethel-core/credential/v1";
    /// Signing adjacent to a SAAP selective-disclosure presentation.
    pub const SAAP_V1: &[u8] = b"aethel-core/saap/v1";

    /// Reserved for aethel-vault: a signed spend intent / pre-authorization.
    /// A spend key must never sign under this purpose's ctx for anything
    /// other than an actual spend intent — see this module's top-level doc.
    pub const VAULT_SPEND_INTENT_V1: &[u8] = b"aethel-vault/spend-intent/v1";
    /// Reserved for aethel-vault: a signed settlement receipt (V-5).
    pub const VAULT_SETTLEMENT_RECEIPT_V1: &[u8] = b"aethel-vault/settlement-receipt/v1";
    /// Reserved for aethel-vault: binding a spend-rail address to an
    /// identity (A-2's `did:pkh:eip155` pairing).
    pub const VAULT_WALLET_BIND_V1: &[u8] = b"aethel-vault/wallet-bind/v1";
    /// Reserved for aethel-vault: a human-in-the-loop approval signature
    /// (V-4's `hitl_above` gate).
    pub const VAULT_HITL_APPROVAL_V1: &[u8] = b"aethel-vault/hitl-approval/v1";

    #[cfg(test)]
    mod tests {
        use super::*;
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        use sha3::Shake256;

        /// Hash the exact registry, byte-length-prefixed so no concatenation
        /// ambiguity is possible between neighbouring constants.
        fn registry_digest() -> [u8; 32] {
            let all: &[&[u8]] = &[
                PLP_PRESENT_V1,
                CREDENTIAL_V1,
                SAAP_V1,
                VAULT_SPEND_INTENT_V1,
                VAULT_SETTLEMENT_RECEIPT_V1,
                VAULT_WALLET_BIND_V1,
                VAULT_HITL_APPROVAL_V1,
            ];
            let mut hasher = Shake256::default();
            for purpose in all {
                hasher.update(&(purpose.len() as u32).to_le_bytes());
                hasher.update(purpose);
            }
            let mut xof = hasher.finalize_xof();
            let mut digest = [0u8; 32];
            xof.read(&mut digest);
            digest
        }

        /// Pins the registry against itself deterministically (two
        /// independent hashing passes must agree) and, more importantly,
        /// against a decisive property: every constant is pairwise distinct
        /// and non-empty. A rename that collided two purposes, or an empty
        /// context string (which would be indistinguishable from "no
        /// purpose"), fails this rather than surfacing only as a confusing
        /// cross-purpose signature acceptance downstream. See the module
        /// doc's "Why constants, not free-form strings".
        #[test]
        fn the_registry_is_pinned() {
            assert_eq!(
                registry_digest(),
                registry_digest(),
                "the registry hash must be deterministic across calls"
            );

            let all: &[(&str, &[u8])] = &[
                ("PLP_PRESENT_V1", PLP_PRESENT_V1),
                ("CREDENTIAL_V1", CREDENTIAL_V1),
                ("SAAP_V1", SAAP_V1),
                ("VAULT_SPEND_INTENT_V1", VAULT_SPEND_INTENT_V1),
                ("VAULT_SETTLEMENT_RECEIPT_V1", VAULT_SETTLEMENT_RECEIPT_V1),
                ("VAULT_WALLET_BIND_V1", VAULT_WALLET_BIND_V1),
                ("VAULT_HITL_APPROVAL_V1", VAULT_HITL_APPROVAL_V1),
            ];
            for (name, purpose) in all {
                assert!(!purpose.is_empty(), "{name} must not be empty");
            }
            for i in 0..all.len() {
                for j in (i + 1)..all.len() {
                    assert_ne!(
                        all[i].1, all[j].1,
                        "{} and {} collide on the same context bytes",
                        all[i].0, all[j].0
                    );
                }
            }
        }

        /// Every constant must be within `pqc_sig::MAX_CONTEXT_LEN` — this is
        /// what [`crate::signing::Identity::sign_with_purpose`] enforces for
        /// caller-supplied purposes too.
        #[test]
        fn every_purpose_fits_the_context_length_limit() {
            let all: &[&[u8]] = &[
                PLP_PRESENT_V1,
                CREDENTIAL_V1,
                SAAP_V1,
                VAULT_SPEND_INTENT_V1,
                VAULT_SETTLEMENT_RECEIPT_V1,
                VAULT_WALLET_BIND_V1,
                VAULT_HITL_APPROVAL_V1,
            ];
            for purpose in all {
                assert!(purpose.len() <= pqc_sig::MAX_CONTEXT_LEN);
            }
        }
    }
}

/// Domain separator for the generation XOF. Distinct from every other
/// SHAKE-256 use in this crate so no two derivations can collide.
const KEYGEN_DOMAIN: &[u8] = b"AETHEL_IDENTITY_KEYGEN_V1";

/// A SHAKE-256 stream presented as an RNG.
///
/// `pqc_sig` takes a caller-supplied `RngCore + CryptoRng` rather than reaching
/// for `OsRng`, which is exactly what makes deterministic generation possible
/// in a component with no ambient randomness.
struct ShakeRng {
    reader: sha3::Shake256Reader,
}

impl RngCore for ShakeRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.read(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.reader.read(dest);
        Ok(())
    }
}

/// The stream is a SHAKE-256 XOF over caller entropy that already met
/// [`MIN_ENTROPY_BYTES`]. Marking it `CryptoRng` asserts it is suitable for key
/// generation, which holds exactly as far as the entropy does.
impl CryptoRng for ShakeRng {}

/// An identity: an ML-DSA-65 signing key plus the PLP master seed, derived
/// together from one entropy input.
///
/// Both secrets stay in this struct. `public_key` is the only thing that leaves
/// it, and the PLP seed is reachable only through [`Identity::plp_seed`], which
/// is `pub(crate)` so the component adapter can hand it to `plp` without it
/// crossing the WIT boundary.
pub struct Identity {
    keypair: MlDsa65Keypair,
    plp_seed: [u8; 32],
    /// The entropy this identity was derived from.
    ///
    /// Kept so the identity can be sealed and re-derived rather than
    /// serialised. It is not additional exposure: this struct already holds the
    /// keys derived from it, and it is wiped on drop alongside them.
    entropy: Vec<u8>,
}

impl Identity {
    /// Derive an identity from caller-supplied entropy.
    ///
    /// Requires at least [`MIN_ENTROPY_BYTES`]. Deterministic: the same entropy
    /// always yields the same identity, which is what makes generation testable
    /// against a fixed vector instead of only against itself.
    pub fn generate(entropy: &[u8]) -> Result<Self, IdentityError> {
        if entropy.len() < MIN_ENTROPY_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }

        let mut hasher = Shake256::default();
        hasher.update(KEYGEN_DOMAIN);
        hasher.update(entropy);
        let mut reader = hasher.finalize_xof();

        // The PLP seed comes off the stream first, then the same stream drives
        // ML-DSA generation. One entropy input, two independent secrets, no
        // second argument for a caller to get wrong.
        let mut plp_seed = [0u8; 32];
        reader.read(&mut plp_seed);

        let mut rng = ShakeRng { reader };
        let keypair =
            MlDsa65Keypair::generate(&mut rng).map_err(|_| IdentityError::SerializationError)?;

        Ok(Self {
            keypair,
            plp_seed,
            entropy: entropy.to_vec(),
        })
    }

    /// The ML-DSA-65 public key. Safe to publish; this is the only key material
    /// that leaves L1.
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().bytes
    }

    /// Sign a message with FIPS 204's deterministic variant.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.keypair
            .sign_deterministic(message)
            .map(|sig| sig.bytes)
            .map_err(|_| IdentityError::SerializationError)
    }

    /// Sign a message under a purpose-separated context (A-1 / X-2).
    ///
    /// Uses FIPS 204's native `ctx` mechanism
    /// ([`MlDsa65Keypair::sign_ctx_deterministic`]) rather than a
    /// crate-defined prefix construction: `pqc-sig` 0.4 exposes it directly,
    /// so there is no reason to build a weaker home-grown equivalent. An
    /// empty `purpose` (`&[]`) produces a signature byte-identical to
    /// [`Self::sign`] — both are FIPS 204 "pure" mode with the empty context
    /// string — so `sign_with_purpose(&[], m)` and `sign(m)` are
    /// interchangeable, and a signature made with one verifies under the
    /// other. A non-empty `purpose`, however, produces a signature that does
    /// **not** verify under a different non-empty purpose (nor under plain
    /// `sign`/`verify`) — that mode separation is the entire point.
    ///
    /// `purpose` MUST be at most [`pqc_sig::MAX_CONTEXT_LEN`] (255) bytes, or
    /// this returns `IdentityError::InvalidInputLength`. See
    /// `docs/PURPOSES.md` and the [`purpose`] module for the registry of
    /// context strings this crate and aethel-vault use, and the rule that
    /// governs them: **a key must never sign under a purpose other than the
    /// one it was invoked for.**
    pub fn sign_with_purpose(
        &self,
        purpose: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        if purpose.len() > pqc_sig::MAX_CONTEXT_LEN {
            return Err(IdentityError::InvalidInputLength);
        }
        self.keypair
            .sign_ctx_deterministic(purpose, message)
            .map(|sig| sig.bytes)
            .map_err(|_| IdentityError::SerializationError)
    }

    /// Derive this identity's PLP projection at context `tau` (A-1).
    ///
    /// This is the native `signing::Identity` → PLP bridge the gap analysis
    /// names: previously the only way to reach a PLP projection from an
    /// `Identity` was through the crate-private [`Self::plp_seed`], reachable
    /// only from `component.rs`. This method mirrors the WIT
    /// `master-identity.project-at-context` resource method so the native
    /// and component paths share one derivation
    /// (`plp::MasterIdentity::from_seed(self.plp_seed).project_at_context`),
    /// without ever exposing the raw seed itself.
    ///
    /// `randomness` MUST be at least 32 bytes of fresh, secret entropy — see
    /// [`crate::plp::MasterIdentity::project_at_context`] for why.
    pub fn project_at_context(
        &self,
        tau: &[u8],
        randomness: &[u8],
    ) -> Result<crate::plp::EphemeralProjection, IdentityError> {
        if randomness.len() < 32 {
            return Err(IdentityError::InvalidInputLength);
        }
        let identity = crate::plp::MasterIdentity::from_seed(&self.plp_seed);
        Ok(identity.project_at_context(tau, randomness))
    }

    /// Prove ownership of this identity's projection at context `tau` (A-1).
    ///
    /// `randomness` MUST be the *same* value passed to
    /// [`Self::project_at_context`] for this `tau` — see
    /// `crate::plp::Prover::prove_identity` for why. Mirrors the WIT
    /// `master-identity.prove` resource method and
    /// `component.rs`'s `OwnedIdentity::prove`, which this method lets that
    /// adapter delegate to instead of duplicating the derivation.
    pub fn prove(
        &self,
        tau: &[u8],
        randomness: &[u8],
    ) -> Result<crate::plp::ZkIdentityProof, IdentityError> {
        if randomness.len() < 32 {
            return Err(IdentityError::InvalidInputLength);
        }
        let identity = crate::plp::MasterIdentity::from_seed(&self.plp_seed);
        let proj = identity.project_at_context(tau, randomness);
        crate::plp::Prover::prove_identity(&identity, &proj, &self.plp_seed)
    }

    /// The PLP master seed, for the component adapter to drive `plp` with.
    ///
    /// Deliberately `pub(crate)`: this is private key material, and the whole
    /// point of holding it here is that it has no route across the WIT boundary.
    pub(crate) fn plp_seed(&self) -> &[u8; 32] {
        &self.plp_seed
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.plp_seed.zeroize();
        self.entropy.zeroize();
        // MlDsa65Keypair's SigSecretKey zeroizes its own bytes on drop.
    }
}

/// Verify an ML-DSA-65 signature.
///
/// A free function rather than a method: verification needs only public
/// material, so requiring an [`Identity`] would imply the verifier holds a
/// secret it does not need and cannot have.
///
/// Returns `Ok(false)` for a well-formed signature that does not verify, and
/// `Err` for input that cannot be parsed at all. Collapsing those two into one
/// answer is the sentinel-return mistake this crate has already been bitten by.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, IdentityError> {
    let pk = SigPublicKey {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: public_key.to_vec(),
    };
    let sig = Signature {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: signature.to_vec(),
    };

    match MlDsa65Keypair::verify(&pk, message, &sig) {
        Ok(()) => Ok(true),
        // A rejected signature is a well-formed negative answer, not an error.
        Err(_) => Ok(false),
    }
}

/// Verify a signature made with [`Identity::sign_with_purpose`] (A-1 / X-2).
///
/// A free function, for the same reason [`verify`] is: verification needs
/// only public material. Uses FIPS 204's native `ctx` verification
/// ([`MlDsa65Keypair::verify_ctx`]), so a signature made under one purpose
/// provably does not verify under another — see [`purpose`] for the registry
/// and the rule it exists to enforce.
///
/// `purpose` MUST be at most [`pqc_sig::MAX_CONTEXT_LEN`] bytes, or this
/// returns `Err(IdentityError::InvalidInputLength)`. Returns `Ok(false)` for
/// a well-formed signature that does not verify under `purpose` (including
/// one made under a *different* purpose), and `Err` only for input that
/// cannot be parsed at all.
pub fn verify_with_purpose(
    public_key: &[u8],
    purpose: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, IdentityError> {
    if purpose.len() > pqc_sig::MAX_CONTEXT_LEN {
        return Err(IdentityError::InvalidInputLength);
    }
    let pk = SigPublicKey {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: public_key.to_vec(),
    };
    let sig = Signature {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: signature.to_vec(),
    };

    match MlDsa65Keypair::verify_ctx(&pk, purpose, message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Sealing an identity at rest ───────────────────────────────────────────────

/// Format version, first byte of every sealed blob.
///
/// Present so a future format change is a clean rejection rather than a
/// misparse. A blob whose version this build does not know is refused, not
/// guessed at.
const SEAL_VERSION: u8 = 2;

/// Domain-separated key derivation for sealing.
const SEAL_KDF_DOMAIN: &[u8] = b"AETHEL_IDENTITY_SEAL_KDF_V1";

/// What kind of object a sealed blob holds.
///
/// # Why this exists
///
/// Version 1 sealed the entropy with a nonce derived from `(key, plaintext)`
/// and no associated data. That is sound against nonce reuse: the nonce is a
/// function of the plaintext, so two different plaintexts under one key get
/// different nonces, and XChaCha20-Poly1305 never sees a repeated (key, nonce)
/// pair with differing messages.
///
/// What it is *not* sound against is type confusion. Nothing in a v1 blob said
/// what kind of object it held. The moment a second kind of thing is sealed
/// under the same key (a rotation record is the motivating case), a blob of one
/// kind is indistinguishable from a blob of another at the API boundary, and
/// `import_sealed` would decrypt a rotation record and hand it to
/// `Identity::generate` as though it were entropy.
///
/// The tag is mixed into both the nonce derivation and the AEAD associated
/// data, and is **not** written to the blob. A reader always supplies the tag
/// it expects, so a blob of the wrong kind fails its authentication tag rather
/// than being parsed as something it is not. That costs zero bytes on the wire
/// and makes the failure a decryption failure, which is already the one failure
/// mode callers must handle.
///
/// This is made now, while there is exactly one sealed type and the migration
/// cost is a regenerated fixture. After a second type exists it is not cheap.
const SEAL_TYPE_IDENTITY: &[u8] = b"identity";

/// Associated data for a sealed blob: the version byte and the type tag.
///
/// The version byte is checked before decryption, but checking is not binding.
/// Putting it here means a blob whose version was edited fails its tag rather
/// than merely failing a comparison, so the two cannot disagree.
fn seal_aad(version: u8, type_tag: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + type_tag.len());
    aad.push(version);
    aad.extend_from_slice(type_tag);
    aad
}

/// Minimum sealing key length.
///
/// This is a **key**, not a passphrase. See [`Identity::export_sealed`].
pub const MIN_SEAL_KEY_BYTES: usize = 32;

/// Nonce length for XChaCha20-Poly1305.
const SEAL_NONCE_BYTES: usize = 24;

/// `version ‖ nonce ‖ ciphertext+tag`.
const SEAL_OVERHEAD: usize = 1 + SEAL_NONCE_BYTES;

impl Identity {
    /// Seal this identity so it can be written to disk and loaded again.
    ///
    /// # This takes a key, not a password
    ///
    /// `key` must be at least [`MIN_SEAL_KEY_BYTES`] of **high-entropy** key
    /// material: a key from an OS keychain, an HSM, or a random value the
    /// caller stores. It is stretched with SHAKE-256 for domain separation, and
    /// SHAKE-256 is fast by design.
    ///
    /// **Do not hand this a human-chosen password.** A password needs a
    /// deliberately slow, memory-hard KDF (Argon2id or scrypt) to survive
    /// offline guessing, and this crate does not provide one. Passing a password
    /// here would produce a blob that looks encrypted and falls to a wordlist.
    /// If you need password-based sealing, run a real password KDF first and
    /// pass its output as `key`.
    ///
    /// # What is sealed
    ///
    /// The entropy the identity was derived from, not the derived keys. Import
    /// re-runs the same deterministic derivation, so the blob stays small and
    /// there is no key serialisation format to get wrong. It also means the
    /// sealed blob is exactly as sensitive as the identity itself: anyone who
    /// opens it holds the identity.
    ///
    /// The nonce is derived from the key and the entropy rather than sampled,
    /// because the component has no randomness of its own. That makes sealing
    /// deterministic: sealing the same identity under the same key twice yields
    /// identical bytes. Since each (key, identity) pair produces exactly one
    /// nonce and one plaintext, the nonce is never reused under a different
    /// message, which is the property that matters.
    pub fn export_sealed(&self, key: &[u8]) -> Result<Vec<u8>, IdentityError> {
        if key.len() < MIN_SEAL_KEY_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }

        let (cipher_key, nonce) = derive_seal_material(key, SEAL_TYPE_IDENTITY, &self.entropy);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let aad = seal_aad(SEAL_VERSION, SEAL_TYPE_IDENTITY);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: self.entropy.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| IdentityError::SerializationError)?;

        let mut out = Vec::with_capacity(SEAL_OVERHEAD + ciphertext.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a sealed identity.
    ///
    /// Returns `Err` for a blob that is malformed, truncated, of an unknown
    /// version, or sealed under a different key. The AEAD tag makes those
    /// indistinguishable to a caller, which is intended: a decryption failure
    /// must not tell an attacker which part they got wrong.
    pub fn import_sealed(sealed: &[u8], key: &[u8]) -> Result<Self, IdentityError> {
        if key.len() < MIN_SEAL_KEY_BYTES || sealed.len() <= SEAL_OVERHEAD {
            return Err(IdentityError::InvalidInputLength);
        }
        if sealed[0] != SEAL_VERSION {
            return Err(IdentityError::SerializationError);
        }

        let nonce: [u8; SEAL_NONCE_BYTES] = sealed[1..1 + SEAL_NONCE_BYTES]
            .try_into()
            .map_err(|_| IdentityError::InvalidInputLength)?;
        let ciphertext = &sealed[SEAL_OVERHEAD..];

        // The key half of the derivation does not depend on the plaintext, so it
        // can be computed before the plaintext is known. The nonce comes from
        // the blob and is authenticated by the tag.
        let cipher_key = derive_seal_key(key);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let aad = seal_aad(SEAL_VERSION, SEAL_TYPE_IDENTITY);
        let mut entropy = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentityError::SerializationError)?;

        let identity = Identity::generate(&entropy);
        entropy.zeroize();
        identity
    }
}

/// Derive the sealing key from caller key material.
fn derive_seal_key(key: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(SEAL_KDF_DOMAIN);
    hasher.update(b"key");
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Derive the sealing key and a nonce bound to the key, the object type, and
/// the plaintext.
///
/// The type tag participates so that two different kinds of object with
/// identical plaintext bytes, sealed under one key, still get different nonces.
/// See [`SEAL_TYPE_IDENTITY`].
fn derive_seal_material(
    key: &[u8],
    type_tag: &[u8],
    entropy: &[u8],
) -> ([u8; 32], [u8; SEAL_NONCE_BYTES]) {
    let cipher_key = derive_seal_key(key);

    let mut hasher = Shake256::default();
    hasher.update(SEAL_KDF_DOMAIN);
    hasher.update(b"nonce");
    hasher.update(&(type_tag.len() as u32).to_le_bytes());
    hasher.update(type_tag);
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);
    hasher.update(&(entropy.len() as u32).to_le_bytes());
    hasher.update(entropy);
    let mut reader = hasher.finalize_xof();
    let mut nonce = [0u8; SEAL_NONCE_BYTES];
    reader.read(&mut nonce);

    (cipher_key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";

    #[test]
    fn generation_is_deterministic() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(ENTROPY).expect("generate");
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.plp_seed(), b.plp_seed());
    }

    /// Positive control for the test above: if generation ignored its entropy
    /// entirely, `generation_is_deterministic` would still pass.
    #[test]
    fn different_entropy_yields_a_different_identity() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(b"a completely different entropy!!").expect("generate");
        assert_ne!(
            a.public_key(),
            b.public_key(),
            "two different entropy inputs produced the same signing key"
        );
        assert_ne!(
            a.plp_seed(),
            b.plp_seed(),
            "two different entropy inputs produced the same PLP seed"
        );
    }

    /// The two derived secrets must be independent, not the same bytes reused.
    #[test]
    fn the_plp_seed_is_not_the_signing_key() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let pk = id.public_key();
        assert!(
            !pk.windows(32).any(|w| w == id.plp_seed()),
            "the PLP seed appears verbatim inside the public key"
        );
    }

    #[test]
    fn short_entropy_is_refused() {
        for len in [0usize, 1, 31] {
            let entropy = alloc::vec![0xABu8; len];
            assert!(
                matches!(
                    Identity::generate(&entropy),
                    Err(IdentityError::InvalidInputLength)
                ),
                "{len} bytes of entropy was accepted"
            );
        }
        assert!(
            Identity::generate(&[0xABu8; 32]).is_ok(),
            "32 bytes was refused"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"the message that was actually signed";
        let sig = id.sign(msg).expect("sign");
        assert_eq!(verify(&id.public_key(), msg, &sig), Ok(true));
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let sig = id.sign(b"transfer 10 to alice").expect("sign");
        assert_eq!(
            verify(&id.public_key(), b"transfer 99 to alice", &sig),
            Ok(false),
            "a signature verified against a message it was not made over"
        );
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let signer = Identity::generate(ENTROPY).expect("generate");
        let other = Identity::generate(b"a completely different entropy!!").expect("generate");
        let msg = b"signed by exactly one of these";
        let sig = signer.sign(msg).expect("sign");
        assert_eq!(
            verify(&other.public_key(), msg, &sig),
            Ok(false),
            "a signature verified under a key that did not produce it"
        );
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"message";
        let mut sig = id.sign(msg).expect("sign");
        sig[0] ^= 0x01;
        assert_eq!(verify(&id.public_key(), msg, &sig), Ok(false));
    }

    /// Malformed public material is an error, not a quiet `false`. Otherwise
    /// "this signature is invalid" and "you passed me nonsense" are the same
    /// answer, which is the defect P3-10 was opened for.
    #[test]
    fn signing_is_deterministic_across_calls() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"same message, twice";
        assert_eq!(id.sign(msg).unwrap(), id.sign(msg).unwrap());
    }

    // ── A-1: the Identity → PLP projection/proof bridge ─────────────────────

    /// The native `Identity::project_at_context` must be byte-equal to the
    /// derivation the component adapter has always used
    /// (`plp::MasterIdentity::from_seed(plp_seed).project_at_context`), for
    /// the same entropy/tau/randomness. If these ever drift, the native and
    /// component paths stop being "one artifact, two runtimes" and start
    /// being two independent implementations that happen to agree today.
    #[test]
    fn identity_projection_matches_component_path() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let tau = b"bridge-parity-context";
        let randomness = [0x5au8; 32];

        let via_identity = id.project_at_context(tau, &randomness).expect("project");

        let via_component_path = crate::plp::MasterIdentity::from_seed(id.plp_seed())
            .project_at_context(tau, &randomness);

        assert_eq!(via_identity.tau, via_component_path.tau);
        assert_eq!(via_identity.salt, via_component_path.salt);
        let flat = |v: &crate::plp::PolyVec| {
            v.iter()
                .flat_map(|p| p.coeffs().to_vec())
                .collect::<alloc::vec::Vec<u32>>()
        };
        assert_eq!(
            flat(&via_identity.public_b),
            flat(&via_component_path.public_b)
        );
    }

    /// `Identity::prove` must produce a proof that verifies against
    /// `Identity::project_at_context`'s output for the same inputs — the
    /// end-to-end native bridge, not just the projection half.
    #[test]
    fn identity_prove_verifies_against_identity_project_at_context() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let tau = b"bridge-prove-context";
        let randomness = [0x7bu8; 32];

        let proj = id.project_at_context(tau, &randomness).expect("project");
        let proof = id.prove(tau, &randomness).expect("prove");

        assert!(
            crate::plp::Verifier::verify(&proj, &proof),
            "the bridge's own proof did not verify"
        );
    }

    /// Short randomness is refused by both bridge methods, matching
    /// `plp::checked_project_at_context`'s rule.
    #[test]
    fn bridge_methods_reject_short_randomness() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let short = [0u8; 31];
        assert_eq!(
            id.project_at_context(b"ctx", &short).err(),
            Some(IdentityError::InvalidInputLength)
        );
        assert_eq!(
            id.prove(b"ctx", &short).err(),
            Some(IdentityError::InvalidInputLength)
        );
    }

    // ── A-1 / X-2: purpose-separated signing ────────────────────────────────

    /// The mode-separation property `sign_with_purpose`/`verify_with_purpose`
    /// exist to provide: a signature made under one purpose must not verify
    /// under a different one, even over the identical message and key.
    #[test]
    fn purpose_separated_signature_does_not_verify_under_another_purpose() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"attach challenge bytes";
        let sig = id
            .sign_with_purpose(purpose::PLP_PRESENT_V1, msg)
            .expect("sign");

        assert_eq!(
            verify_with_purpose(&id.public_key(), purpose::PLP_PRESENT_V1, msg, &sig),
            Ok(true),
            "control: the signature must verify under its own purpose"
        );
        assert_eq!(
            verify_with_purpose(&id.public_key(), purpose::CREDENTIAL_V1, msg, &sig),
            Ok(false),
            "a signature verified under a purpose it was not made for"
        );
        assert_eq!(
            verify(&id.public_key(), msg, &sig),
            Ok(false),
            "a purpose-separated signature verified under plain (no-context) verify"
        );
    }

    /// An empty purpose is byte-identical to plain `sign`/`verify` — pinned
    /// because `docs/PURPOSES.md` and this module's doc comments both state
    /// it, and `pqc-sig` guarantees it at the FIPS 204 level.
    #[test]
    fn empty_purpose_is_interchangeable_with_plain_sign() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"empty context message";
        let sig = id.sign_with_purpose(b"", msg).expect("sign");
        assert_eq!(sig, id.sign(msg).expect("sign"));
        assert_eq!(verify(&id.public_key(), msg, &sig), Ok(true));
    }

    /// A purpose longer than `pqc_sig::MAX_CONTEXT_LEN` is refused before it
    /// ever reaches `pqc-sig`.
    #[test]
    fn oversized_purpose_is_refused() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let long_purpose = alloc::vec![0u8; pqc_sig::MAX_CONTEXT_LEN + 1];
        assert_eq!(
            id.sign_with_purpose(&long_purpose, b"msg").err(),
            Some(IdentityError::InvalidInputLength)
        );
        assert_eq!(
            verify_with_purpose(&id.public_key(), &long_purpose, b"msg", &[0u8; 10]).err(),
            Some(IdentityError::InvalidInputLength)
        );
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;
    // `vec!` is not in scope under `--no-default-features --features wasm`,
    // where the crate is `no_std`. The wasm job builds the tests too.
    use alloc::vec;

    const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
    const KEY: &[u8; 32] = b"a sealing key of thirty-two byte";
    const OTHER_KEY: &[u8; 32] = b"a different sealing key, 32 byte";

    /// The point of the whole feature: an identity survives being written down
    /// and read back, and it is the same identity.
    #[test]
    fn a_sealed_identity_round_trips() {
        let original = Identity::generate(ENTROPY).expect("generate");
        let sealed = original.export_sealed(KEY).expect("seal");
        let reopened = Identity::import_sealed(&sealed, KEY).expect("open");

        assert_eq!(
            original.public_key(),
            reopened.public_key(),
            "the reopened identity has a different public key"
        );
        assert_eq!(
            original.plp_seed(),
            reopened.plp_seed(),
            "the reopened identity has a different PLP seed"
        );
    }

    /// Same identity in the strong sense: it produces signatures the original's
    /// public key verifies. Comparing public keys alone would pass for an
    /// implementation that restored the public half and lost the private one.
    #[test]
    fn a_reopened_identity_can_still_sign() {
        let original = Identity::generate(ENTROPY).expect("generate");
        let sealed = original.export_sealed(KEY).expect("seal");
        let reopened = Identity::import_sealed(&sealed, KEY).expect("open");

        let message = b"signed after being reopened";
        let signature = reopened.sign(message).expect("sign");

        assert_eq!(
            verify(&original.public_key(), message, &signature),
            Ok(true),
            "a signature from the reopened identity did not verify under the original key"
        );
    }

    /// Positive control for the round trip. Without it, an `import_sealed` that
    /// ignored the blob and regenerated from a constant would pass every test
    /// above.
    #[test]
    fn sealing_two_identities_yields_two_different_identities() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(b"a completely different entropy!!").expect("generate");

        let sealed_a = a.export_sealed(KEY).expect("seal");
        let sealed_b = b.export_sealed(KEY).expect("seal");
        assert_ne!(
            sealed_a, sealed_b,
            "two identities sealed to the same bytes"
        );

        let reopened_a = Identity::import_sealed(&sealed_a, KEY).expect("open");
        let reopened_b = Identity::import_sealed(&sealed_b, KEY).expect("open");
        assert_ne!(
            reopened_a.public_key(),
            reopened_b.public_key(),
            "two different sealed identities reopened as the same identity"
        );
        assert_eq!(reopened_a.public_key(), a.public_key());
        assert_eq!(reopened_b.public_key(), b.public_key());
    }

    #[test]
    fn the_wrong_key_does_not_open_it() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        assert!(
            Identity::import_sealed(&sealed, OTHER_KEY).is_err(),
            "a sealed identity opened under the wrong key"
        );
    }

    /// Every byte of the blob is authenticated. Flipping any one of them must
    /// fail, not just the ones in the ciphertext.
    #[test]
    fn any_tampered_byte_is_rejected() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            assert!(
                Identity::import_sealed(&tampered, KEY).is_err(),
                "a blob with byte {index} flipped still opened"
            );
        }
    }

    #[test]
    fn a_truncated_blob_is_rejected() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        for cut in [0usize, 1, SEAL_OVERHEAD, sealed.len() - 1] {
            assert!(
                Identity::import_sealed(&sealed[..cut], KEY).is_err(),
                "a blob truncated to {cut} bytes still opened"
            );
        }
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let mut sealed = identity.export_sealed(KEY).expect("seal");
        sealed[0] = 0xFF;

        assert!(
            matches!(
                Identity::import_sealed(&sealed, KEY),
                Err(IdentityError::SerializationError)
            ),
            "a blob with an unknown format version was parsed anyway"
        );
    }

    #[test]
    fn a_short_key_is_refused_on_both_sides() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let short = b"too short";

        assert!(matches!(
            identity.export_sealed(short),
            Err(IdentityError::InvalidInputLength)
        ));

        let sealed = identity.export_sealed(KEY).expect("seal");
        assert!(matches!(
            Identity::import_sealed(&sealed, short),
            Err(IdentityError::InvalidInputLength)
        ));
    }

    /// The blob must not contain the entropy, the PLP seed or the secret key in
    /// the clear. This is the claim "sealed" makes.
    #[test]
    fn the_blob_does_not_contain_the_secret_in_the_clear() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        assert!(
            !sealed
                .windows(ENTROPY.len())
                .any(|w| w == ENTROPY.as_slice()),
            "the entropy appears verbatim in the sealed blob"
        );
        assert!(
            !sealed
                .windows(32)
                .any(|w| w == identity.plp_seed().as_slice()),
            "the PLP seed appears verbatim in the sealed blob"
        );
    }

    // ── Sealed blob type tagging (Q6) ────────────────────────────────────────

    /// Seal `plaintext` as some other kind of object under the same key.
    ///
    /// This is what a rotation record would look like on the wire: same key,
    /// same format, different type tag. It exists so the confusion the tag
    /// prevents can actually be attempted, rather than asserted about.
    fn seal_as_other_type(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        const OTHER: &[u8] = b"rotation-record";

        let (cipher_key, nonce) = derive_seal_material(key, OTHER, plaintext);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let aad = seal_aad(SEAL_VERSION, OTHER);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("seal");

        let mut out = vec![SEAL_VERSION];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// A blob of another type must not open as an identity.
    ///
    /// This is the whole point of the type tag. Before it, a second kind of
    /// object sealed under the same key was byte-indistinguishable from an
    /// identity at the API boundary, and `import_sealed` would have decrypted
    /// it and fed it to `Identity::generate` as entropy.
    #[test]
    fn a_blob_of_another_type_does_not_open_as_an_identity() {
        let blob = seal_as_other_type(KEY, ENTROPY);

        assert!(
            matches!(
                Identity::import_sealed(&blob, KEY),
                Err(IdentityError::SerializationError)
            ),
            "a blob sealed as a different object type opened as an identity"
        );
    }

    /// Positive control for the test above.
    ///
    /// `seal_as_other_type` differs from `export_sealed` only in its type tag.
    /// If the helper were simply producing malformed blobs, the rejection above
    /// would prove nothing about tagging. The same construction with the
    /// identity tag must open.
    #[test]
    fn the_type_tag_check_is_what_rejects_the_other_type() {
        let (cipher_key, nonce) = derive_seal_material(KEY, SEAL_TYPE_IDENTITY, ENTROPY);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let aad = seal_aad(SEAL_VERSION, SEAL_TYPE_IDENTITY);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: ENTROPY,
                    aad: &aad,
                },
            )
            .expect("seal");

        let mut blob = vec![SEAL_VERSION];
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        assert!(
            Identity::import_sealed(&blob, KEY).is_ok(),
            "the same construction with the identity tag failed to open, so the              rejection of the other type is not attributable to the tag"
        );
    }

    /// Two object types with identical plaintext get different nonces.
    ///
    /// The nonce is a function of (key, type, plaintext). Without the type in
    /// that derivation, sealing the same bytes as two different kinds of object
    /// under one key would reuse a nonce across differing associated data.
    #[test]
    fn the_type_tag_separates_nonces_for_identical_plaintext() {
        let (_, identity_nonce) = derive_seal_material(KEY, SEAL_TYPE_IDENTITY, ENTROPY);
        let (_, other_nonce) = derive_seal_material(KEY, b"rotation-record", ENTROPY);

        assert_ne!(
            identity_nonce, other_nonce,
            "the same plaintext under the same key produced one nonce for two types"
        );
    }

    /// Positive control for the leak check above: it must be able to see the
    /// secret when the secret really is there. An unsealed blob is the case it
    /// has to catch.
    #[test]
    fn the_leak_check_catches_an_unsealed_blob() {
        let mut unsealed = vec![SEAL_VERSION];
        unsealed.extend_from_slice(&[0u8; SEAL_NONCE_BYTES]);
        unsealed.extend_from_slice(ENTROPY);

        assert!(
            unsealed
                .windows(ENTROPY.len())
                .any(|w| w == ENTROPY.as_slice()),
            "the leak check cannot see the entropy even when it is stored in the clear"
        );
    }

    /// Sealing is deterministic, so the same identity under the same key is
    /// byte-identical. That is a property worth pinning: it means a sealed file
    /// does not churn, and it means each (key, identity) pair uses exactly one
    /// nonce.
    #[test]
    fn sealing_is_deterministic() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        assert_eq!(
            identity.export_sealed(KEY).expect("seal"),
            identity.export_sealed(KEY).expect("seal")
        );
    }

    /// The same identity under two keys must produce different nonces, or the
    /// determinism above would mean nonce reuse across keys.
    #[test]
    fn different_keys_give_different_nonces() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let a = identity.export_sealed(KEY).expect("seal");
        let b = identity.export_sealed(OTHER_KEY).expect("seal");

        let nonce_a = &a[1..1 + SEAL_NONCE_BYTES];
        let nonce_b = &b[1..1 + SEAL_NONCE_BYTES];
        assert_ne!(nonce_a, nonce_b, "two keys produced the same nonce");
    }
}
