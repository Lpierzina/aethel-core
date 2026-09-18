//! `aethel-plp-1` — versioned, self-describing wire envelope for PLP
//! projections and proofs (A-4).
//!
//! # Why an envelope, not just the raw struct codecs
//!
//! [`crate::plp::EphemeralProjection::to_bytes`] and
//! [`crate::plp::ZkIdentityProof::to_bytes`] produce a fixed, un-tagged byte
//! layout: nothing in the bytes themselves says what they are or which
//! version of the layout produced them. That layout has already changed once
//! — the projection's `public_b` moved from a single ring element to a
//! rank-`MODULE_K` vector when the module rank moved from 1 to 4 — and a
//! caller holding old-layout bytes got a length mismatch with no indication
//! of *why*. A version byte turns the next such change into a clean,
//! diagnosable rejection instead of a misparse.
//!
//! `aethel-plp-1` wraps each struct's raw bytes in a small header:
//!
//! ```text
//! magic(4) ‖ version(1) ‖ kind(1) ‖ body_len(4, LE u32) ‖ body
//! ```
//!
//! `magic` is [`crate::EIAB_MAGIC`] (`b"ATH1"`), declared at the crate root
//! and unused until now. `kind` distinguishes a projection envelope from a
//! proof envelope, so the two cannot be swapped and silently misparsed into
//! each other's shape.
//!
//! # What this module does NOT do
//!
//! It does not pull in anything from [`crate::sampling`] — the enclave
//! sampler's types (`PlpProof`, `RejectionError`, `VectorK`) have no relation
//! to this wire format, and mixing them into the public verify surface was
//! itself part of the A-4 gap (host code copying internals it should never
//! have needed to see). `tests/no_debug_leak.rs`-style compile-time checks
//! pin that this module's public surface stays free of them.

extern crate alloc;

use alloc::vec::Vec;

use crate::identity_error::IdentityError;
use crate::plp::{pad_tau, EphemeralProjection, Verifier, ZkIdentityProof};

/// Magic header bytes for every `aethel-plp-1` envelope. Reuses
/// [`crate::EIAB_MAGIC`] ("Ephemeral Identity Attestation Bundle"), which was
/// declared at the crate root but used nowhere until this module.
pub const WIRE_MAGIC: &[u8; 4] = crate::EIAB_MAGIC;

/// Wire format version for the `aethel-plp-1` codec. The only version this
/// build knows how to decode.
pub const WIRE_VERSION_PLP1: u8 = 1;

/// Human-readable name of this wire codec, for logs, docs and error messages.
pub const CODEC_NAME: &str = "aethel-plp-1";

/// Length of an envelope header: `magic(4) + version(1) + kind(1) + len(4)`.
const HEADER_LEN: usize = 4 + 1 + 1 + 4;

/// What an envelope's body holds. Encoded as the header's `kind` byte so a
/// projection envelope can never be misparsed as a proof envelope (or vice
/// versa) even though both currently happen to have different fixed lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// An [`EphemeralProjection`], encoded via
    /// [`EphemeralProjection::to_bytes`].
    Projection = 0x01,
    /// A [`ZkIdentityProof`], encoded via [`ZkIdentityProof::to_bytes`].
    Proof = 0x02,
}

fn encode_envelope(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.push(WIRE_VERSION_PLP1);
    out.push(kind as u8);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Strip and validate the envelope header, returning the body slice.
///
/// Checks magic, version, kind and length before anything the caller-chosen
/// `Kind` disagrees with is even inspected. Each failure returns a distinct
/// [`IdentityError`] variant (`WireBadMagic` / `WireBadVersion` /
/// `WireLengthMismatch`) — see that enum's doc comments for why these are
/// native-only and collapse to `serialization-error` at the WIT boundary.
fn decode_envelope(bytes: &[u8], expected_kind: Kind) -> Result<&[u8], IdentityError> {
    if bytes.len() < HEADER_LEN {
        return Err(IdentityError::WireLengthMismatch);
    }
    if &bytes[0..4] != WIRE_MAGIC.as_slice() {
        return Err(IdentityError::WireBadMagic);
    }
    if bytes[4] != WIRE_VERSION_PLP1 {
        return Err(IdentityError::WireBadVersion);
    }
    if bytes[5] != expected_kind as u8 {
        // Wrong kind (projection bytes handed to the proof decoder, or vice
        // versa) is a shape error, not a magic/version/length one — folded
        // into `SerializationError` rather than given its own variant.
        return Err(IdentityError::SerializationError);
    }
    let declared_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let body = &bytes[HEADER_LEN..];
    if body.len() != declared_len {
        return Err(IdentityError::WireLengthMismatch);
    }
    Ok(body)
}

/// Encode a projection as an `aethel-plp-1` envelope.
pub fn encode_projection(projection: &EphemeralProjection) -> Vec<u8> {
    encode_envelope(Kind::Projection, &projection.to_bytes())
}

/// Decode an `aethel-plp-1` projection envelope.
///
/// Delegates the body to [`EphemeralProjection::from_bytes`] after validating
/// the header, so a decoded projection is subject to the same exact-length
/// and coefficient-range checks a caller invoking that function directly
/// would get.
pub fn decode_projection(bytes: &[u8]) -> Result<EphemeralProjection, IdentityError> {
    let body = decode_envelope(bytes, Kind::Projection)?;
    EphemeralProjection::from_bytes(body)
}

/// Encode a proof as an `aethel-plp-1` envelope.
pub fn encode_proof(proof: &ZkIdentityProof) -> Vec<u8> {
    encode_envelope(Kind::Proof, &proof.to_bytes())
}

/// Decode an `aethel-plp-1` proof envelope.
pub fn decode_proof(bytes: &[u8]) -> Result<ZkIdentityProof, IdentityError> {
    let body = decode_envelope(bytes, Kind::Proof)?;
    ZkIdentityProof::from_bytes(body)
}

/// Verify a PLP identity proof from `aethel-plp-1` wire bytes, binding the
/// verifier's own context (A-4).
///
/// This is the entry point the gap analysis names: a caller with only bytes
/// — no `sampling` internals, no hand-copied structs — decodes both
/// envelopes, and the *verifier's* `context` is checked against the
/// projection's carried `tau` rather than trusted from the wire. That is the
/// "purpose context on attach" binding: a projection built for one context
/// must not verify against another, even if the proof itself is honest.
///
/// # Verdict vs failure
///
/// Matches the crate's established rule ([`aethel-core.wit`]'s
/// `plp-verify`/`saap-verify-presentation` pattern): `Ok(false)` is a
/// verdict — a well-formed projection/proof pair that either does not verify
/// or was not made for `context` — while `Err` means the input could not be
/// decoded at all. A caller must not conflate the two.
///
/// [`aethel-core.wit`]: ../../wit/aethel-core.wit
pub fn verify_projection(
    projection: &[u8],
    proof: &[u8],
    context: &[u8],
) -> Result<bool, IdentityError> {
    let proj = decode_projection(projection)?;
    let zk = decode_proof(proof)?;

    if proj.tau != pad_tau(context) {
        return Ok(false);
    }

    Ok(Verifier::verify(&proj, &zk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plp::{MasterIdentity, Prover};

    fn honest_projection_and_proof(
        seed: &[u8; 32],
        tau: &[u8],
        rho: &[u8; 32],
    ) -> (EphemeralProjection, ZkIdentityProof) {
        let identity = MasterIdentity::from_seed(seed);
        let proj = identity.project_at_context(tau, rho);
        let proof = Prover::prove_identity(&identity, &proj, seed).expect("honest proving");
        (proj, proof)
    }

    #[test]
    fn projection_round_trips_through_the_envelope() {
        let (proj, _) = honest_projection_and_proof(&[0x11u8; 32], b"wire-ctx", &[0x22u8; 32]);
        let encoded = encode_projection(&proj);
        assert_eq!(&encoded[0..4], WIRE_MAGIC.as_slice());
        assert_eq!(encoded[4], WIRE_VERSION_PLP1);
        assert_eq!(encoded[5], Kind::Projection as u8);

        let decoded = decode_projection(&encoded).expect("decode");
        assert_eq!(decoded.tau, proj.tau);
        assert_eq!(decoded.salt, proj.salt);
    }

    #[test]
    fn proof_round_trips_through_the_envelope() {
        let (_, proof) = honest_projection_and_proof(&[0x33u8; 32], b"wire-ctx-2", &[0x44u8; 32]);
        let encoded = encode_proof(&proof);
        assert_eq!(encoded[5], Kind::Proof as u8);

        let decoded = decode_proof(&encoded).expect("decode");
        assert_eq!(decoded.challenge_c.coeffs(), proof.challenge_c.coeffs());
    }

    #[test]
    fn verify_projection_accepts_an_honest_pair() {
        let seed = [0x55u8; 32];
        let tau = b"verify-projection-honest";
        let (proj, proof) = honest_projection_and_proof(&seed, tau, &[0x66u8; 32]);

        let result = verify_projection(&encode_projection(&proj), &encode_proof(&proof), tau);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn verify_projection_rejects_the_wrong_context() {
        let seed = [0x55u8; 32];
        let tau = b"verify-projection-honest";
        let (proj, proof) = honest_projection_and_proof(&seed, tau, &[0x66u8; 32]);

        let result = verify_projection(
            &encode_projection(&proj),
            &encode_proof(&proof),
            b"a-different-context",
        );
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn verify_projection_rejects_a_tampered_proof() {
        let seed = [0x77u8; 32];
        let tau = b"verify-projection-tamper";
        let (proj, proof) = honest_projection_and_proof(&seed, tau, &[0x88u8; 32]);

        let mut proof_bytes = encode_proof(&proof);
        let last = proof_bytes.len() - 1;
        proof_bytes[last] ^= 0x01;

        // Either the tamper breaks decoding (range/shape) or it decodes and
        // fails to verify — both are acceptable; what must NOT happen is a
        // `true` verdict.
        if let Ok(v) = verify_projection(&encode_projection(&proj), &proof_bytes, tau) {
            assert!(!v, "a tampered proof verified");
        }
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let (proj, _) = honest_projection_and_proof(&[0x99u8; 32], b"magic-ctx", &[0xAAu8; 32]);
        let mut encoded = encode_projection(&proj);
        encoded[0] ^= 0xFF;
        assert_eq!(
            decode_projection(&encoded).err(),
            Some(IdentityError::WireBadMagic)
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let (proj, _) = honest_projection_and_proof(&[0xBBu8; 32], b"version-ctx", &[0xCCu8; 32]);
        let mut encoded = encode_projection(&proj);
        encoded[4] = 0xFF;
        assert_eq!(
            decode_projection(&encoded).err(),
            Some(IdentityError::WireBadVersion)
        );
    }

    #[test]
    fn declared_length_mismatch_is_rejected() {
        let (proj, _) = honest_projection_and_proof(&[0xDDu8; 32], b"length-ctx", &[0xEEu8; 32]);
        let mut encoded = encode_projection(&proj);
        // Corrupt the declared body length field without touching the body.
        encoded[6] = 0xFF;
        encoded[7] = 0xFF;
        assert_eq!(
            decode_projection(&encoded).err(),
            Some(IdentityError::WireLengthMismatch)
        );
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        assert_eq!(
            decode_projection(&[0u8; 3]).err(),
            Some(IdentityError::WireLengthMismatch)
        );
    }

    #[test]
    fn decode_projection_refuses_proof_shaped_bytes() {
        let (_, proof) = honest_projection_and_proof(&[0x12u8; 32], b"kind-ctx", &[0x34u8; 32]);
        let proof_bytes = encode_proof(&proof);
        assert_eq!(
            decode_projection(&proof_bytes).err(),
            Some(IdentityError::SerializationError)
        );
    }
}
