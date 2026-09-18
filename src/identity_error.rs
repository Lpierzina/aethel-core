//! Rust-side mirror of the `identity-error` variant defined in the
//! `aethel:core` WIT world ([`wit/aethel-core.wit`](../../wit/aethel-core.wit)).
//!
//! Kept as one flat, closed set — not a hierarchy — matching the WIT design.
//!
//! # Which variants a caller can actually observe
//!
//! Five of the eight are reachable through the component today, and are driven
//! end-to-end by tests in `tests/component_execution.rs`:
//! `InvalidInputLength`, `SerializationError`, `ThresholdNotMet`,
//! `RejectionSamplingFailed`, and `InvalidShareSet`.
//!
//! Three are **reserved and currently unreachable**: [`Self::NormBoundViolation`],
//! [`Self::ChallengeMismatch`] and [`Self::InvalidAttributeCommitment`]. They
//! are named here deliberately rather than removed — see their individual doc
//! comments and `component_error_variant_reachability` in
//! `tests/component_execution.rs`, which pins the split so it cannot drift
//! silently.
//!
//! `RejectionSamplingFailed` is reachable but not forceable from outside: it
//! needs all 16 rejection-sampling iterations to fail, which is negligible for
//! honest parameters. It is exercised natively instead.

use crate::saap::SaapValidationError;
use crate::sampling::RejectionError;

/// Closed set of failure reasons across all `aethel:core` WIT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// A byte-slice input was too short or malformed for the operation.
    InvalidInputLength,
    /// Serialization or deserialization of a proof/projection failed.
    SerializationError,
    /// Rejection sampling exhausted its fixed iteration ceiling.
    RejectionSamplingFailed,
    /// A response vector's infinity norm exceeded the rejection bound.
    ///
    /// **Reserved, no producer today.** Reachable only through the superseded
    /// `saap` verifier, which is crate-private and not exported by the
    /// component. `saap-verify-presentation` reports a well-formed proof that
    /// does not verify as `ok(false)`, never as an error, because "this does
    /// not verify" is a verdict and not a failure to reach one.
    ///
    /// Kept for the predicate relation (RFC §5.6 relation 3), which is
    /// deliberately deferred and will need to distinguish a range proof whose
    /// response is out of bounds from one that simply does not hold.
    NormBoundViolation,
    /// A recomputed Fiat-Shamir challenge did not match the proof's challenge.
    ///
    /// **Reserved, no producer today.** Same reasoning as
    /// [`Self::NormBoundViolation`].
    ChallengeMismatch,
    /// A disclosed attribute did not match its vector commitment.
    ///
    /// **Reserved, no producer today.** Same reasoning as
    /// [`Self::NormBoundViolation`].
    InvalidAttributeCommitment,
    /// Fewer than the threshold number of shares were supplied for reconstruction.
    ThresholdNotMet,
    /// The supplied shares are not a valid, authenticated share set. Three
    /// causes, all folded into one variant because they share a consequence —
    /// none of them may reconstruct:
    ///
    /// - an evaluation index appears more than once
    /// - more shares were supplied than the scheme issues
    /// - a share's Merkle proof does not check out against the caller-supplied
    ///   root (0X3-105)
    ///
    /// Distinct from [`Self::SerializationError`] on purpose. "This share is
    /// malformed" and "you sent the same share twice" (or "this share was
    /// never part of the sharing it claims to be") are different failures
    /// with different fixes, and collapsing them is the same sentinel-flattening
    /// this crate treats as a defect class elsewhere. Lagrange interpolation
    /// over a repeated evaluation point is undefined, and interpolation over a
    /// share nobody ever split is defined but meaningless; a share set
    /// carrying either does not reconstruct to the shared secret, so it must
    /// not reconstruct at all.
    InvalidShareSet,

    // ── A-4: `aethel-plp-1` wire envelope (native-only, no WIT producer) ────
    //
    // These four are new in 0.6.0 and reachable only through `wire::{decode_projection,
    // decode_proof, verify_projection}` and the raw struct codecs
    // (`EphemeralProjection::from_bytes` / `ZkIdentityProof::from_bytes`) they build
    // on. None of them has a WIT producer: `wit/aethel-core.wit`'s `identity-error`
    // variant is unchanged (adding a case there would be a breaking ordinal shift
    // for every existing importer), so `component.rs`'s `From<IdentityError> for
    // WitError` collapses all four to `WitError::SerializationError` at the
    // component boundary — the same fold the RESERVED variants above already use,
    // just in the other direction (many native causes, one WIT effect, rather than
    // one native cause with several WIT-side reservations).
    //
    // Kept distinct on the native side because "wrong magic", "wrong version",
    // "declared length disagrees with what's actually there", and "a coefficient
    // isn't a member of R_q" are different failures with different fixes for a
    // native caller debugging a bad wire payload, even though a WASM component
    // caller sees one undifferentiated `serialization-error`.
    /// An `aethel-plp-1` envelope's magic bytes did not match
    /// [`crate::EIAB_MAGIC`].
    WireBadMagic,
    /// An `aethel-plp-1` envelope declared a version byte this build does not
    /// recognize. See `wire::WIRE_VERSION_PLP1`.
    WireBadVersion,
    /// An `aethel-plp-1` envelope was too short to contain its header, or its
    /// declared body length did not match the number of bytes actually
    /// present after the header.
    WireLengthMismatch,
    /// A decoded polynomial coefficient was `>= Q`, i.e. not a member of
    /// `R_q = Z_q[X]/(X^N + 1)`. Raised by [`crate::plp::EphemeralProjection::from_bytes`]
    /// and [`crate::plp::ZkIdentityProof::from_bytes`] before any arithmetic
    /// ever touches the value — `add_mod`/`sub_mod` assume reduced inputs, so
    /// admitting an out-of-range coefficient would be a robustness defect
    /// even though the Fiat-Shamir challenge recomputation means it is not,
    /// by itself, a soundness break.
    CoefficientOutOfRange,
}

impl From<SaapValidationError> for IdentityError {
    fn from(e: SaapValidationError) -> Self {
        match e {
            SaapValidationError::NormBoundViolation => IdentityError::NormBoundViolation,
            SaapValidationError::ChallengeMismatch => IdentityError::ChallengeMismatch,
            SaapValidationError::InvalidAttributeCommitment => {
                IdentityError::InvalidAttributeCommitment
            }
        }
    }
}

impl From<RejectionError> for IdentityError {
    fn from(e: RejectionError) -> Self {
        match e {
            RejectionError::AllIterationsRejected => IdentityError::RejectionSamplingFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htss::SecretSharer;
    use crate::plp::{checked_project_at_context, EphemeralProjection};

    #[test]
    fn every_saap_validation_error_maps() {
        assert_eq!(
            IdentityError::from(SaapValidationError::NormBoundViolation),
            IdentityError::NormBoundViolation
        );
        assert_eq!(
            IdentityError::from(SaapValidationError::ChallengeMismatch),
            IdentityError::ChallengeMismatch
        );
        assert_eq!(
            IdentityError::from(SaapValidationError::InvalidAttributeCommitment),
            IdentityError::InvalidAttributeCommitment
        );
    }

    #[test]
    fn rejection_sampling_failure_maps() {
        assert_eq!(
            IdentityError::from(RejectionError::AllIterationsRejected),
            IdentityError::RejectionSamplingFailed
        );
    }

    // ── InvalidInputLength: driven through checked_project_at_context ──────────

    // Fresh per-projection randomness for the error term e_τ. In tests a fixed
    // 32-byte value is fine; in production this MUST be freshly sampled.
    const RHO: [u8; 32] = [0x5au8; 32];

    #[test]
    fn invalid_input_length_from_a_short_secret() {
        // One byte short of the required 32-byte seed (randomness is valid, so
        // the failure is unambiguously about the secret length).
        let short_secret = [0u8; 31];
        let result = checked_project_at_context(&short_secret, b"context", &RHO);
        assert_eq!(result.err(), Some(IdentityError::InvalidInputLength));
    }

    #[test]
    fn invalid_input_length_from_short_randomness() {
        // A valid secret but under-length randomness must also be rejected:
        // silently proceeding would seed e_τ from too little entropy.
        let secret = [0x42u8; 32];
        let short_rho = [0u8; 31];
        let result = checked_project_at_context(&secret, b"context", &short_rho);
        assert_eq!(result.err(), Some(IdentityError::InvalidInputLength));
    }

    #[test]
    fn checked_project_at_context_succeeds_with_a_valid_secret() {
        // The validation isn't just rejecting everything — a correctly-sized
        // secret and randomness must actually produce a projection.
        let secret = [0x42u8; 32];
        assert!(checked_project_at_context(&secret, b"context", &RHO).is_ok());
    }

    // ── SerializationError: driven through EphemeralProjection::from_bytes ─────

    #[test]
    fn serialization_error_from_truncated_projection_bytes() {
        let truncated = [0u8; 10];
        let result = EphemeralProjection::from_bytes(&truncated);
        assert_eq!(result.err(), Some(IdentityError::SerializationError));
    }

    #[test]
    fn ephemeral_projection_round_trips_through_bytes() {
        let secret = [0x99u8; 32];
        let projection = checked_project_at_context(&secret, b"round-trip", &RHO).unwrap();
        let bytes = projection.to_bytes();
        let decoded =
            EphemeralProjection::from_bytes(&bytes).expect("well-formed bytes must decode");
        assert_eq!(decoded.tau, projection.tau);
        // Compare the whole rank-k matrix and vector. Checking one cell would
        // let a codec that dropped the other components round-trip cleanly.
        let flat_a = |p: &EphemeralProjection| {
            p.matrix_a
                .iter()
                .flat_map(|row| row.iter().flat_map(|q| q.coeffs().to_vec()))
                .collect::<alloc::vec::Vec<u32>>()
        };
        let flat_b = |p: &EphemeralProjection| {
            p.public_b
                .iter()
                .flat_map(|q| q.coeffs().to_vec())
                .collect::<alloc::vec::Vec<u32>>()
        };
        assert_eq!(flat_a(&decoded), flat_a(&projection));
        assert_eq!(flat_b(&decoded), flat_b(&projection));
    }

    // ── ThresholdNotMet: driven through SecretSharer::reconstruct_secret_checked ─

    #[test]
    fn threshold_not_met_with_fewer_than_three_shares() {
        let shares = SecretSharer::split_secret(12_345u64, 3, 5, 0xdead_beef);
        let result = SecretSharer::reconstruct_secret_checked(&shares[0..2]);
        assert_eq!(result.err(), Some(IdentityError::ThresholdNotMet));
    }

    #[test]
    fn reconstruct_secret_checked_succeeds_at_the_threshold() {
        let secret = 12_345u64;
        let shares = SecretSharer::split_secret(secret, 3, 5, 0xdead_beef);
        let result = SecretSharer::reconstruct_secret_checked(&shares[0..3]);
        assert_eq!(result, Ok(secret));
    }
}
