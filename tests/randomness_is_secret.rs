//! PLP `e_τ` and SAAP `r` are per-call secret randomness.
//!
//! Both are seeded from a caller-supplied `rho` that must be fresh, secret
//! entropy sampled anew per operation. These tests assert the properties that
//! guarantee gives: fresh randomness produces fresh outputs (each projection is
//! its own single-use M-LWE sample, each proof its own independent mask), and
//! the same randomness reproduces the same output (so a holder can recompute its
//! projection without storing it, and the scheme stays testable).

use aethel_core::plp::{EphemeralProjection, MasterIdentity};

// Distinct fixed rho per logical session. Real callers MUST sample these
// freshly; the tests fix them only to be reproducible.
const RHO_A: [u8; 32] = [0x11u8; 32];
const RHO_B: [u8; 32] = [0x22u8; 32];

// ── PLP ──────────────────────────────────────────────────────────────────────

/// Fresh randomness changes the projection; the same randomness reproduces it.
///
/// This test used to assert the opposite of its last case: that `A_τ` depended
/// only on τ and was stable across `rho`. That stability was the vulnerability
/// (AETHEL-F-02 / 0X3-95). Two projections at one τ shared one `A`, so the
/// samples `b_i = A·s + e_i` differed only in a centered error term and
/// averaging enough of them recovered `A·s`. The assertion is now inverted, and
/// `a_reused_tau_does_not_share_a_context_matrix` below is the substantive
/// version of it.
#[test]
fn plp_projection_is_fresh_per_rho_and_reproducible_given_rho() {
    let identity = MasterIdentity::from_seed(&[0x42u8; 32]);
    let tau = b"context-block-height-1000";

    let p_a1 = identity.project_at_context(tau, &RHO_A);
    let p_a2 = identity.project_at_context(tau, &RHO_A);
    let p_b = identity.project_at_context(tau, &RHO_B);

    // Compare every component of the rank-k vector, not just the first: a
    // projection that agreed on component 0 and differed elsewhere would pass
    // a first-component-only check while being a different projection.
    let b_coeffs = |p: &EphemeralProjection| {
        p.public_b.iter().flat_map(|q| q.coeffs().to_vec()).collect::<Vec<u32>>()
    };
    let a_coeffs = |p: &EphemeralProjection| {
        p.matrix_a
            .iter()
            .flat_map(|row| row.iter().flat_map(|q| q.coeffs().to_vec()))
            .collect::<Vec<u32>>()
    };

    assert_eq!(
        b_coeffs(&p_a1),
        b_coeffs(&p_a2),
        "same rho must reproduce the same projection"
    );
    assert_ne!(
        b_coeffs(&p_a1),
        b_coeffs(&p_b),
        "different rho must change the projection — e_τ carries per-call entropy"
    );
    assert_eq!(
        a_coeffs(&p_a1),
        a_coeffs(&p_a2),
        "same rho at one τ must reproduce the same context matrix"
    );
    assert_ne!(
        a_coeffs(&p_a1),
        a_coeffs(&p_b),
        "different rho at one τ must change A: a shared A is what makes repeated          projection at one τ recover the secret"
    );
    assert_ne!(
        p_a1.salt, p_b.salt,
        "different rho must give a different salt, which is what freshens A"
    );
}

/// Two distinct identities produce distinct projections under one τ — the
/// projection is bound to the secret, not just to the public context.
#[test]
fn plp_projections_are_identity_bound() {
    let tau = b"context-block-height-1000";
    let a = MasterIdentity::from_seed(&[0x01u8; 32]).project_at_context(tau, &RHO_A);
    let b = MasterIdentity::from_seed(&[0x02u8; 32]).project_at_context(tau, &RHO_A);
    let flat = |p: &EphemeralProjection| {
        p.public_b.iter().flat_map(|q| q.coeffs().to_vec()).collect::<Vec<u32>>()
    };
    assert_ne!(
        flat(&a),
        flat(&b),
        "distinct identities must not share a projection"
    );
}
