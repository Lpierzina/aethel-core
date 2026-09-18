//! SAAP as specified: a BDLOP credential and three linked relations.
//!
//! This is P3-11 (0X3-79). The previous implementation proved a single relation
//! against a SAAP-local public key that was an exact linear image of the secret
//! and therefore unsafe to publish. RFC `AETHEL-SPEC-001` §5.6 specifies
//! something different: a proof over a real issued credential, anchored on the
//! PLP projection `b_τ`.
//!
//! # The three relations
//!
//! 1. **Identity linkage.** Knowledge of `(s, e_τ)` with `b_τ = A_τ·s + e_τ`.
//! 2. **Credential membership.** Knowledge of short `r*` and hidden messages
//!    with `t_blind − (0‖m_pub) = B_1·r* + (0‖m_hidden)`.
//! 3. **Predicate satisfaction.** Range and set-membership over hidden numeric
//!    attributes. **Not implemented.** See [`the predicate relation`](#predicates).
//!
//! # What "linked" means here, concretely
//!
//! A shared Fiat-Shamir challenge alone does not link two relations: it binds
//! them to one transcript, but a prover could still satisfy each with unrelated
//! witnesses. The linkage is a **shared witness**. Credential slot 0 is reserved
//! for the holder's master secret `s`, it is always hidden, and its mask is the
//! same `y_s` used by relation 1. So `z_m[0]` and `z_s` are the same value by
//! construction, and the verifier checks that they are equal. A credential
//! issued to one identity therefore cannot be presented by another.
//!
//! # Reconciling the two algebraic settings
//!
//! The issue flagged this as the main design decision. PLP works in `R_q` with a
//! single polynomial; SAAP's commitment works in the module `R_q^{l+n}`. Rather
//! than lift PLP into the module (which would invent structure that the PLP
//! construction does not have) the two relations stay in their own settings and
//! are linked by a challenge `c ∈ R_q`, which multiplies correctly in both, and
//! by the shared `s` described above.
//!
//! # Deviation from RFC §5.7, and why
//!
//! Registered as D-08 in `docs/DEVIATIONS.md`, with every other place this
//! crate and its specifications disagree.
//!
//! The RFC's verifier computes `W_2' = A_τ·z_s − c·b_τ` and expects it to equal
//! the prover's `W_2`. It does not. Expanding with `b_τ = A_τ·s + e_τ`:
//!
//! ```text
//! A_τ·z_s − c·b_τ = A_τ·(y_s + c·s) − c·(A_τ·s + e_τ) = A_τ·y_s − c·e_τ
//! ```
//!
//! The error term leaves a residual `−c·e_τ`. A Fiat-Shamir verifier that
//! recomputes the challenge from `W_2'` cannot tolerate that residual, because
//! the hash of an approximately-correct commitment is not approximately the
//! challenge. `plp::Verifier` handles this by sending `W` in the proof and
//! accepting `‖A_τ·z − c·b_τ − W‖ < 2β`, which is a *relaxed* check.
//!
//! This implementation removes the residual instead of tolerating it: `e_τ`
//! becomes part of the witness. The prover masks it as `y_e`, commits
//! `W_2 = A_τ·y_s + y_e`, and responds `z_e = y_e + c·e_τ`. Then
//!
//! ```text
//! A_τ·z_s + z_e − c·b_τ = A_τ·y_s + y_e = W_2
//! ```
//!
//! exactly, and the challenge can be recomputed. `e_τ` is not stored anywhere:
//! it is a deterministic function of the projection randomness and τ, so the
//! prover re-derives it via [`plp::derive_error_tau`].
//!
//! # Message masks are not small, and that is deliberate
//!
//! BDLOP requires only the *randomness* `r` to be short. Attribute values are
//! not, so masking them with a short `y_m` would not hide them. Attribute masks
//! are drawn uniformly from all of `R_q`, which hides the message perfectly and
//! needs no rejection sampling. Slot 0 is the exception: it holds `s`, which is
//! CBD-small, and shares the short mask `y_s` so that the linkage check works.
//!
//! Soundness for the message components does not need shortness. Extraction from
//! two transcripts yields `Δz_r = Δc·r*` short, which is the relaxed opening
//! BDLOP is proved under.
//!
//! # Predicates
//!
//! Relation 3 is **not implemented**. Nothing in this module evaluates a range
//! or set-membership predicate, and no function claims to. It is scoped out
//! explicitly rather than stubbed, so that no caller can mistake an unevaluated
//! predicate for a satisfied one.
//!
//! It is also not implementable here. A range claim needs a quadratic constraint
//! that a linear sigma protocol cannot express, the verification relation holds
//! only modulo `q` and so says nothing about a 64-bit value, and shortness of a
//! masked response bounds `c * w` rather than `w`. What two accepting transcripts
//! establish is a relaxed opening, which is what BDLOP binding is proved under and
//! is adequate for the two relations that are built. It expresses no range. See
//! `docs/PREDICATE-PROOFS.md`.

use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

use crate::identity_error::IdentityError;
use crate::plp;
use crate::saap::{
    hash_to_challenge_from_xof, mod_q, poly_add, poly_mul_negacyclic, poly_sub, Polynomial,
    PARAM_GAMMA1, PARAM_Q, REJECTION_BOUND, RING_N,
};

/// Dimension of the commitment randomness `r`.
pub const CRED_L: usize = 4;

/// Number of attribute slots available to an issuer.
pub const CRED_ATTRIBUTES: usize = 8;

/// Message slots: slot 0 is the identity binding, slots 1..=8 the attributes.
pub const CRED_SLOTS: usize = CRED_ATTRIBUTES + 1;

/// Rows of `B_1`, and the dimension of `t_cred`.
pub const CRED_T: usize = CRED_L + CRED_SLOTS;

/// Slot reserved for the holder's master secret. Never disclosable.
pub const IDENTITY_SLOT: usize = 0;

/// Rejection-sampling attempts before giving up.
///
/// Exhausting this returns an error. It deliberately does **not** fall back to
/// returning the last candidate: a response that failed the norm check is
/// exactly the value rejection sampling exists to withhold, and emitting one
/// leaks the secret it was protecting.
/// Rejection-sampling attempts before `prove` refuses.
///
/// Sized from the acceptance rate, not picked round. A presentation carries 12
/// short responses at module rank 4 (`z_r` is `CRED_L`, `z_s` and `z_e` are
/// `MODULE_K` each), so 3072 coefficients must all fall inside `γ₁ - β`. That
/// accepts about 16% of the time, and 32 attempts would leave roughly 1 honest
/// presentation in 270 failing outright.
///
/// At 192 the chance of exhausting the budget is about 2e-15. The cost is
/// worst-case latency only: the expected number of attempts is about 6, and
/// 99.9% of presentations finish within 40.
///
/// This scales with `MODULE_K`. Raising the rank again without revisiting this
/// number reintroduces the same availability problem.
const MAX_REJECTION_ITERATIONS: usize = 192;

const DOMAIN_B1: &[u8] = b"AETHEL_SAAP_B1_V2";
const DOMAIN_ISSUER_PUBLIC: &[u8] = b"AETHEL_SAAP_ISSUER_PUBLIC_V1";
const DOMAIN_CHALLENGE: &[u8] = b"AETHEL_SAAP_CHALLENGE_V3";
const DOMAIN_ISSUE_RANDOMNESS: &[u8] = b"AETHEL_SAAP_ISSUE_R_V1";
const DOMAIN_BLIND: &[u8] = b"AETHEL_SAAP_BLIND_V1";
const DOMAIN_MASK: &[u8] = b"AETHEL_SAAP_PROOF_MASK_V2";

// ── Conversion between the PLP and SAAP polynomial representations ───────────

/// `plp::Poly` stores coefficients as `u32` in `[0, q)`; `saap::Polynomial`
/// stores them centred as `i32`. Both are `R_q = Z_q[X]/(X^256+1)` with the
/// same `q` and `N`, so this is a representation change, not a conversion
/// between different objects.
/// Convert a rank-`k` plp vector into this module's polynomial type.
fn from_plp_vec(v: &plp::PolyVec) -> [Polynomial; plp::MODULE_K] {
    let mut out = [Polynomial::zero(); plp::MODULE_K];
    for (slot, vi) in out.iter_mut().zip(v.iter()) {
        *slot = from_plp(vi);
    }
    out
}

/// Convert a `k × k` plp matrix into this module's polynomial type.
fn from_plp_mat(m: &plp::PolyMat) -> [[Polynomial; plp::MODULE_K]; plp::MODULE_K] {
    let mut out = [[Polynomial::zero(); plp::MODULE_K]; plp::MODULE_K];
    for (orow, mrow) in out.iter_mut().zip(m.iter()) {
        for (cell, src) in orow.iter_mut().zip(mrow.iter()) {
            *cell = from_plp(src);
        }
    }
    out
}

/// `A · v` over this module's polynomial type.
fn mat_vec(
    a: &[[Polynomial; plp::MODULE_K]; plp::MODULE_K],
    v: &[Polynomial; plp::MODULE_K],
) -> [Polynomial; plp::MODULE_K] {
    let mut out = [Polynomial::zero(); plp::MODULE_K];
    for (slot, row) in out.iter_mut().zip(a.iter()) {
        let mut acc = Polynomial::zero();
        for (cell, vj) in row.iter().zip(v.iter()) {
            acc = poly_add(&acc, &poly_mul_negacyclic(cell, vj));
        }
        *slot = acc;
    }
    out
}

fn from_plp(p: &plp::Poly) -> Polynomial {
    let mut out = Polynomial::zero();
    for i in 0..RING_N {
        out.coeffs[i] = mod_q(p.coeffs[i] as i64);
    }
    out
}

// ── Sampling ─────────────────────────────────────────────────────────────────

/// Centred binomial sample with η=2: coefficients in [-2, 2].
fn sample_cbd(xof: &mut impl XofReader) -> Polynomial {
    let mut p = Polynomial::zero();
    let mut buf = [0u8; 1];
    for i in 0..RING_N {
        xof.read(&mut buf);
        let a = (buf[0] & 0x03).count_ones() as i32;
        let b = ((buf[0] >> 2) & 0x03).count_ones() as i32;
        p.coeffs[i] = a - b;
    }
    p
}

/// Uniform in `[-γ₁, γ₁]`. Used for witnesses that must stay short.
fn sample_short_mask(xof: &mut impl XofReader) -> Polynomial {
    let mut p = Polynomial::zero();
    let range = 2 * PARAM_GAMMA1 as u32 + 1;
    let mut i = 0usize;
    while i < RING_N {
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        let val = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32 & 0x7F) << 16);
        if val < range {
            p.coeffs[i] = val as i32 - PARAM_GAMMA1;
            i += 1;
        }
    }
    p
}

/// Uniform over all of `R_q`. Used to mask attribute messages, which are not
/// short and so cannot be hidden by a short mask.
fn sample_uniform(xof: &mut impl XofReader) -> Polynomial {
    let mut p = Polynomial::zero();
    let q = PARAM_Q as u32;
    let mut i = 0usize;
    while i < RING_N {
        // 23 bits, matching q = 2^23 - 2^13 + 1. This is the same construction
        // `plp.rs` uses, and it must stay the same: masking wider than the
        // modulus does not make the output more uniform, it only rejects more.
        //
        // This previously read 4 bytes and masked to 31 bits, then rejected
        // anything >= q. Acceptance was q / 2^31, about 0.39%, so it drew
        // roughly 256 samples per accepted coefficient and cost 44.6 ms to
        // expand the 52 KB issuer matrix. At 23 bits acceptance is q / 2^23,
        // about 99.9%.
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        let val =
            (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32 & 0x7F) << 16);
        if val < q {
            p.coeffs[i] = mod_q(val as i64);
            i += 1;
        }
    }
    p
}

fn xof_for(domain: &[u8], parts: &[&[u8]]) -> sha3::Shake256Reader {
    let mut h = Shake256::default();
    h.update(domain);
    for part in parts {
        h.update(&(part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize_xof()
}

// ── Issuer parameters ────────────────────────────────────────────────────────

/// The public expansion matrix `B_1 ∈ R_q^{T×L}`, together with the public seed
/// it was expanded from.
///
/// This is the **public half** of an issuer's key pair. It is what the
/// verification relation is checked against, and it is derivable from the
/// issuer seed but not the other way round: the seed is hashed through
/// SHAKE-256 to produce `public_seed`, and recovering the seed from it is a
/// preimage search against SHAKE-256.
///
/// The seed used to be expanded into `B_1` directly, which left the parameters
/// with no compact publishable form: the only short representation of `B_1` was
/// the seed itself, so handing a verifier something it could pin meant handing
/// it the issuing secret. Interposing a public seed separates the two. `B_1` is
/// still a deterministic expansion, so a verifier reconstructs the issuer's
/// matrix rather than being handed it in the proof, and an inconsistent `B_1`
/// stays unrepresentable.
pub struct IssuerParams {
    public_seed: [u8; PUBLIC_SEED_BYTES],
    b1: [[Polynomial; CRED_L]; CRED_T],
}

/// Length of an issuer's public seed, and of the issuer seed's minimum.
pub const PUBLIC_SEED_BYTES: usize = 32;

impl IssuerParams {
    /// Derive an issuer's public parameters from its secret seed.
    ///
    /// Requires at least 32 bytes. The seed is the issuer's authority: whoever
    /// holds it can issue credentials. What comes back does not carry it.
    pub fn from_seed(issuer_seed: &[u8]) -> Result<Self, IdentityError> {
        if issuer_seed.len() < PUBLIC_SEED_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }
        let mut public_seed = [0u8; PUBLIC_SEED_BYTES];
        xof_for(DOMAIN_ISSUER_PUBLIC, &[issuer_seed]).read(&mut public_seed);
        Ok(Self::from_public_seed(&public_seed))
    }

    /// Expand public parameters from an already-published public seed.
    pub fn from_public_seed(public_seed: &[u8; PUBLIC_SEED_BYTES]) -> Self {
        let mut b1 = [[Polynomial::zero(); CRED_L]; CRED_T];
        for row in 0..CRED_T {
            for col in 0..CRED_L {
                let mut xof = xof_for(DOMAIN_B1, &[public_seed, &[row as u8, col as u8]]);
                b1[row][col] = sample_uniform(&mut xof);
            }
        }
        Self { public_seed: *public_seed, b1 }
    }

    /// The published form of these parameters.
    ///
    /// Safe to hand to anyone: it grants verification and nothing else.
    pub fn public_seed(&self) -> &[u8; PUBLIC_SEED_BYTES] {
        &self.public_seed
    }

    /// `B_1 · v` for a length-`L` vector.
    fn mul(&self, v: &[Polynomial; CRED_L]) -> [Polynomial; CRED_T] {
        let mut out = [Polynomial::zero(); CRED_T];
        for row in 0..CRED_T {
            let mut acc = Polynomial::zero();
            for col in 0..CRED_L {
                acc = poly_add(&acc, &poly_mul_negacyclic(&self.b1[row][col], &v[col]));
            }
            out[row] = acc;
        }
        out
    }
}

// ── Attribute encoding ───────────────────────────────────────────────────────

/// Bits carried per coefficient when encoding an attribute.
///
/// 16, not the 22 that would fit: `mod_q` reduces to a *centred* range, so any
/// limb above `q/2` (about 4.19 million) comes back negative and decodes to the
/// wrong value. A 22-bit limb can reach 4,194,303 and cross that line; a 16-bit
/// limb tops out at 65,535 and cannot.
const ATTRIBUTE_LIMB_BITS: u32 = 16;

/// Coefficients used per attribute. Four 16-bit limbs carry exactly 64 bits.
const ATTRIBUTE_LIMBS: usize = 4;

/// Encode an attribute value across low-order coefficients.
///
/// A single coefficient would cap attributes at `q`, about 8.38 million, which
/// is smaller than it sounds: a date of birth written `19900101`, a unix
/// timestamp, or an account number all exceed it. Rather than refuse those or,
/// worse, reduce them modulo `q` and produce a verifying proof of the wrong
/// value, the value is split into three 22-bit limbs.
///
/// Both the issuer and the verifier encode from the same `u64`, so no decoding
/// is needed and the two sides cannot disagree about the representation.
///
/// The relation is linear, so a multi-coefficient message costs nothing: the
/// commitment, the responses and the verification equation are unchanged.
fn encode_attribute(value: u64) -> Result<Polynomial, IdentityError> {
    let mut p = Polynomial::zero();
    let mask = (1u64 << ATTRIBUTE_LIMB_BITS) - 1;
    for limb in 0..ATTRIBUTE_LIMBS {
        let chunk = (value >> (ATTRIBUTE_LIMB_BITS * limb as u32)) & mask;
        p.coeffs[limb] = mod_q(chunk as i64);
    }
    Ok(p)
}

/// Recover an attribute value from its encoding.
///
/// The inverse of [`encode_attribute`], and the reason the limbs must stay
/// below `q/2`: this reads them back as non-negative values.
fn decode_attribute(p: &Polynomial) -> u64 {
    let mut value = 0u64;
    for limb in 0..ATTRIBUTE_LIMBS {
        let coeff = p.coeffs[limb];
        // Centred representation: a limb is never negative by construction, but
        // read defensively rather than assume it.
        let chunk = if coeff < 0 {
            (coeff as i64 + PARAM_Q as i64) as u64
        } else {
            coeff as u64
        };
        value |= chunk << (ATTRIBUTE_LIMB_BITS * limb as u32);
    }
    value
}

// ── Credential ───────────────────────────────────────────────────────────────

/// A credential issued over a holder's identity and attribute values.
///
/// Holds the commitment randomness, so it is secret material and must not
/// cross the L1 boundary.
pub struct Credential {
    t_cred: [Polynomial; CRED_T],
    r: [Polynomial; CRED_L],
    m: [Polynomial; CRED_SLOTS],
}

impl Drop for Credential {
    fn drop(&mut self) {
        for p in self.r.iter_mut() {
            p.zeroize();
        }
        for p in self.m.iter_mut() {
            p.zeroize();
        }
    }
}

impl Credential {
    /// Issue a credential binding `attributes` to the holder's identity.
    ///
    /// `identity_secret` is the holder's PLP master secret. It occupies slot 0
    /// and is what ties the credential to one identity: a proof under this
    /// credential can only be produced by someone who also satisfies the
    /// identity-linkage relation for the same `s`.
    pub fn issue(
        params: &IssuerParams,
        identity: &plp::MasterIdentity,
        attributes: &[u64; CRED_ATTRIBUTES],
        issuance_randomness: &[u8],
    ) -> Result<Self, IdentityError> {
        if issuance_randomness.len() < 32 {
            return Err(IdentityError::InvalidInputLength);
        }

        let mut m = [Polynomial::zero(); CRED_SLOTS];
        // Slot 0 binds the credential to the holder's identity. The secret is a
        // rank-`k` vector and a slot holds one ring element, so slot 0 carries
        // `s[0]`. That is sufficient: the identity relation separately proves
        // knowledge of the whole `s` satisfying `b_τ = A_τ·s + e_τ`, and this
        // slot ties the credential to the `s[0]` of that same `s`. Presenting
        // another holder's credential would require a valid secret for one's
        // own projection whose first component equals theirs, which is exactly
        // as hard as knowing their secret.
        m[IDENTITY_SLOT] = from_plp(&identity.secret()[0]);
        for (i, value) in attributes.iter().enumerate() {
            m[i + 1] = encode_attribute(*value)?;
        }

        let mut r = [Polynomial::zero(); CRED_L];
        for (i, slot) in r.iter_mut().enumerate() {
            let mut xof = xof_for(DOMAIN_ISSUE_RANDOMNESS, &[issuance_randomness, &[i as u8]]);
            *slot = sample_cbd(&mut xof);
        }

        // t_cred = B_1 · r + (0^L ‖ m)
        let mut t_cred = params.mul(&r);
        for slot in 0..CRED_SLOTS {
            t_cred[CRED_L + slot] = poly_add(&t_cred[CRED_L + slot], &m[slot]);
        }

        Ok(Self { t_cred, r, m })
    }
}

/// A credential blinded for one presentation.
///
/// `t_blind = t_cred + B_1·r_blind`, with `r* = r + r_blind`. Fresh blinding per
/// presentation is what makes two showings of the same credential unlinkable:
/// `t_blind` is a fresh commitment to the same messages.
pub struct BlindedCredential {
    t_blind: [Polynomial; CRED_T],
    r_star: [Polynomial; CRED_L],
    m: [Polynomial; CRED_SLOTS],
}

impl Drop for BlindedCredential {
    fn drop(&mut self) {
        for p in self.r_star.iter_mut() {
            p.zeroize();
        }
        for p in self.m.iter_mut() {
            p.zeroize();
        }
    }
}

impl BlindedCredential {
    /// Blind a credential for presentation.
    ///
    /// `blinding_randomness` must be fresh per presentation. Reusing it makes
    /// two presentations linkable, which is the property this exists to provide.
    pub fn new(
        params: &IssuerParams,
        credential: &Credential,
        blinding_randomness: &[u8],
    ) -> Result<Self, IdentityError> {
        if blinding_randomness.len() < 32 {
            return Err(IdentityError::InvalidInputLength);
        }

        let mut r_blind = [Polynomial::zero(); CRED_L];
        for (i, slot) in r_blind.iter_mut().enumerate() {
            let mut xof = xof_for(DOMAIN_BLIND, &[blinding_randomness, &[i as u8]]);
            *slot = sample_cbd(&mut xof);
        }

        let b_r_blind = params.mul(&r_blind);
        let mut t_blind = [Polynomial::zero(); CRED_T];
        for i in 0..CRED_T {
            t_blind[i] = poly_add(&credential.t_cred[i], &b_r_blind[i]);
        }

        let mut r_star = [Polynomial::zero(); CRED_L];
        for i in 0..CRED_L {
            r_star[i] = poly_add(&credential.r[i], &r_blind[i]);
        }
        for p in r_blind.iter_mut() {
            p.zeroize();
        }

        Ok(Self { t_blind, r_star, m: credential.m })
    }

    /// The public blinded commitment, which the verifier needs.
    pub fn commitment(&self) -> &[Polynomial; CRED_T] {
        &self.t_blind
    }
}

// ── Proof ────────────────────────────────────────────────────────────────────

/// A SAAP presentation proving two linked relations.
pub struct SaapPresentation {
    /// Context tag τ.
    pub tau: [u8; 32],
    /// Which attribute slots are disclosed. Bit `i` is attribute `i`.
    pub disclosed: u8,
    /// Disclosed attribute values; hidden slots are zero and carry no meaning.
    pub disclosed_values: [u64; CRED_ATTRIBUTES],
    /// Fiat-Shamir challenge.
    pub challenge: Polynomial,
    /// Response for the commitment randomness.
    pub z_r: [Polynomial; CRED_L],
    /// Response for the message slots.
    pub z_m: [Polynomial; CRED_SLOTS],
    /// Response for the identity secret, one entry per module component.
    pub z_s: [Polynomial; plp::MODULE_K],
    /// Response for the projection error term, one entry per module component.
    pub z_e: [Polynomial; plp::MODULE_K],
}

fn absorb_poly(h: &mut Shake256, p: &Polynomial) {
    for c in p.coeffs.iter() {
        h.update(&c.to_le_bytes());
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_challenge(
    w1: &[Polynomial; CRED_T],
    w2: &[Polynomial; plp::MODULE_K],
    b_tau: &[Polynomial; plp::MODULE_K],
    t_blind: &[Polynomial; CRED_T],
    disclosed: u8,
    disclosed_values: &[u64; CRED_ATTRIBUTES],
    tau: &[u8],
    salt: &[u8; 32],
    public_seed: &[u8; PUBLIC_SEED_BYTES],
) -> Polynomial {
    let mut h = Shake256::default();
    h.update(DOMAIN_CHALLENGE);
    for p in w1.iter() {
        absorb_poly(&mut h, p);
    }
    for p in w2.iter() {
        absorb_poly(&mut h, p);
    }
    for p in b_tau.iter() {
        absorb_poly(&mut h, p);
    }
    for p in t_blind.iter() {
        absorb_poly(&mut h, p);
    }
    h.update(&[disclosed]);
    for v in disclosed_values.iter() {
        h.update(&v.to_le_bytes());
    }
    h.update(&(tau.len() as u32).to_le_bytes());
    h.update(tau);
    // The two seeds that determine the matrices this transcript is checked
    // against. Without them `A_tau` and `B_1` are bound only through the
    // verification equations, which is the weak Fiat-Shamir pattern `plp`
    // already corrected. Neither is prover-chosen today, since both are hash
    // images, so this closes the pattern rather than a live attack.
    h.update(salt);
    h.update(public_seed);
    let mut xof = h.finalize_xof();
    hash_to_challenge_from_xof(&mut xof)
}

/// Split the message vector into its disclosed and hidden halves.
///
/// Slot 0 is always hidden regardless of the mask: it is the identity binding,
/// and disclosing it would publish the master secret.
fn split_messages(
    m: &[Polynomial; CRED_SLOTS],
    disclosed: u8,
) -> ([Polynomial; CRED_SLOTS], [Polynomial; CRED_SLOTS]) {
    let mut m_pub = [Polynomial::zero(); CRED_SLOTS];
    let mut m_hidden = [Polynomial::zero(); CRED_SLOTS];
    m_hidden[IDENTITY_SLOT] = m[IDENTITY_SLOT];
    for i in 0..CRED_ATTRIBUTES {
        let slot = i + 1;
        if disclosed & (1 << i) != 0 {
            m_pub[slot] = m[slot];
        } else {
            m_hidden[slot] = m[slot];
        }
    }
    (m_pub, m_hidden)
}

fn infinity_norm(p: &Polynomial) -> i32 {
    p.coeffs.iter().map(|c| c.abs()).max().unwrap_or(0)
}

/// Produce a SAAP presentation.
///
/// `projection_randomness` is the same `rho` that produced the projection, and
/// is needed to re-derive `e_τ` as a witness. `presentation_randomness` seeds
/// the proof masks and must be fresh per presentation.
pub fn prove(
    params: &IssuerParams,
    blinded: &BlindedCredential,
    identity: &plp::MasterIdentity,
    projection: &plp::EphemeralProjection,
    tau: &[u8],
    projection_randomness: &[u8],
    disclosed: u8,
    presentation_randomness: &[u8],
) -> Result<SaapPresentation, IdentityError> {
    if presentation_randomness.len() < 32 {
        return Err(IdentityError::InvalidInputLength);
    }

    let a_tau = from_plp_mat(&projection.matrix_a);
    let b_tau = from_plp_vec(&projection.public_b);
    let s = from_plp_vec(identity.secret());

    // `tau` is the caller's original context bytes, not `projection.tau`, which
    // is a zero-padded 32-byte copy. `project_at_context` derives e_tau from the
    // original, so re-deriving from the padded form yields a different error
    // term and the identity relation silently proves nothing. The arithmetic
    // agreement test caught exactly this.
    let mut e_tau_plp = plp::derive_error_tau(projection_randomness, tau);
    let e_tau = from_plp_vec(&e_tau_plp);
    e_tau_plp.iter_mut().for_each(|p| p.zeroize());

    let (m_pub, m_hidden) = split_messages(&blinded.m, disclosed);

    let mut disclosed_values = [0u64; CRED_ATTRIBUTES];
    for i in 0..CRED_ATTRIBUTES {
        if disclosed & (1 << i) != 0 {
            disclosed_values[i] = decode_attribute(&m_pub[i + 1]);
        }
    }

    // Everything about the statement, absorbed into every mask below. Deriving
    // masks from `presentation_randomness` alone meant two presentations that
    // reused it shared `y_s`, and subtracting their responses gave
    // `(c1 - c2) * s`, recovering the master secret. That is the class P3-15
    // fixed in `plp` by absorbing `tau`; the fix had not reached here. Binding
    // the full statement makes reuse harmless rather than catastrophic.
    let statement = {
        let mut h = Shake256::default();
        h.update(&(tau.len() as u32).to_le_bytes());
        h.update(tau);
        h.update(&projection.salt);
        h.update(params.public_seed());
        for p in blinded.t_blind.iter() {
            absorb_poly(&mut h, p);
        }
        for p in b_tau.iter() {
            absorb_poly(&mut h, p);
        }
        h.update(&[disclosed]);
        for v in disclosed_values.iter() {
            h.update(&v.to_le_bytes());
        }
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    };

    for iteration in 0..MAX_REJECTION_ITERATIONS {
        let nonce = [iteration as u8];

        // Short masks: witnesses that must stay short for the relaxed opening.
        let mut y_r = [Polynomial::zero(); CRED_L];
        for (i, slot) in y_r.iter_mut().enumerate() {
            let mut xof =
                xof_for(DOMAIN_MASK, &[presentation_randomness, &statement, b"r", &nonce, &[i as u8]]);
            *slot = sample_short_mask(&mut xof);
        }
        let mut y_s = [Polynomial::zero(); plp::MODULE_K];
        for (i, slot) in y_s.iter_mut().enumerate() {
            let mut xof =
                xof_for(DOMAIN_MASK, &[presentation_randomness, &statement, b"s", &nonce, &[i as u8]]);
            *slot = sample_short_mask(&mut xof);
        }
        let mut y_e = [Polynomial::zero(); plp::MODULE_K];
        for (i, slot) in y_e.iter_mut().enumerate() {
            let mut xof =
                xof_for(DOMAIN_MASK, &[presentation_randomness, &statement, b"e", &nonce, &[i as u8]]);
            *slot = sample_short_mask(&mut xof);
        }

        // Message masks are uniform over R_q: attribute values are not short,
        // so a short mask would not hide them. Slot 0 is the exception and
        // reuses y_s, which is what makes z_m[0] == z_s hold.
        let mut y_m = [Polynomial::zero(); CRED_SLOTS];
        // Slot 0 shares the identity mask's first component, which is what
        // makes z_m[0] == z_s[0] hold and links the two relations.
        y_m[IDENTITY_SLOT] = y_s[0];
        for slot in 1..CRED_SLOTS {
            let mut xof =
                xof_for(DOMAIN_MASK, &[presentation_randomness, &statement, b"m", &nonce, &[slot as u8]]);
            y_m[slot] = sample_uniform(&mut xof);
        }

        // W_1 = B_1·y_r + (0^L ‖ y_m)
        let mut w1 = params.mul(&y_r);
        for slot in 0..CRED_SLOTS {
            w1[CRED_L + slot] = poly_add(&w1[CRED_L + slot], &y_m[slot]);
        }

        // W_2 = A_τ·y_s + y_e, a rank-k vector.
        let mut w2 = mat_vec(&a_tau, &y_s);
        for i in 0..plp::MODULE_K {
            w2[i] = poly_add(&w2[i], &y_e[i]);
        }

        let c = derive_challenge(
            &w1,
            &w2,
            &b_tau,
            &blinded.t_blind,
            disclosed,
            &disclosed_values,
            tau,
            &projection.salt,
            params.public_seed(),
        );

        let mut z_r = [Polynomial::zero(); CRED_L];
        for i in 0..CRED_L {
            z_r[i] = poly_add(&y_r[i], &poly_mul_negacyclic(&c, &blinded.r_star[i]));
        }
        let mut z_m = [Polynomial::zero(); CRED_SLOTS];
        for slot in 0..CRED_SLOTS {
            z_m[slot] = poly_add(&y_m[slot], &poly_mul_negacyclic(&c, &m_hidden[slot]));
        }
        let mut z_s = [Polynomial::zero(); plp::MODULE_K];
        let mut z_e = [Polynomial::zero(); plp::MODULE_K];
        for i in 0..plp::MODULE_K {
            z_s[i] = poly_add(&y_s[i], &poly_mul_negacyclic(&c, &s[i]));
            z_e[i] = poly_add(&y_e[i], &poly_mul_negacyclic(&c, &e_tau[i]));
        }

        // Rejection sampling applies only to the short witnesses. z_m for the
        // attribute slots is uniform by construction and has no bound to check.
        let mut reject = z_s.iter().any(|z| infinity_norm(z) >= REJECTION_BOUND)
            || z_e.iter().any(|z| infinity_norm(z) >= REJECTION_BOUND);
        for z in z_r.iter() {
            reject |= infinity_norm(z) >= REJECTION_BOUND;
        }

        if !reject {
            y_r.iter_mut().for_each(|p| p.zeroize());
            y_s.iter_mut().for_each(|p| p.zeroize());
            y_e.iter_mut().for_each(|p| p.zeroize());
            return Ok(SaapPresentation {
                tau: projection.tau,
                disclosed,
                disclosed_values,
                challenge: c,
                z_r,
                z_m,
                z_s,
                z_e,
            });
        }

        // A rejected response is precisely the value rejection sampling exists
        // to withhold. Wipe it rather than let it fall out of scope.
        y_r.iter_mut().for_each(|p| p.zeroize());
        y_s.iter_mut().for_each(|p| p.zeroize());
        y_e.iter_mut().for_each(|p| p.zeroize());
        z_r.iter_mut().for_each(|p| p.zeroize());
        z_m.iter_mut().for_each(|p| p.zeroize());
    }

    // No fallback. Returning the last candidate would emit a response that
    // failed the norm check, which is how a sigma protocol leaks its secret.
    Err(IdentityError::RejectionSamplingFailed)
}

/// Verify a SAAP presentation.
///
/// Returns `Ok(false)` for a well-formed presentation that does not verify, and
/// `Err` only for input that cannot be processed.
pub fn verify(
    params: &IssuerParams,
    presentation: &SaapPresentation,
    t_blind: &[Polynomial; CRED_T],
    projection: &plp::EphemeralProjection,
    tau: &[u8],
) -> Result<bool, IdentityError> {
    let a_tau = from_plp_mat(&projection.matrix_a);
    let b_tau = from_plp_vec(&projection.public_b);
    let c = &presentation.challenge;

    // 1. Norm checks on the short responses.
    if presentation.z_s.iter().any(|z| infinity_norm(z) >= REJECTION_BOUND)
        || presentation.z_e.iter().any(|z| infinity_norm(z) >= REJECTION_BOUND)
    {
        return Ok(false);
    }
    for z in presentation.z_r.iter() {
        if infinity_norm(z) >= REJECTION_BOUND {
            return Ok(false);
        }
    }

    // 2. The linkage check. Slot 0's response must be the identity response.
    //    Without this the two relations would share only a challenge, and a
    //    holder could present someone else's credential alongside their own
    //    identity proof.
    let mut linkage_mismatch = 0i32;
    for i in 0..RING_N {
        linkage_mismatch |=
            presentation.z_m[IDENTITY_SLOT].coeffs[i] ^ presentation.z_s[0].coeffs[i];
    }
    if linkage_mismatch != 0 {
        return Ok(false);
    }

    // 3. Rebuild m_pub from the disclosed values the presentation carries.
    let mut m_pub = [Polynomial::zero(); CRED_SLOTS];
    for i in 0..CRED_ATTRIBUTES {
        if presentation.disclosed & (1 << i) != 0 {
            m_pub[i + 1] = encode_attribute(presentation.disclosed_values[i])?;
        }
    }

    // 4. W_1' = B_1·z_r + (0 ‖ z_m) − c·(t_blind − (0 ‖ m_pub))
    let mut w1 = params.mul(&presentation.z_r);
    for slot in 0..CRED_SLOTS {
        w1[CRED_L + slot] = poly_add(&w1[CRED_L + slot], &presentation.z_m[slot]);
    }
    for row in 0..CRED_T {
        let mut target = t_blind[row];
        if row >= CRED_L {
            target = poly_sub(&target, &m_pub[row - CRED_L]);
        }
        w1[row] = poly_sub(&w1[row], &poly_mul_negacyclic(c, &target));
    }

    // 5. W_2' = A_τ·z_s + z_e − c·b_τ, componentwise over the rank-k module.
    //    Exact, because e_τ is in the witness.
    let az = mat_vec(&a_tau, &presentation.z_s);
    let mut w2 = [Polynomial::zero(); plp::MODULE_K];
    for i in 0..plp::MODULE_K {
        w2[i] = poly_sub(
            &poly_add(&az[i], &presentation.z_e[i]),
            &poly_mul_negacyclic(c, &b_tau[i]),
        );
    }

    // 6. Challenge consistency.
    let c_prime = derive_challenge(
        &w1,
        &w2,
        &b_tau,
        t_blind,
        presentation.disclosed,
        &presentation.disclosed_values,
        tau,
        &projection.salt,
        params.public_seed(),
    );

    let mut mismatch = 0i32;
    for i in 0..RING_N {
        mismatch |= c_prime.coeffs[i] ^ c.coeffs[i];
    }
    Ok(mismatch == 0)
}

/// Flatten polynomials into one coefficient list.
///
/// The component surface carries these as a flat `list<s32>` rather than nested
/// lists, because the dimensions are fixed by the parameter set and a nested
/// list would let a caller supply a ragged one.
pub fn flatten(polys: &[Polynomial]) -> Vec<i32> {
    let mut out = Vec::with_capacity(polys.len() * RING_N);
    for p in polys {
        out.extend_from_slice(&p.coeffs);
    }
    out
}

/// Rebuild exactly `K` polynomials from a flat coefficient list.
///
/// A wrong length is an error rather than a truncation or a zero-fill: a
/// silently reshaped vector would still produce a verification answer, and it
/// would be the wrong one.
pub fn unflatten<const K: usize>(flat: &[i32]) -> Result<[Polynomial; K], IdentityError> {
    if flat.len() != K * RING_N {
        return Err(IdentityError::InvalidInputLength);
    }
    let mut out = [Polynomial::zero(); K];
    for (k, poly) in out.iter_mut().enumerate() {
        poly.coeffs.copy_from_slice(&flat[k * RING_N..(k + 1) * RING_N]);
    }
    Ok(out)
}

/// The blinded commitment, as the component carries it.
pub fn commitment_flat(blinded: &BlindedCredential) -> Vec<i32> {
    flatten(blinded.commitment())
}

/// Serialise a presentation, for tests that need to inspect the wire form.
pub fn presentation_bytes(p: &SaapPresentation) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.tau);
    out.push(p.disclosed);
    for v in p.disclosed_values.iter() {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut push = |poly: &Polynomial| {
        for c in poly.coeffs.iter() {
            out.extend_from_slice(&c.to_le_bytes());
        }
    };
    push(&p.challenge);
    for z in p.z_r.iter() {
        push(z);
    }
    for z in p.z_m.iter() {
        push(z);
    }
    for z in p.z_s.iter() {
        push(z);
    }
    for z in p.z_e.iter() {
        push(z);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER_SEED: &[u8] = b"issuer seed for the test suite!!";
    const ISSUE_R: &[u8] = b"issuance randomness for tests!!!";
    const BLIND_R: &[u8] = b"blinding randomness for tests!!!";
    const PRES_R: &[u8] = b"presentation randomness tests!!!";
    const RHO: &[u8] = b"projection randomness for tests!";

    fn identity(seed: u8) -> plp::MasterIdentity {
        plp::MasterIdentity::from_seed(&[seed; 32])
    }

    fn attrs() -> [u64; CRED_ATTRIBUTES] {
        [31, 1990, 7, 42, 100, 5, 9, 12345]
    }

    /// The two representations must agree, or nothing above them means anything.
    ///
    /// PLP computes `b_tau = A_tau*s + e_tau` with `u32` coefficients and its own
    /// schoolbook multiply. This module converts to centred `i32` and uses
    /// SAAP's negacyclic multiply. If those disagree, the identity-linkage
    /// relation is proving a statement about different arithmetic than the
    /// projection was built with, and every other test here would still pass.
    #[test]
    fn the_two_polynomial_representations_agree() {
        let id = identity(0x42);
        let proj = id.project_at_context(b"arithmetic-check", RHO);

        let a_tau = from_plp_mat(&proj.matrix_a);
        let s = from_plp_vec(id.secret());
        let e_tau = from_plp_vec(&plp::derive_error_tau(RHO, b"arithmetic-check"));

        let az = mat_vec(&a_tau, &s);
        let expected = from_plp_vec(&proj.public_b);

        // Every component must agree. A check on component 0 alone would pass
        // for a matrix-vector product that was wrong in the other rows.
        for i in 0..plp::MODULE_K {
            let recomputed = poly_add(&az[i], &e_tau[i]);
            assert_eq!(
                recomputed.coeffs, expected[i].coeffs,
                "SAAP arithmetic over the converted PLP values does not reproduce                  b_tau in component {i}"
            );
        }
    }

    /// Positive control for the test above: a wrong secret must not reproduce
    /// `b_tau`. Otherwise the equality could hold for reasons unrelated to the
    /// arithmetic being right.
    #[test]
    fn the_arithmetic_check_can_fail() {
        let id = identity(0x42);
        let other = identity(0x99);
        let proj = id.project_at_context(b"arithmetic-check", RHO);

        let a_tau = from_plp_mat(&proj.matrix_a);
        let wrong_s = from_plp_vec(other.secret());
        let e_tau = from_plp_vec(&plp::derive_error_tau(RHO, b"arithmetic-check"));

        let az = mat_vec(&a_tau, &wrong_s);
        let expected = from_plp_vec(&proj.public_b);
        let agrees = (0..plp::MODULE_K)
            .all(|i| poly_add(&az[i], &e_tau[i]).coeffs == expected[i].coeffs);
        assert!(
            !agrees,
            "a different secret reproduced b_tau, so the check proves nothing"
        );
    }

    /// `e_tau` must be recoverable from `(rho, tau)`, since the prover needs it
    /// as a witness and `project_at_context` wipes its copy.
    #[test]
    fn the_error_term_is_reproducible_from_rho_and_tau() {
        let flat = |v: &plp::PolyVec| {
            v.iter().flat_map(|p| p.coeffs().to_vec()).collect::<Vec<u32>>()
        };
        let a = plp::derive_error_tau(RHO, b"ctx");
        let b = plp::derive_error_tau(RHO, b"ctx");
        assert_eq!(flat(&a), flat(&b));
        let different = plp::derive_error_tau(RHO, b"other-ctx");
        assert_ne!(flat(&a), flat(&different), "e_tau does not depend on tau");
    }

    struct Fixture {
        params: IssuerParams,
        blinded: BlindedCredential,
        id: plp::MasterIdentity,
        proj: plp::EphemeralProjection,
        tau: &'static [u8],
    }

    fn fixture(seed: u8, tau: &'static [u8]) -> Fixture {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(seed);
        let cred = Credential::issue(&params, &id, &attrs(), ISSUE_R).expect("issue");
        let blinded = BlindedCredential::new(&params, &cred, BLIND_R).expect("blind");
        let proj = id.project_at_context(tau, RHO);
        Fixture { params, blinded, id, proj, tau }
    }

    /// AC: a proof verifies against `b_tau` from `project_at_context`, not
    /// against a SAAP-local public key.
    #[test]
    fn an_honest_presentation_verifies_against_the_plp_projection() {
        let f = fixture(0x42, b"context-alpha");
        let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");
        assert!(
            verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
            "an honestly generated presentation failed to verify"
        );
    }

    /// AC: a proof generated for identity A fails against identity B's `b_tau`.
    #[test]
    fn a_presentation_does_not_verify_against_another_identity() {
        let f = fixture(0x42, b"context-alpha");
        let other = identity(0x99);
        let other_proj = other.project_at_context(b"context-alpha", RHO);

        let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        assert!(
            !verify(&f.params, &p, f.blinded.commitment(), &other_proj, f.tau).expect("verify"),
            "a presentation verified against a different identity's projection"
        );
    }

    /// AC: rewriting a disclosed attribute value invalidates the proof.
    #[test]
    fn rewriting_a_disclosed_attribute_invalidates_the_presentation() {
        let f = fixture(0x42, b"context-alpha");
        let mut p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0011, PRES_R)
            .expect("prove");

        assert!(verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"));

        p.disclosed_values[0] += 1;
        assert!(
            !verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
            "a rewritten disclosed attribute still verified"
        );
    }

    /// The published parameters must not be the seed. If they were, handing a
    /// verifier what it needs would hand it the power to issue, which is the
    /// whole reason this split exists.
    #[test]
    fn public_parameters_are_not_the_issuer_seed() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        assert_ne!(
            params.public_seed().as_slice(),
            ISSUER_SEED,
            "the published parameters were the issuer seed verbatim"
        );
    }

    /// Publishing has to be deterministic, or a verifier could not pin an
    /// issuer, and distinct, or two issuers would be indistinguishable.
    #[test]
    fn deriving_public_parameters_is_deterministic_and_issuer_specific() {
        let a = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let b = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let other = IssuerParams::from_seed(b"a different issuer seed entirely").unwrap();

        assert_eq!(a.public_seed(), b.public_seed(), "derivation was not deterministic");
        assert_ne!(a.public_seed(), other.public_seed(), "two issuers collided");
    }

    /// A verifier reconstructs `B_1` from the published seed alone, and gets the
    /// same matrix the issuer used. Checked through the relation rather than by
    /// comparing matrices, because the relation is what a verifier depends on.
    #[test]
    fn parameters_rebuilt_from_the_published_seed_verify_the_same_presentation() {
        let f = fixture(0x42, b"context-alpha");
        let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        let published = *f.params.public_seed();
        let verifier_side = IssuerParams::from_public_seed(&published);

        let ok = verify(&verifier_side, &p, f.blinded.commitment(), &f.proj, f.tau)
            .expect("verify");
        assert!(ok, "a presentation did not verify under rebuilt public parameters");
    }

    /// An issuer seed is secret key material, and carries the same 32-byte floor
    /// as every other secret in this crate.
    #[test]
    fn a_short_issuer_seed_is_refused() {
        assert!(matches!(
            IssuerParams::from_seed(b"too short"),
            Err(IdentityError::InvalidInputLength)
        ));
    }

    /// AC: a credential the issuer never issued fails the membership relation.
    #[test]
    fn a_credential_from_another_issuer_fails() {
        let f = fixture(0x42, b"context-alpha");
        let rogue = IssuerParams::from_seed(b"a different issuer seed entirely").unwrap();

        let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        assert!(
            !verify(&rogue, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
            "a presentation verified under an issuer that never issued it"
        );
    }

    /// A commitment that was never produced by an issuance must fail.
    #[test]
    fn a_fabricated_commitment_fails() {
        let f = fixture(0x42, b"context-alpha");
        let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        let mut fake = *f.blinded.commitment();
        fake[CRED_L].coeffs[0] = mod_q(fake[CRED_L].coeffs[0] as i64 + 1);

        assert!(
            !verify(&f.params, &p, &fake, &f.proj, f.tau).expect("verify"),
            "a presentation verified against a commitment it was not made over"
        );
    }

    /// The linkage is the point of "three linked relations". Breaking it must be
    /// detected: a shared challenge alone would let a holder present someone
    /// else's credential beside their own identity proof.
    #[test]
    fn breaking_the_identity_linkage_is_detected() {
        let f = fixture(0x42, b"context-alpha");
        let mut p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        p.z_m[IDENTITY_SLOT].coeffs[0] = mod_q(p.z_m[IDENTITY_SLOT].coeffs[0] as i64 + 1);

        assert!(
            !verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
            "z_m[0] and z_s were allowed to disagree"
        );
    }

    /// Tampering with any response must be caught.
    #[test]
    fn a_tampered_response_is_rejected() {
        let f = fixture(0x42, b"context-alpha");
        let base = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        for which in 0..3 {
            let mut p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 0b0000_0001, PRES_R)
                .expect("prove");
            match which {
                0 => p.z_r[0].coeffs[5] = mod_q(p.z_r[0].coeffs[5] as i64 + 1),
                1 => p.z_e[0].coeffs[5] = mod_q(p.z_e[0].coeffs[5] as i64 + 1),
                _ => p.z_m[3].coeffs[5] = mod_q(p.z_m[3].coeffs[5] as i64 + 1),
            }
            assert!(
                !verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
                "tampering with response {which} was not detected"
            );
        }
        assert!(verify(&f.params, &base, f.blinded.commitment(), &f.proj, f.tau).expect("verify"));
    }

    /// AC: two presentations of the same credential under different tau are
    /// unlinkable. Asserted, not argued.
    #[test]
    fn two_presentations_under_different_contexts_are_unlinkable() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(0x42);
        let cred = Credential::issue(&params, &id, &attrs(), ISSUE_R).expect("issue");

        let b1 = BlindedCredential::new(&params, &cred, b"blinding for presentation one!!!")
            .expect("blind");
        let b2 = BlindedCredential::new(&params, &cred, b"blinding for presentation two!!!")
            .expect("blind");

        let p1_proj = id.project_at_context(b"context-one", RHO);
        let p2_proj = id.project_at_context(b"context-two", RHO);

        let p1 = prove(&params, &b1, &id, &p1_proj, b"context-one", RHO, 0b0000_0001, PRES_R)
            .expect("prove");
        let p2 = prove(&params, &b2, &id, &p2_proj, b"context-two", RHO, 0b0000_0001, PRES_R)
            .expect("prove");

        assert!(verify(&params, &p1, b1.commitment(), &p1_proj, b"context-one").expect("verify"));
        assert!(verify(&params, &p2, b2.commitment(), &p2_proj, b"context-two").expect("verify"));

        assert_ne!(
            b1.commitment()[0].coeffs,
            b2.commitment()[0].coeffs,
            "two presentations reused the same blinded commitment"
        );

        assert_ne!(p1.z_s[0].coeffs, p2.z_s[0].coeffs, "z_s was reused across contexts");
        assert_ne!(p1.z_r[0].coeffs, p2.z_r[0].coeffs, "z_r was reused across contexts");
        assert_ne!(
            p1.challenge.coeffs, p2.challenge.coeffs,
            "the challenge was reused across contexts"
        );
    }

    /// P9-06. The masks must be a function of the statement, not of
    /// `presentation_randomness` alone.
    ///
    /// Two presentations of the *same* credential at the same context, with
    /// identical `presentation_randomness`, differing only in which attributes
    /// are disclosed. Before the masks absorbed the statement these shared
    /// `y_s`, so `z1 - z2 = (c1 - c2) * s` recovered the master secret. The
    /// point is not that the values differ by luck: they differ because the
    /// derivation depends on `disclosed`.
    #[test]
    fn masks_differ_when_only_the_disclosure_set_differs() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(0x31);
        let cred = Credential::issue(&params, &id, &[11, 22, 33, 0, 0, 0, 0, 0], ISSUE_R)
            .expect("issue");
        let blinded = BlindedCredential::new(&params, &cred, BLIND_R).expect("blind");
        let proj = id.project_at_context(b"one-context", RHO);

        // Same everything, including presentation_randomness. Only `disclosed`
        // moves, so only the statement moves.
        let a = prove(&params, &blinded, &id, &proj, b"one-context", RHO, 0b0000_0001, PRES_R)
            .expect("prove");
        let b = prove(&params, &blinded, &id, &proj, b"one-context", RHO, 0b0000_0010, PRES_R)
            .expect("prove");

        assert_ne!(
            a.z_s[0].coeffs, b.z_s[0].coeffs,
            "two presentations differing only in the disclosure set produced the              same identity response, so the mask is not bound to the statement and              the difference of the two responses leaks the master secret"
        );

        // Both must still verify: binding the masks must not break soundness.
        assert!(verify(&params, &a, blinded.commitment(), &proj, b"one-context").expect("v"));
        assert!(verify(&params, &b, blinded.commitment(), &proj, b"one-context").expect("v"));
    }

    /// P9-05. The challenge must depend on the issuer public seed and on the
    /// projection salt, since those fix `B_1` and `A_tau` respectively.
    #[test]
    fn the_challenge_binds_the_issuer_seed_and_the_projection_salt() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let w1 = [Polynomial::zero(); CRED_T];
        let w2 = [Polynomial::zero(); plp::MODULE_K];
        let b_tau = [Polynomial::zero(); plp::MODULE_K];
        let t_blind = [Polynomial::zero(); CRED_T];
        let values = [0u64; CRED_ATTRIBUTES];

        let base = derive_challenge(
            &w1, &w2, &b_tau, &t_blind, 0, &values, b"ctx", &[0x11u8; 32], params.public_seed(),
        );
        let other_salt = derive_challenge(
            &w1, &w2, &b_tau, &t_blind, 0, &values, b"ctx", &[0x22u8; 32], params.public_seed(),
        );
        let other_seed = derive_challenge(
            &w1, &w2, &b_tau, &t_blind, 0, &values, b"ctx", &[0x11u8; 32], &[0x99u8; 32],
        );

        assert_ne!(
            base.coeffs, other_salt.coeffs,
            "the challenge does not depend on the projection salt, so A_tau is bound              only through the verification equation"
        );
        assert_ne!(
            base.coeffs, other_seed.coeffs,
            "the challenge does not depend on the issuer public seed, so B_1 is bound              only through the verification equation"
        );
    }

    /// AC: an undisclosed attribute cannot be recovered from a transcript.
    #[test]
    fn an_undisclosed_attribute_does_not_appear_in_the_transcript() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(0x42);
        let secret_attr = 0x0011_2233u64;
        let mut values = attrs();
        values[3] = secret_attr;

        let cred = Credential::issue(&params, &id, &values, ISSUE_R).expect("issue");
        let blinded = BlindedCredential::new(&params, &cred, BLIND_R).expect("blind");
        let proj = id.project_at_context(b"context-alpha", RHO);

        let p = prove(&params, &blinded, &id, &proj, b"context-alpha", RHO, 0b0000_0001, PRES_R)
            .expect("prove");
        let bytes = presentation_bytes(&p);

        assert!(
            !bytes.windows(8).any(|w| w == secret_attr.to_le_bytes()),
            "the hidden attribute value appears verbatim in the transcript"
        );
        assert_eq!(
            p.disclosed_values[3], 0,
            "a hidden attribute was published in disclosed_values"
        );
        assert_ne!(
            p.z_m[4].coeffs[0], secret_attr as i32,
            "the hidden attribute's response is the value itself"
        );
    }

    /// Positive control for the test above.
    #[test]
    fn the_transcript_leak_check_can_detect_a_leak() {
        let secret_attr = 0x0011_2233u64;
        let mut leaky = Vec::new();
        leaky.extend_from_slice(&[0u8; 16]);
        leaky.extend_from_slice(&secret_attr.to_le_bytes());
        assert!(
            leaky.windows(8).any(|w| w == secret_attr.to_le_bytes()),
            "the leak check cannot see the value even when it is present"
        );
    }

    /// Determinism makes tests reproducible; the second half shows the
    /// randomness is actually used.
    #[test]
    fn presentations_depend_on_their_randomness() {
        let f = fixture(0x42, b"context-alpha");
        let a = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 1, PRES_R).expect("prove");
        let b = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, 1, PRES_R).expect("prove");
        let c = prove(
            &f.params,
            &f.blinded,
            &f.id,
            &f.proj,
            f.tau,
            RHO,
            1,
            b"different presentation rand!!!!!",
        )
        .expect("prove");

        assert_eq!(a.z_s[0].coeffs, b.z_s[0].coeffs);
        assert_ne!(a.z_s[0].coeffs, c.z_s[0].coeffs, "the presentation ignores its randomness");
    }

    #[test]
    fn short_randomness_is_refused() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(0x42);
        assert!(matches!(
            Credential::issue(&params, &id, &attrs(), b"short"),
            Err(IdentityError::InvalidInputLength)
        ));
    }

    /// Attributes larger than `q` must work, because the values people actually
    /// put in credentials are larger than `q`. A single-coefficient encoding
    /// capped them at about 8.38 million, which excludes any date written
    /// `YYYYMMDD` and any unix timestamp.
    #[test]
    fn attributes_larger_than_q_round_trip() {
        let params = IssuerParams::from_seed(ISSUER_SEED).unwrap();
        let id = identity(0x42);

        let big = [
            PARAM_Q as u64,      // exactly the old limit
            19_900_101,          // a date of birth
            1_767_225_600,       // a unix timestamp
            u32::MAX as u64,
            u64::MAX,
            0,
            1,
            123_456_789_012,
        ];

        let cred = Credential::issue(&params, &id, &big, ISSUE_R).expect("issue");
        let blinded = BlindedCredential::new(&params, &cred, BLIND_R).expect("blind");
        let proj = id.project_at_context(b"big-attributes", RHO);

        // Disclose everything, so every value has to survive encoding on both
        // the prover's and the verifier's side.
        let p = prove(&params, &blinded, &id, &proj, b"big-attributes", RHO, 0xFF, PRES_R)
            .expect("prove");
        assert!(
            verify(&params, &p, blinded.commitment(), &proj, b"big-attributes").expect("verify"),
            "a credential with large attributes failed to verify"
        );
        assert_eq!(p.disclosed_values, big, "large attribute values did not survive");
    }

    /// Two values that differ only above the old single-coefficient limit must
    /// encode differently. Otherwise the wider encoding would be decorative and
    /// they would collide exactly as they did before.
    #[test]
    fn values_differing_above_the_old_limit_do_not_collide() {
        let a = encode_attribute(19_900_101).expect("encode");
        let b = encode_attribute(19_900_101 + PARAM_Q as u64).expect("encode");
        assert_ne!(
            a.coeffs, b.coeffs,
            "two values a multiple of q apart encoded identically"
        );
    }

    /// Every disclosure pattern must work, not only the one the happy path uses.
    #[test]
    fn every_disclosure_pattern_verifies() {
        let f = fixture(0x42, b"context-alpha");
        for mask in [0u8, 1, 0b1010_1010, 0b0111_1111, 0xFF] {
            let p = prove(&f.params, &f.blinded, &f.id, &f.proj, f.tau, RHO, mask, PRES_R)
                .expect("prove");
            assert!(
                verify(&f.params, &p, f.blinded.commitment(), &f.proj, f.tau).expect("verify"),
                "disclosure mask {mask:#010b} failed to verify"
            );
        }
    }
}
