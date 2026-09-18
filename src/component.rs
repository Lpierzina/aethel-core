//! WebAssembly Component Model adapter for the `aethel:core` WIT world.
//!
//! This is the L1 boundary the charter describes: **one artifact, embedded by
//! every language, never per-language crypto.** No cryptography is implemented
//! here — every function in this module converts between the WIT-declared types
//! and the native API, and calls into `plp`, `credential` or `htss`.
//!
//! ## Why this exists separately from the `wasm` feature
//!
//! The `wasm` feature produces a `wasm-bindgen` cdylib: a *core module* with a
//! flat pointer/length ABI plus JavaScript glue. That is not a Component Model
//! component, its exports are untyped, and it cannot express
//! `result<T, identity-error>`. It was also the surface on which the P3-10
//! soundness findings sat unnoticed, because nothing connected it to the
//! declared world.
//!
//! This module implements the world as declared, with its real types, generated
//! from `wit/aethel-core.wit` rather than hand-written.
//!
//! ## Build
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown \
//!   --no-default-features --features component
//! wasm-tools component new \
//!   target/wasm32-unknown-unknown/release/aethel_core.wasm \
//!   -o aethel_core.component.wasm
//! ```
//!
//! ## Removed: the `attestation` interface
//!
//! The WIT world used to export a second, single-relation SAAP surface
//! (`attestation.saap-prove` / `saap-verify`) alongside `identity`'s
//! three-relation flow. It is gone: `saap-prove` built proofs over
//! `saap::saap_public_key`, which that function's own doc comment says "was
//! never safe to publish" (no error term — an exact linear image of the
//! secret), and `saap-verify` could only ever return `ok(false)` because
//! there was no sound way to check a proof against that key. P3-11 (0X3-79)
//! built the real construction anchored on `b_τ = A_τ·s + e_τ`, exposed as
//! `identity.saap-verify-presentation`, which is the only supported SAAP
//! verification path now. `src/saap.rs` stays in the crate only because
//! `tests/saap_soundness.rs` and `tests/randomness_is_secret.rs` pin its
//! historical defects as executable characterisation tests; none of it is
//! reachable through the WIT world any more.

#![allow(clippy::needless_range_loop)]

extern crate alloc;

use alloc::vec::Vec;

wit_bindgen::generate!({
    path: "wit",
    world: "aethel-core",
});

use aethel::core::types::IdentityError as WitError;
use exports::aethel::core::identity::{
    Credential as WitCredential, DisclosureAttributes, EphemeralProjection as WitProjection,
    Guest as IdentityGuest, GuestCredential, GuestIssuerPublicParameters, GuestMasterIdentity,
    IssuerPublicParameters as WitIssuerPublicParameters, IssuerPublicParametersBorrow,
    MasterIdentity as WitMasterIdentity, MasterIdentityBorrow,
    SaapPresentation as WitSaapPresentation, ZkIdentityProof as WitZkProof,
};
use exports::aethel::core::secret_sharing::{Guest as SecretSharingGuest, HtssShare as WitShare};

use crate::identity_error::IdentityError;
use crate::{credential, htss, plp, signing};

/// The `htss-split` WIT signature carries no nonce parameter, but
/// [`htss::SecretSharer::split_key_material`] takes one to separate independent
/// sharings of the same secret.
///
/// A fixed value is safe — the nonce is explicitly not required to be secret,
/// and the threshold property rests on coefficients derived from the secret
/// itself — but it makes sharing deterministic: splitting the same secret twice
/// yields identical shares. That is acceptable for reconstruction and it does
/// not weaken the threshold, but a caller who wants two unlinkable sharings of
/// one secret cannot get them through this interface.
///
/// Adding a `nonce` parameter to `htss-split` is a WIT change that ripples into
/// P6 and P7, so it is flagged rather than made here. See 0X3-78.
const COMPONENT_SPLIT_NONCE: &[u8] = b"AETHEL_COMPONENT_HTSS_V1";

struct Component;

// ── Error mapping ─────────────────────────────────────────────────────────────

impl From<IdentityError> for WitError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::InvalidInputLength => WitError::InvalidInputLength,
            IdentityError::SerializationError => WitError::SerializationError,
            IdentityError::RejectionSamplingFailed => WitError::RejectionSamplingFailed,
            IdentityError::NormBoundViolation => WitError::NormBoundViolation,
            IdentityError::ChallengeMismatch => WitError::ChallengeMismatch,
            IdentityError::InvalidAttributeCommitment => WitError::InvalidAttributeCommitment,
            IdentityError::ThresholdNotMet => WitError::ThresholdNotMet,
            IdentityError::InvalidShareSet => WitError::InvalidShareSet,
            // A-4: the `aethel-plp-1` wire codec's four native-only variants
            // have no WIT producer and collapse to `serialization-error`
            // here — see their doc comments in `identity_error.rs` for why
            // `identity-error`'s variant ordinals stay unchanged rather than
            // growing a matching case.
            IdentityError::WireBadMagic => WitError::SerializationError,
            IdentityError::WireBadVersion => WitError::SerializationError,
            IdentityError::WireLengthMismatch => WitError::SerializationError,
            IdentityError::CoefficientOutOfRange => WitError::SerializationError,
        }
    }
}

/// `MasterIdentity::from_seed` takes `&[u8; 32]`; the WIT declares `list<u8>`,
/// which cannot express that bound. The implementation owns it, and says so with
/// `invalid-input-length` rather than truncating or panicking.
fn secret_as_seed(secret: &[u8]) -> Result<[u8; 32], WitError> {
    if secret.len() != 32 {
        return Err(WitError::InvalidInputLength);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(secret);
    Ok(seed)
}

// ── identity ──────────────────────────────────────────────────────────────────

impl IdentityGuest for Component {
    fn plp_project_at_context(
        secret: Vec<u8>,
        tau: Vec<u8>,
        randomness: Vec<u8>,
    ) -> Result<WitProjection, WitError> {
        let seed = secret_as_seed(&secret)?;
        // `randomness` seeds the error term e_tau; short randomness weakens the
        // projection to an exact linear image of the secret, so reject it.
        if randomness.len() < 32 {
            return Err(WitError::InvalidInputLength);
        }
        let identity = plp::MasterIdentity::from_seed(&seed);
        let proj = identity.project_at_context(&tau, &randomness);

        Ok(WitProjection {
            tau: proj.tau.to_vec(),
            salt: proj.salt.to_vec(),
            public_b: vec_to_coeffs(&proj.public_b),
        })
    }

    fn plp_prove_identity(
        secret: Vec<u8>,
        tau: Vec<u8>,
        randomness: Vec<u8>,
    ) -> Result<WitZkProof, WitError> {
        if randomness.len() < 32 {
            return Err(WitError::InvalidInputLength);
        }
        let seed = secret_as_seed(&secret)?;
        let identity = plp::MasterIdentity::from_seed(&seed);
        // Needs the *same* randomness the projection used, because A is
        // derived from a salt derived from it (0X3-95), and now — since the
        // challenge binds b_τ (0X3-108) — because `prove_identity` needs the
        // real `public_b` this randomness produces, not a placeholder. The
        // proving seed is still the secret itself; `prove_identity` runs a
        // fixed 16-iteration rejection loop and returns
        // `rejection-sampling-failed` if every iteration is rejected, rather
        // than a proof that failed the norm bound.
        let proj = identity.project_at_context(&tau, &randomness);
        let proof = plp::Prover::prove_identity(&identity, &proj, &seed)?;

        Ok(WitZkProof {
            commitment_w: vec_to_coeffs(&proof.commitment_w),
            challenge_c: proof.challenge_c.coeffs().to_vec(),
            response_z: vec_to_coeffs(&proof.response_z),
        })
    }

    fn plp_verify(projection: WitProjection, proof: WitZkProof) -> Result<bool, WitError> {
        let proj = projection_from_wit(&projection)?;
        let zk = zk_proof_from_wit(&proof)?;

        // A well-formed proof that does not verify is `ok(false)`; input that
        // could not be parsed is `err`. The previous export returned a bare
        // `bool` and could not tell a caller which had happened.
        Ok(plp::Verifier::verify(&proj, &zk))
    }

    type MasterIdentity = OwnedIdentity;
    type Credential = OwnedCredential;
    type IssuerPublicParameters = OwnedIssuerParams;

    fn saap_verify_presentation(
        issuer: IssuerPublicParametersBorrow<'_>,
        presentation: WitSaapPresentation,
        projection: WitProjection,
        tau: Vec<u8>,
    ) -> Result<bool, WitError> {
        // A presentation is not allowed to certify its own context. The verifier
        // supplies tau and the presentation must agree with it, which is the
        // check P3-10 found missing on the old verifier.
        if presentation.tau != tau {
            return Ok(false);
        }

        let proj = projection_from_wit(&projection)?;
        let t_blind = credential::unflatten::<{ credential::CRED_T }>(&presentation.t_blind)?;

        if presentation.disclosed_values.len() != credential::CRED_ATTRIBUTES {
            return Err(WitError::InvalidInputLength);
        }
        let mut disclosed_values = [0u64; credential::CRED_ATTRIBUTES];
        disclosed_values.copy_from_slice(&presentation.disclosed_values);

        let mut tau_padded = [0u8; 32];
        let len = tau.len().min(32);
        tau_padded[..len].copy_from_slice(&tau[..len]);

        let native = credential::SaapPresentation {
            tau: tau_padded,
            disclosed: presentation.disclosed.bits(),
            disclosed_values,
            challenge: credential::unflatten::<1>(&presentation.challenge)?[0],
            z_r: credential::unflatten::<{ credential::CRED_L }>(&presentation.z_r)?,
            z_m: credential::unflatten::<{ credential::CRED_SLOTS }>(&presentation.z_m)?,
            z_s: credential::unflatten::<{ plp::MODULE_K }>(&presentation.z_s)?,
            z_e: credential::unflatten::<{ plp::MODULE_K }>(&presentation.z_e)?,
        };

        let params = &issuer.get::<OwnedIssuerParams>().0;
        credential::verify(params, &native, &t_blind, &proj, &tau).map_err(Into::into)
    }

    fn verify_signature(
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, WitError> {
        signing::verify(&public_key, &message, &signature).map_err(Into::into)
    }

    /// A-4: verify from `aethel-plp-1` wire bytes, binding the verifier's
    /// own context. Delegates entirely to `crate::wire::verify_projection`
    /// so the component and native paths share one implementation.
    fn plp_verify_bytes(
        projection: Vec<u8>,
        proof: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<bool, WitError> {
        crate::wire::verify_projection(&projection, &proof, &context).map_err(Into::into)
    }

    /// A-4: encode a typed projection as `aethel-plp-1` wire bytes.
    ///
    /// No `WitError` in this signature (see the WIT doc comment for why):
    /// a malformed record — `tau`/`salt` not exactly 32 bytes, or `public-b`
    /// not exactly `MODULE_K * RING_N` coefficients or carrying an
    /// out-of-range coefficient — encodes to an empty `Vec`, which
    /// `plp-verify-bytes`/`wire::decode_projection` is guaranteed to reject
    /// on length rather than silently accepting truncated data.
    fn encode_projection(projection: WitProjection) -> Vec<u8> {
        match projection_from_wit(&projection) {
            Ok(proj) => crate::wire::encode_projection(&proj),
            Err(_) => Vec::new(),
        }
    }

    /// A-4: encode a typed proof as `aethel-plp-1` wire bytes. See
    /// [`Self::encode_projection`] for why this has no `WitError`.
    fn encode_proof(proof: WitZkProof) -> Vec<u8> {
        match zk_proof_from_wit(&proof) {
            Ok(zk) => crate::wire::encode_proof(&zk),
            Err(_) => Vec::new(),
        }
    }
}

/// The component-side owner of a [`signing::Identity`].
///
/// The secret key lives in here for the lifetime of the resource handle and has
/// no route out: the WIT exposes `public-key`, `sign`, `project-at-context` and
/// `prove`, and none of them returns key material. That is the charter's
/// "no private key material crosses out of L1" expressed as a type rather than
/// as a convention.
pub struct OwnedIdentity(signing::Identity);

impl GuestMasterIdentity for OwnedIdentity {
    fn generate(entropy: Vec<u8>) -> Result<WitMasterIdentity, WitError> {
        let identity = signing::Identity::generate(&entropy)?;
        Ok(WitMasterIdentity::new(OwnedIdentity(identity)))
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }

    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, WitError> {
        self.0.sign(&message).map_err(Into::into)
    }

    fn project_at_context(
        &self,
        tau: Vec<u8>,
        randomness: Vec<u8>,
    ) -> Result<WitProjection, WitError> {
        // Delegates to `signing::Identity::project_at_context` (A-1) so the
        // component and native paths share one derivation instead of two
        // that happen to agree. The length bound on `randomness` is enforced
        // there.
        let proj = self.0.project_at_context(&tau, &randomness)?;

        Ok(WitProjection {
            tau: proj.tau.to_vec(),
            salt: proj.salt.to_vec(),
            public_b: vec_to_coeffs(&proj.public_b),
        })
    }

    fn export_sealed(&self, key: Vec<u8>) -> Result<Vec<u8>, WitError> {
        self.0.export_sealed(&key).map_err(Into::into)
    }

    fn import_sealed(sealed: Vec<u8>, key: Vec<u8>) -> Result<WitMasterIdentity, WitError> {
        let identity = signing::Identity::import_sealed(&sealed, &key)?;
        Ok(WitMasterIdentity::new(OwnedIdentity(identity)))
    }

    fn prove(&self, tau: Vec<u8>, randomness: Vec<u8>) -> Result<WitZkProof, WitError> {
        // Delegates to `signing::Identity::prove` (A-1) — same randomness as
        // the projection at this tau, enforced there. See `plp_prove_identity`
        // for why the randomness must match.
        let proof = self.0.prove(&tau, &randomness)?;

        Ok(WitZkProof {
            commitment_w: vec_to_coeffs(&proof.commitment_w),
            challenge_c: proof.challenge_c.coeffs().to_vec(),
            response_z: vec_to_coeffs(&proof.response_z),
        })
    }
}

/// Flatten a rank-`k` vector into the `list<u32>` the WIT records carry.
///
/// Component order, low index first. The WIT type is unchanged by the module
/// rank: only the list length moves, from `RING_N` to `MODULE_K * RING_N`.
fn vec_to_coeffs(v: &plp::PolyVec) -> alloc::vec::Vec<u32> {
    let mut out = alloc::vec::Vec::with_capacity(plp::MODULE_K * crate::RING_N);
    for poly in v.iter() {
        out.extend_from_slice(poly.coeffs());
    }
    out
}

/// Parse a `list<u32>` back into a rank-`k` vector.
///
/// The length check is exact. A caller handing over a rank-1 list, which is what
/// every projection published before the rank change looks like, is rejected
/// rather than zero-extended into a projection that would then fail to verify
/// for an unexplained reason.
///
/// **Range-checked (A-4).** Every coefficient must be `< Q`. This used to
/// copy `u32`s straight into a `Poly` with no such check; `add_mod`/`sub_mod`
/// (`plp.rs`) assume reduced inputs, so an out-of-range coefficient from an
/// untrusted WIT caller produced undefined arithmetic — not a soundness
/// break by itself, since the Fiat-Shamir challenge recomputation would
/// still reject a forged transcript, but a robustness defect the new codec
/// (`plp::EphemeralProjection::from_bytes` / `ZkIdentityProof::from_bytes`)
/// must not inherit. This function now shares that same check.
fn vec_from_coeffs(coeffs: &[u32]) -> Result<plp::PolyVec, WitError> {
    if coeffs.len() != plp::MODULE_K * crate::RING_N {
        return Err(WitError::SerializationError);
    }
    for &c in coeffs {
        if c >= plp::Q {
            return Err(WitError::SerializationError);
        }
    }
    let mut out = [plp::Poly::zero(); plp::MODULE_K];
    for (i, chunk) in coeffs.chunks(crate::RING_N).enumerate() {
        out[i].coeffs.copy_from_slice(chunk);
    }
    Ok(out)
}

/// See [`vec_from_coeffs`]: same exact-length and `< Q` range checks, for a
/// single ring element (the proof's `challenge-c`).
fn poly_from_coeffs(coeffs: &[u32]) -> Result<plp::Poly, WitError> {
    if coeffs.len() != crate::RING_N {
        return Err(WitError::SerializationError);
    }
    for &c in coeffs {
        if c >= plp::Q {
            return Err(WitError::SerializationError);
        }
    }
    let mut poly = plp::Poly::zero();
    poly.coeffs.copy_from_slice(coeffs);
    Ok(poly)
}

fn projection_from_wit(p: &WitProjection) -> Result<plp::EphemeralProjection, WitError> {
    if p.tau.len() != 32 {
        return Err(WitError::SerializationError);
    }
    if p.salt.len() != 32 {
        return Err(WitError::SerializationError);
    }
    let mut tau = [0u8; 32];
    tau.copy_from_slice(&p.tau);
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&p.salt);

    Ok(plp::EphemeralProjection {
        tau,
        salt,
        // Derived, not decoded. The wire carries no matrix, so there is no
        // inconsistent A for a caller to supply. See the record's doc comment.
        matrix_a: plp::derive_context_matrix(&tau, &salt),
        public_b: vec_from_coeffs(&p.public_b)?,
    })
}

fn zk_proof_from_wit(p: &WitZkProof) -> Result<plp::ZkIdentityProof, WitError> {
    Ok(plp::ZkIdentityProof {
        commitment_w: vec_from_coeffs(&p.commitment_w)?,
        challenge_c: poly_from_coeffs(&p.challenge_c)?,
        response_z: vec_from_coeffs(&p.response_z)?,
    })
}

// ── secret-sharing ────────────────────────────────────────────────────────────

impl SecretSharingGuest for Component {
    /// # L1 boundary review (P3-12 / 0X3-80)
    ///
    /// Shares are key-derived, and they leave the component, so it is worth
    /// stating exactly why that does not widen the boundary the charter draws.
    ///
    /// **The secret arrives from outside.** `htss-split` takes
    /// `secret: list<u8>` as a parameter, so whoever calls it already holds
    /// that material; splitting it emits nothing the caller did not have. This
    /// is the opposite posture from `master-identity`, which derives its secret
    /// inside the component and exposes no accessor for it.
    ///
    /// **A `master-identity`'s secret cannot reach here.** That resource has no
    /// method returning its ML-DSA key or PLP seed — `public-key` is the only
    /// key material it emits, and `export-sealed` emits ciphertext under a
    /// caller-supplied key. So there is no route, inside the component or
    /// outside it, from a generated identity to `htss-split`. Splitting an
    /// identity for recovery would need a method on the resource itself, which
    /// is P5-08's design problem, not something this surface silently allows.
    ///
    /// **What a share reveals.** Each share is an index and a value; the value
    /// is one evaluation per 16-bit limb. Its length therefore discloses the
    /// secret's length rounded up to a limb, and nothing else. Below the
    /// threshold the shares are information-theoretically independent of the
    /// secret, which `a_public_nonce_does_not_compromise_a_single_share` and
    /// `losing_one_share_does_not_lose_the_secret` assert rather than assume.
    ///
    /// **Shares are secret material to the caller.** Three of five reconstruct,
    /// so a caller holding three has the secret. That is the scheme working as
    /// designed, not a leak, but it does mean shares must be distributed to
    /// distinct custodians. The WIT cannot enforce that and does not pretend to.
    ///
    /// **The root is not secret and is not optional.** `htss-split` now also
    /// returns a 32-byte root; `htss-reconstruct` needs it to tell a genuine
    /// share from a fabricated one (0X3-105). The root discloses nothing about
    /// the secret — it is a hash-based commitment to the share set, not to the
    /// secret itself — but it is load-bearing: keep it somewhere a share
    /// custodian cannot also tamper with, or the authentication step is
    /// checking fabricated shares against a fabricated root. See
    /// `SecretSharer::reconstruct_key_material`'s doc comment for the exact
    /// trust boundary.
    fn htss_split(secret: Vec<u8>) -> Result<(Vec<WitShare>, Vec<u8>), WitError> {
        let (shares, root) =
            htss::SecretSharer::split_key_material(&secret, COMPONENT_SPLIT_NONCE)?;
        let wit_shares = shares
            .into_iter()
            .map(|s| WitShare {
                index: s.index,
                value: s.value,
                path: s.path,
            })
            .collect();
        Ok((wit_shares, root.to_vec()))
    }

    fn htss_reconstruct(shares: Vec<WitShare>, root: Vec<u8>) -> Result<Vec<u8>, WitError> {
        if root.len() != 32 {
            return Err(WitError::InvalidInputLength);
        }
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&root);

        let native: Vec<htss::HtssShare> = shares
            .into_iter()
            .map(|s| htss::HtssShare {
                index: s.index,
                value: s.value,
                path: s.path,
            })
            .collect();
        Ok(htss::SecretSharer::reconstruct_key_material(
            &native, &root_arr,
        )?)
    }
}

export!(Component);

/// The component-side owner of an issued credential.
///
/// The commitment randomness and the attribute values live in here for the
/// lifetime of the handle and have no route out. `present` is the only method,
/// and it returns disclosed values, a fresh blinded commitment and the
/// responses, none of which is key material.
///
/// The issuer's **public** parameters are kept alongside the credential because
/// presenting needs the same `B_1` the credential was issued under, and asking
/// the caller to supply it again on every presentation would be one more thing
/// to get wrong. The seed is not kept: it is consumed at issuance and dropped,
/// so a holder's runtime does not sit on the issuing secret for the lifetime of
/// the credential. It used to.
pub struct OwnedCredential {
    credential: credential::Credential,
    params: credential::IssuerParams,
}

impl GuestCredential for OwnedCredential {
    fn issue(
        holder: MasterIdentityBorrow<'_>,
        issuer_seed: Vec<u8>,
        attributes: Vec<u64>,
        issuance_randomness: Vec<u8>,
    ) -> Result<WitCredential, WitError> {
        if attributes.len() != credential::CRED_ATTRIBUTES {
            return Err(WitError::InvalidInputLength);
        }
        let mut values = [0u64; credential::CRED_ATTRIBUTES];
        values.copy_from_slice(&attributes);

        let identity = plp::MasterIdentity::from_seed(holder.get::<OwnedIdentity>().0.plp_seed());
        let params = credential::IssuerParams::from_seed(&issuer_seed)?;
        let cred =
            credential::Credential::issue(&params, &identity, &values, &issuance_randomness)?;

        Ok(WitCredential::new(OwnedCredential {
            credential: cred,
            params,
        }))
    }

    fn present(
        &self,
        holder: MasterIdentityBorrow<'_>,
        tau: Vec<u8>,
        projection_randomness: Vec<u8>,
        disclosed: DisclosureAttributes,
        blinding_randomness: Vec<u8>,
        presentation_randomness: Vec<u8>,
    ) -> Result<WitSaapPresentation, WitError> {
        if projection_randomness.len() < 32 {
            return Err(WitError::InvalidInputLength);
        }

        let identity = plp::MasterIdentity::from_seed(holder.get::<OwnedIdentity>().0.plp_seed());
        let projection = identity.project_at_context(&tau, &projection_randomness);

        let blinded = credential::BlindedCredential::new(
            &self.params,
            &self.credential,
            &blinding_randomness,
        )?;

        let presentation = credential::prove(
            &self.params,
            &blinded,
            &identity,
            &projection,
            &tau,
            &projection_randomness,
            disclosed.bits(),
            &presentation_randomness,
        )?;

        Ok(WitSaapPresentation {
            tau,
            disclosed,
            disclosed_values: presentation.disclosed_values.to_vec(),
            t_blind: credential::commitment_flat(&blinded),
            challenge: presentation.challenge.coeffs.to_vec(),
            z_r: credential::flatten(&presentation.z_r),
            z_m: credential::flatten(&presentation.z_m),
            z_s: credential::flatten(&presentation.z_s),
            z_e: credential::flatten(&presentation.z_e),
        })
    }
}

/// The component-side owner of a [`credential::IssuerParams`].
///
/// A resource rather than a record so that the only way to obtain one is to
/// derive it from a seed or to deserialise published bytes. A record of raw
/// bytes would be structurally interchangeable with the seed, which is the
/// confusion this type exists to prevent.
pub struct OwnedIssuerParams(credential::IssuerParams);

impl GuestIssuerPublicParameters for OwnedIssuerParams {
    fn derive(issuer_seed: Vec<u8>) -> Result<WitIssuerPublicParameters, WitError> {
        let params = credential::IssuerParams::from_seed(&issuer_seed)?;
        Ok(WitIssuerPublicParameters::new(OwnedIssuerParams(params)))
    }

    fn serialize(&self) -> Vec<u8> {
        self.0.public_seed().to_vec()
    }

    fn deserialize(bytes: Vec<u8>) -> Result<WitIssuerPublicParameters, WitError> {
        let seed: [u8; credential::PUBLIC_SEED_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| WitError::InvalidInputLength)?;
        let params = credential::IssuerParams::from_public_seed(&seed);
        Ok(WitIssuerPublicParameters::new(OwnedIssuerParams(params)))
    }
}
