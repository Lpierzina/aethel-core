# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.6.0] - 2026-09-10

Closes the aethel-core portion of the SAGP-PG-001 primitive-gap-remediation plan (A-1
through A-5, X-2, X-3). See `aethel-docs/plan/PRIMITIVE-GAP-REMEDIATION.md` §2 for the
full gap-by-gap rationale; this entry lists the resulting public-API surface.

### Added

- **`signing::Identity::project_at_context`/`prove` (A-1).** The native bridge from a
  `signing::Identity` to a PLP projection/proof, mirroring the WIT `master-identity`
  resource's `project-at-context`/`prove` methods. Previously the only route from an
  `Identity` to `plp` was the crate-private `plp_seed()`, reachable only from
  `component.rs`; a native "load identity, present to a verifier" flow could not be
  written without holding two unrelated secrets. `component.rs`'s `OwnedIdentity` now
  delegates to these methods instead of duplicating the derivation.
- **`signing::Identity::sign_with_purpose` / `signing::verify_with_purpose` (A-1 / X-2).**
  Purpose-separated (domain-separated) signing via FIPS 204's native `ctx` mechanism
  (`pqc_sig::MlDsa65Keypair::sign_ctx_deterministic`/`verify_ctx`). A signature made under
  one purpose does not verify under another, nor under plain `sign`/`verify` for a
  non-empty purpose; an empty purpose is byte-identical to plain `sign`/`verify`.
- **`signing::purpose` registry (A-1 / X-2).** Pinned context-string constants:
  `PLP_PRESENT_V1`, `CREDENTIAL_V1`, `SAAP_V1` for this crate's own operations, and
  `VAULT_SPEND_INTENT_V1`, `VAULT_SETTLEMENT_RECEIPT_V1`, `VAULT_WALLET_BIND_V1`,
  `VAULT_HITL_APPROVAL_V1` reserved on aethel-vault's behalf. See `docs/PURPOSES.md`.
- **`examples/present_to_verifier.rs` (A-1).** A ~40-line, network-free, end-to-end demo:
  generate an identity, derive a projection + proof, sign an attach challenge under a
  purpose, and verify everything from bytes only. Run with
  `cargo run --example present_to_verifier`.
- **`wire` module — the `aethel-plp-1` versioned wire envelope (A-4).**
  `wire::{encode_projection, decode_projection, encode_proof, decode_proof}` and the public
  entry point the gap analysis names:
  `wire::verify_projection(projection: &[u8], proof: &[u8], context: &[u8]) -> Result<bool, IdentityError>`.
  Envelope: `magic(4, = EIAB_MAGIC) ‖ version(1) ‖ kind(1) ‖ body_len(4, LE) ‖ body`. See
  `docs/WIRE-FORMAT.md` for the normative spec.
- **`plp::ZkIdentityProof::{to_bytes, from_bytes}` (A-4).** A proof previously had no byte
  codec at all (`ZK_IDENTITY_PROOF_BYTE_LEN` new). Decode-then-validate: exact length,
  every coefficient `< Q`, and `challenge_c` must be ternary with exactly
  `CHALLENGE_WEIGHT` non-zero coefficients.
- **WIT (additive): `plp-verify-bytes`, `encode-projection`, `encode-proof`.** Appended to
  `interface identity` in `wit/aethel-core.wit`; does not change `identity-error`'s variant
  ordinals. Implemented in `component.rs` by delegating to `wire::verify_projection`/
  `wire::{encode_projection,encode_proof}`.
- **`IdentityError` gained four native-only variants (A-4):** `WireBadMagic`,
  `WireBadVersion`, `WireLengthMismatch`, `CoefficientOutOfRange`. None has a WIT producer
  — `component.rs`'s `From<IdentityError> for WitError` collapses all four to
  `WitError::SerializationError`, so the WIT `identity-error` variant is unchanged.
- **`tests/vectors/aethel-plp-1/` (A-5 / X-4).** Checked-in, deterministically-generated
  hex test vectors (`valid-1`, `valid-2`, `tampered-projection`, `tampered-proof`,
  `wrong-context`) plus `tests/plp_vectors.rs` (native loader/verifier, and the
  `#[ignore]`d `regenerate_vectors`) and two new tests in `tests/component_execution.rs`
  that drive the identical files through the component's `plp-verify-bytes`. This is the
  "sagp-host (native) and agent SDKs (wasm) agree" proof: one set of files, two runtimes.
- **`docs/PURPOSES.md` (X-2)** and **`docs/WIRE-FORMAT.md` (A-4)** — new normative/reference
  docs; see their contents for detail. `docs/PLP-ALGORITHM.md` gained §9 (PLP vs
  `did:pkh:eip155`, A-2) and `docs/HTSS-TOPOLOGY.md` / `src/htss.rs` gained a "Who runs
  HTSS" section (A-3): HTSS is a principal/operator backup ritual, not a hosted service.

### Changed (BREAKING)

- **`sampling::{PlpProof, RejectionError, VectorK}` no longer re-exported at the crate
  root.** These are the enclave sampler's internal types; re-exporting them mixed sampler
  internals into the public verify surface, which A-4 closes. Still reachable at
  `aethel_core::sampling::*`.
- **`EphemeralProjection::from_bytes` is stricter.** Length check changed from `>=` to
  exact equality, and every `public_b` coefficient is now checked `< Q`
  (`IdentityError::CoefficientOutOfRange` on violation) before any arithmetic touches it.
  Previously accepted over-long buffers and unranged coefficients.
- **`plp::pad_tau` is now `pub`** (was `pub(crate)`) — needed so `wire::verify_projection`
  can compute the padded context form outside the `plp` module boundary.
- **`component.rs`'s `vec_from_coeffs`/`poly_from_coeffs` now range-check `< Q`.**
  Previously copied `u32` coefficients from an untrusted WIT caller straight into a `Poly`
  with no check; `add_mod`/`sub_mod` assume reduced inputs. Not a soundness break by
  itself (the Fiat-Shamir challenge recomputation still rejects a forged transcript), but
  a robustness defect the new byte codecs must not inherit.
- **`lib.rs`'s stale feature-flag doc corrected.** The `wasm` feature and `puf_enroll`/
  `puf_reconstruct` WASM exports described there no longer exist (retired in 0.1.5 / P3-13);
  the doc now describes `component` and the current `puf` feature accurately.
- **`signing::Identity` and `signing::verify` now re-exported at the crate root**
  (`pub use signing::{Identity, verify, verify_with_purpose};`), alongside
  `pub use wire::verify_projection;`.

### Security

- No change to the cryptographic construction itself in this release; A-4's range checks
  and exact-length decoding harden the *codec* boundary against malformed/adversarial
  input without altering `Prover`/`Verifier`'s math.

## [0.5.0] - 2026-09-08

### Security

- **Recorded three limitations in the shipped identity and credential paths.**
  A cryptographic review of the `plp` and `credential` modules completed on
  2026-09-08. The projection operates at module rank 1 where the specification
  requires 4, so the lattice-hardness argument written for the specified profile
  does not apply to the shipped code. The credential commitment is specified with
  a randomness dimension below its commitment dimension and therefore does not
  provide the hiding property claimed for it, which means undisclosed attribute
  values are not protected by the commitment and two presentations of one
  credential are not unlinkable. The rejection-sampling bound `beta` corresponds
  to a challenge of weight 39 while the implemented challenge has weight 60, so
  the rejection-sampling argument does not carry as written, though measured
  behaviour stays far from the bound. Full detail in
  [`SECURITY.md`](./SECURITY.md#known-limitations).

### Changed

- **The PLP identity path now runs at module rank 4 (BREAKING).**
  `AETHEL-SPEC-001` §3.2 sets `k = 4` for the profile this crate targets and §9.2
  forbids going below it. The implementation ran at rank 1, so the hardness
  argument in `SECURITY-PROOFS.md`, written for a secret dimension of 1024 and a
  BKZ block size of 400, did not describe the shipped code. The master secret,
  context matrix, projection, error term, commitment and response are now
  rank-4 module elements, sourced from `plp::MODULE_K`.

  The rank is a single constant and every operation is generic in it, so moving
  to LEVEL3 or LEVEL5 is a parameter change rather than a rewrite.

  Three domain separators move, because the objects they derive are no longer the
  same shape: `AETHEL_PLP_CTX_V2` to `V3`, `AETHEL_PLP_CHALLENGE_V3` to `V4`, and
  `AETHEL_ERROR_V2` to `V3`. The WIT record types are unchanged, since
  `public-b`, `commitment-w` and `response-z` were already `list<u32>` and only
  their length moves. A projection or proof produced by `0.4.0` is rejected on
  length rather than silently zero-extended. There is no migration path:
  regenerate identities.

  Measured over 500 identity proofs and 200 credential presentations, no honest
  prover exhausted its rejection-sampling budget, so the existing iteration
  ceilings absorb the lower per-iteration acceptance rate that four times as many
  coefficients implies.

- **The Fiat-Shamir challenge weight is now derived, not asserted (BREAKING).**
  The challenge carried 60 non-zero coefficients while `β = 78` is the value for a
  weight-39 challenge against a CBD(η=2) witness. The rejection-sampling argument
  needs `β` to bound the infinity norm of the challenge times the witness, and at
  weight 60 the worst case is 120, so `SECURITY-PROOFS.md` §7.4 did not carry.
  Measured behaviour stayed far from the bound, so the practical leakage was
  negligible, but every extraction bound stated elsewhere depends on the true
  value.

  The weight is now 39 (`plp::CHALLENGE_WEIGHT`), shared between `plp` and `saap`
  so one bound cannot serve two challenge spaces. That makes the parameter set
  exactly the profile the specification defines rather than a mixture of two
  ML-DSA profiles, at no cost in proof size. The relationship
  `BETA >= CHALLENGE_WEIGHT * ETA` is asserted at compile time, so the drift
  cannot recur silently.

- **Rejection-sampling ceilings raised to match the module rank.**
  Rank 4 doubled the short responses in a credential presentation, from 6
  polynomials to 12, so 3072 coefficients must now clear `γ₁ - β`. That accepts
  about 16% of the time, and the previous 32 attempts left roughly 1 honest
  presentation in 270 failing outright. The credential ceiling is now 192,
  putting exhaustion at about 2e-15; the identity ceiling moves from 16 to 48,
  from about 1 in 280,000 to about 5e-17. Expected attempts are 6 and 2
  respectively, so typical latency is unchanged and only the tail moves. Both
  scale with the rank and are documented as needing revisiting if it changes.

  `γ₁` deliberately stays at 2^17. Moving it to 2^19 would have restored the rate
  with the old ceilings, but it would take the parameter set off the specified
  profile and widen every extracted bound by four times against `q/2 ≈ 2^22`.

- **The credential challenge and masks now bind the whole statement (BREAKING).**
  `derive_challenge` absorbed neither the per-projection salt that determines
  `A_τ` nor the issuer public seed that determines `B_1`, so both matrices were
  bound to the transcript only through the verification equations. That is the
  weak Fiat-Shamir pattern `plp` corrected earlier and the correction had not
  reached `credential`. Both are now absorbed, and `AETHEL_SAAP_CHALLENGE_V2`
  becomes `V3`.

  Presentation masks derived from `presentation_randomness`, a tag, the iteration
  nonce and the slot index only. Two presentations that reused the randomness
  therefore shared `y_s`, and subtracting the responses gave `(c₁ − c₂)·s`, which
  recovers the master secret. Masks now absorb the context, the blinded
  commitment, the projection, the disclosure set and the disclosed values, so
  reuse is harmless rather than catastrophic. `AETHEL_SAAP_PROOF_MASK_V1` becomes
  `V2`. This changes what a prover produces and not what a verifier checks, so it
  is not itself a wire change.

- **Corrected published claims to match the implementation.** The README's
  parameter table stated a module rank of 4, and two domain separators that the
  code had already moved past. `docs/SAAP-SPEC.md` asserted context-isolated
  unlinkability, presentation unlinkability and zero-knowledge disclosure without
  qualification. Each now records whether it is achieved at the shipped
  parameters or remains a requirement the implementation does not yet meet.

## [0.4.0] - 2026-09-06

### Changed

- **Verification no longer takes the issuer's secret (BREAKING).**
  `saap-verify-presentation` took `issuer-seed`, the same value
  `credential.issue` takes. Every party able to verify a presentation therefore
  held the authority to issue credentials that would verify under the same
  issuer, so an issuer could not let a third party verify, a verifier could not
  be a public endpoint, and issuer and verifier could not be separate
  organisations. Two independent readers found this from the published
  documentation alone during blind testing of the Rust SDK.

  The issuer's public parameters are now a distinct type in the world,
  `issuer-public-parameters`, derived from the seed and carrying no part of it.
  `saap-verify-presentation` takes those. `credential.issue` continues to take
  the seed, as it must. There is no seed-taking verification entry point left,
  deliberately: keeping one would leave the wrong wiring available to anyone who
  reached for the familiar signature.

  Public parameters serialise to 32 bytes, round-trip through `deserialize`, and
  are safe to publish: the seed is hashed through SHAKE-256 to produce them, so
  recovering it is a preimage search. What they do and do not grant is stated on
  the type itself, including the limit. The verification relation checks a short
  opening under `B_1`, not issuer authorisation, so these parameters separate the
  verifying role from the issuing role but are not on their own a forgery
  barrier. `docs/ISSUER-AUTHENTICATION.md` is new and states that gap and the
  construction that closes it.

  **Migration:** derive the parameters once and hold them, instead of passing the
  seed per call.

  ```rust
  // before
  let ok = identity::saap_verify_presentation(&issuer_seed, &presentation, &projection, tau)?;

  // after
  let issuer = IssuerPublicParameters::derive(&issuer_seed)?;   // issuing side, once
  let published = issuer.serialize();                            // 32 bytes, publish this

  let issuer = IssuerPublicParameters::deserialize(&published)?; // verifying side, once
  let ok = identity::saap_verify_presentation(&issuer, &presentation, &projection, tau)?;
  ```

  A verifier that only ever holds `published` cannot issue. A presentation
  verifies against parameters derived from the seed it was issued under and
  against no other issuer's, asserted by test on both sides of the component
  boundary.

- **An issuer seed must be at least 32 bytes.** It is secret key material and now
  carries the same floor as the rest of this world's secrets. `credential.issue`
  and `issuer-public-parameters.derive` both return `invalid-input-length` for a
  shorter one. Previously any length was accepted, including empty.

- **`B_1` is expanded from the issuer's public seed rather than the issuer seed
  (BREAKING at the wire level).** Interposing the public seed is what gives the
  parameters a compact publishable form; expanding straight from the issuer seed
  left the seed as the only short representation of `B_1`, so handing a verifier
  something it could pin meant handing it the issuing secret. Credentials issued
  under a previous version do not verify under this one and must be reissued.

### Security

- **A credential resource no longer retains the issuer seed.** It kept the seed
  for the lifetime of the handle so that `present` could re-expand `B_1`, which
  left the issuing secret sitting in the holder's runtime after issuance. It now
  keeps the derived public parameters instead, and the seed is dropped once
  issuance is done.

### Fixed

- `component.sha256` updated to
  `5fee03ee725d32da4949d8d0769dc48fe2f68d5b664b33bdd928a889b7f50dd4`. The reshaped world and
  the version string both move the compiled component's bytes. Verified byte-identical across
  two independent builds in CI on the canonical platform.
- **`pqc-sig` bumped from the yanked `0.3.0` to `0.3.1`.** `0.3.0` was yanked after 0.3.2
  moved onto it, so the same `cargo-deny` advisories failure that fix addressed came back
  from a different version. The requirement was already `0.3` and needed no change; only the
  lockfile was pinned to the yanked release. `0.3.1` is currently the only unyanked version
  of that crate. No source change: this crate uses `SigPublicKey`/`SigAlgorithm`/`Signature`/
  `MlDsa65Keypair`, none of which changed.

## [0.3.2] - 2026-09-03

### Fixed

- **`pqc-sig` dependency bumped from the yanked `0.1.0` to `0.3`.** `0.1.0` was yanked from
  crates.io as part of CRA-2's consolidation onto a single `0.3.0` line; this crate's
  requirement was never updated to follow. This surfaced downstream as a `cargo-deny`
  advisories failure in any consumer resolving `aethel-core`'s dependency graph fresh
  (`aethel-sdk`'s COR-1 re-sync PR, specifically). No source change was needed beyond the
  version requirement: this crate only uses `pqc-sig`'s `SigPublicKey`/`SigAlgorithm`/
  `Signature`/`MlDsa65Keypair` surface, none of which changed between `0.1.0` and `0.3.0` per
  `pqc-sig`'s own migration notes for plain library consumers.
- `component.sha256` updated to `375bf1f3c546fef84b45757417c39e22729b7df44063e8658bb6d0a973bc5218`,
  since the dependency change above changes the compiled component's bytes. Verified
  byte-identical across two independent builds in CI on the canonical platform.

## [0.3.1] - 2026-09-01

### Fixed

- **The Fiat-Shamir challenge now binds the projection it proves knowledge of
  (0X3-108).** The challenge absorbed the commitment, τ, and salt, which binds
  `A_τ` transitively (it is fully determined by τ and salt), but it never
  bound `b_τ` itself, and nothing else in the challenge determined it.

  That let a party with no secret key work backwards: fix a small response
  and an arbitrary commitment, compute the challenge exactly as an honest
  prover would (it never depended on `b_τ`), then solve the verification
  equation for the one `b_τ` that makes the proof check out. The resulting
  projection carries no identity behind it: it is uniform-random, with no
  secret key and no small error term, yet comes with a proof that verifies.

  The challenge now absorbs `b_τ` as well, so it can no longer be computed
  before the statement is chosen. `credential::derive_challenge` already
  absorbed its `b_tau` argument; this brings PLP's own prove/verify pair in
  line with it.

  The challenge domain separator moved to `AETHEL_PLP_CHALLENGE_V3`, so
  proofs from before this fix do not verify under this version, and the
  reverse. Not classed as breaking under [`STABILITY.md`](./STABILITY.md)'s
  own rule for this: the old behavior (accepting a forged proof) contradicted
  the documented one (that a verifying proof attests to a genuine identity),
  so the fix isn't breaking even though it changes output — called out here
  regardless, since you may have been depending on it.

## [0.3.0] - 2026-09-01

### Fixed

- **Reusing τ no longer leaks the master secret (AETHEL-F-02).** The context
  matrix `A` was `SHAKE-256("AETHEL_PLP_CTX_V1" || τ)`, a pure function of the
  context, so every projection of one identity at one τ shared it. The samples
  `b_i = A·s + e_i` then differed only in their error terms, and `e` comes from a
  centered binomial distribution, so averaging enough of them drove the noise to
  nothing and left `A·s`, from which the secret is linear algebra over the ring
  rather than an M-LWE instance. Roughly 64 samples sufficed, and freshness of
  each individual `e_i` did not help.

  `A` is now derived from τ **and** a per-projection salt, and the salt is
  derived from the caller's projection randomness. Two projections at one τ are
  independent samples under unrelated matrices, so there is nothing to average.
  Measured against the old construction the attack recovers 256 of 256
  coefficients of `A·s`; against the new one it recovers 0.

  This was previously documented as a caller obligation ("τ MUST be single-use")
  rather than enforced. A documented MUST is a weak control when violating it
  costs the master secret and the canonical τ is a block height, which collides
  across users by construction. The obligation now rests on the projection
  randomness instead, which is a value the caller generates rather than one they
  are handed.

- **The Fiat-Shamir challenge binds the whole projection.** It hashed the
  commitment and the **first 8 bytes** of τ, so a proof was bound neither to the
  rest of the context nor to `A`. It now covers the full τ and the salt.

- **`htss-reconstruct` now authenticates every share against a root, closing
  the gap `invalid-share-set`'s duplicate-index and cardinality checks could
  not.** Those checks (0.2.0) stopped a share list that cannot determine any
  secret at all. They could not stop one that determines a secret nobody ever
  split: three well-formed shares at three distinct indices interpolate
  whether or not any of them came out of a real `htss-split` call, because
  nothing about valid indices, matching width, or Lagrange interpolation
  distinguishes a genuine share from a fabricated one at a free index. An
  attacker who can call `htss-split` at all (which needs no privilege, since
  the secret it splits is caller-supplied) can trivially produce such a
  share list by splitting bytes of their own choosing.

  `htss-split` now also returns a 32-byte root, and every `htss-share` carries
  a Merkle inclusion path proving its membership in the tree that root names.
  `htss-reconstruct` checks every supplied share's path against the
  caller-supplied root before interpolation runs; a share that does not check
  out (wrong tree, tampered value, swapped path) is refused as
  `invalid-share-set` regardless of how well-formed it otherwise looks.
  Fabricating a share that passes verification against a root you did not
  build requires a second preimage of SHA3-256.

  **This authenticates shares to a root. It does not authenticate the root
  itself.** `root` is ordinary caller input, like everything else in these
  signatures; `htss-reconstruct` has no way to know whether it is the genuine
  value from a real split. A caller who receives `(shares, root)` as one
  untrusted bundle and passes both straight through gets no protection: an
  attacker can always mint a self-consistent bundle of their own. The
  guarantee is only as strong as the channel used to obtain `root`, the same
  requirement verifying a signature places on the public key.

### Changed (breaking)

- **`ephemeral-projection` replaces `matrix-a` with `salt`.** `A` is fully
  determined by `tau` and `salt`, so carrying it would be redundant bytes a
  verifier would have to trust or cross-check. Deriving it on decode makes an
  inconsistent `A` unrepresentable rather than merely detectable, and shrinks the
  record from `32 + 8N` bytes to `64 + 4N`.

  **Migration:** read `salt` where you read `matrix-a`. If you cached `A` by τ,
  stop: it is no longer a function of τ alone. `Verifier::verify` re-derives `A`
  and ignores the struct's cached `matrix_a` field, so a hand-built projection
  cannot supply a doctored matrix.

- **`plp-prove-identity` and `master-identity.prove` take `randomness`.** It MUST
  be the same value passed to the matching projection call. `A` used to be
  recoverable from τ alone, which is precisely the property that made τ reuse
  unsafe; with `A` salted, the prover has to be told which salt to reconstruct.

  **Migration:** `plp-prove-identity(secret, tau)` becomes
  `plp-prove-identity(secret, tau, randomness)`; `prove(tau)` becomes
  `prove(tau, randomness)`. Both refuse randomness under 32 bytes with
  `invalid-input-length`.

- **Proofs and projections from 0.2.0 do not verify under this version**, and the
  reverse. The domain separators moved to `AETHEL_PLP_CTX_V2` and
  `AETHEL_PLP_CHALLENGE_V2`, and the projection wire format changed.

- **`htss-share` gains `path`, and both HTSS operations' signatures change to
  carry a root.**

  - `htss-split(secret)` returns `result<tuple<list<htss-share>, list<u8>>,
    identity-error>` instead of `result<list<htss-share>, identity-error>`,
    with the second tuple element carrying the 32-byte root.
  - `htss-reconstruct(shares, root)` takes the root back; the previous
    signature took only `shares`.
  - `SecretSharer::split_key_material` returns
    `Result<(Vec<HtssShare>, [u8; 32]), IdentityError>` instead of
    `Result<Vec<HtssShare>, IdentityError>`.
  - `SecretSharer::reconstruct_key_material` takes `root: &[u8; 32]` as a
    second parameter.
  - The `split_key_material_bytes` / `reconstruct_key_material_bytes` wire
    format gains a 32-byte root prefix and a per-share path; see
    `split_key_material_bytes`'s doc comment for the exact layout. Both
    functions keep their existing signatures: the root travels inside the
    same blob rather than as a separate parameter, since that boundary already
    treats the whole thing as one opaque transfer unit.

  **Shares from a version before this one cannot be reconstructed under this
  version**, because they carry no path and there is no root to check them
  against. There is no migration path for shares already in storage other
  than re-splitting the underlying secret.

## [0.2.0] - 2026-09-01

### Fixed

- **`htss-reconstruct` now validates the shares as a set.** Lagrange
  interpolation is only defined over distinct evaluation points, and the
  operation checked share count, width, width uniformity and `index != 0` but
  never that the indices were distinct. Two shares carrying the same index give
  that point's basis polynomials a zero denominator, so those terms dropped out
  and the interpolation answered from whatever points remained: a value that is
  not the shared secret. Most such inputs then failed the payload's length-prefix
  sanity check and surfaced as `serialization-error`, which looks like a guard
  and is not one. A caller choosing the share values can make the length prefix
  decode, at which point the operation returned `ok(attacker-chosen bytes)`.

  The share list is now rejected as `invalid-share-set` if any index repeats, or
  if it carries more shares than the scheme issues. The cardinality bound also
  closes a work multiplier: interpolation is quadratic in the share count, and
  the list arrives unauthenticated.

  `SecretSharer::mod_inverse` returns `Option<i64>` instead of a `0` sentinel.
  Zero is never a valid inverse but is an ordinary value to multiply by, so the
  sentinel was indistinguishable from success and is the mechanism that turned a
  degenerate denominator into a silently wrong secret. The uniqueness check is
  the fix; this is the second line.

- **`htss-split` is now linear in the secret's length, not quadratic.** The
  sharing-polynomial coefficients were derived by absorbing the entire secret
  into a fresh SHAKE-256 instance for every coefficient, and the limb loop makes
  one call per byte of secret, so total absorption grew as the square of the
  input. Measured, a 4x larger secret cost 14-16x the time, and a 64 KiB secret
  meant roughly 4.3 GB of absorption and 11.7 seconds of wall clock in a release
  build for one call, on input that arrives unauthenticated.

  The secret is now absorbed once into a 32-byte coefficient key, and each
  coefficient is derived from that key plus its limb and coefficient indices, at
  constant cost. The same 64 KiB split takes about 50 milliseconds.

  The security property is unchanged and deliberately so: the secret is still the
  entropy source, so an attacker who does not know it cannot predict the
  coefficients, which is what makes shares below the threshold reveal nothing.
  Predicting a coefficient still requires the secret or a SHAKE-256 preimage.

- **`saap::saap_prove` no longer emits a rejected response on exhaustion.** Its
  all-rejected fallback re-derived the masking vector at nonce 0, which is
  iteration 0's nonce. The derivation is a pure function of
  `(rho, context_tag, nonce)`, so the commitment, challenge and response all
  recomputed to iteration 0's values: the function returned, verbatim and without
  re-checking the bound, the response iteration 0 had already rejected. An
  out-of-bound response verifies nowhere, so it could only leak, never
  authenticate.

  It now returns `Err(RejectionSamplingFailed)`, matching
  `plp::Prover::prove_identity` and `credential::prove`, which already refuse for
  this reason. "Negligible probability" was the wrong frame: 16 consecutive
  rejections is negligible by chance, but the derivation is deterministic in
  `(rho, context_tag)`, so a context that lands there can be searched for.

  Not reachable through the WIT world: `saap_prove` has had no exported caller
  since the `attestation` interface was removed in 0.1.5. Native Rust callers of
  `saap::saap_prove` must handle the `Result`.

### Added (breaking)

- **`identity-error` gains an eighth case, `invalid-share-set`,** appended last.
  A WIT `variant` is ordinal-encoded, so the new case is added at the end of the
  list: inserting anywhere else silently renumbers every case after it for
  callers compiled against an earlier version of this world. Callers that match
  `identity-error` exhaustively must add an arm. Five of the eight cases now have
  producers; the three `RESERVED` cases are unchanged.

### Changed (breaking)

- **Share values from `htss-split` have changed.** The coefficient derivation's
  domain separator moved from `AETHEL_HTSS_COEFF_V1` to `AETHEL_HTSS_COEFF_V2`,
  so every coefficient, and therefore every share value, differs from what the
  previous version produced for the same secret and nonce. Shares from the two
  derivations must not be mixed within one reconstruction.

  **Reconstruction is unaffected.** `htss-reconstruct` is Lagrange interpolation
  over the share values and never re-derives a coefficient, so a set of shares
  issued by an earlier version still reconstructs correctly under this one. What
  breaks is only re-splitting the same secret and expecting the old share values
  back.

- **`htss-split` refuses a secret larger than 64 KiB** with
  `invalid-input-length`. The previous bound was `u32::MAX`, about 4 GiB, which
  is the largest value the payload's length prefix can hold rather than a
  statement about what the operation is for. 64 KiB is deliberately generous
  against real key material, so the ceiling is a contract rather than a limit a
  legitimate caller meets.

- **`saap::saap_prove` returns `Result<SaapProof, IdentityError>`** rather than
  `SaapProof`. See above.

- **`SecretSharer::reconstruct_secret` returns `Result<u64, IdentityError>`**
  rather than `u64`, so a non-interpolable point set is reported rather than
  absorbed. Native Rust callers only; the WIT surface already returned a
  `result`.

## [0.1.5] - 2026-08-31

### Fixed

- **`build.rs` no longer writes into the source tree by default.** The `dist/`
  convenience copy (WIT, ABI JSON, README, a best-effort WASM binary) was
  regenerated on every build, unconditionally, which is exactly what a build
  script must not do — it broke `cargo publish`'s verification (which
  rejects a source tree build.rs modified) and would have polluted another
  crate's extracted registry cache had anyone depended on this one. Set
  `AETHEL_GENERATE_DIST=1` to opt back into regenerating `dist/` locally;
  ordinary builds, `cargo publish`, and downstream dependents no longer touch
  it.

### Removed (breaking)

- **The `attestation` WIT interface** (`saap-prove`, `saap-verify`) is gone from
  the world. It built proofs over a public key that was never safe to publish
  (no error term, an exact linear image of the secret), so `saap-verify` could
  only ever return `ok(false)`. `identity.saap-verify-presentation`, anchored
  on the noisy PLP projection `b_τ = A_τ·s + e_τ`, is the sole supported SAAP
  verification path now. `src/saap.rs` remains in the crate for its
  characterisation tests only; it is not reachable through the WIT world.

  **Migration:** any caller using `attestation.saap-prove`/`saap-verify` must
  move to `identity.credential.issue`/`.present` and
  `identity.saap-verify-presentation`, which is the construction P3-11
  (0X3-79) actually built.

  **Deprecation-policy exception ([STABILITY.md](./STABILITY.md) §3):** this
  removal skips the usual mark-deprecated-for-one-minor-version cycle.
  `saap-verify` had exactly one behavior since it shipped — `ok(false)`,
  unconditionally — so no caller could have been relying on a *correct*
  result from it; a deprecation cycle would have kept a function whose only
  output was a guaranteed denial callable for another release, with no
  caller for whom that's useful and starting a fresh confusion clock for
  anyone new who found it. `saap-prove` disappearing alongside it is the
  same call: a prove half with no sound verify half isn't a usable API on
  its own. Ordinary removals still get the full cycle; this one is an
  explicit, reasoned exception, not a precedent for skipping it by default.

### Security

- **Strengthened randomness handling in PLP and SAAP.** The projection error term
  `e_τ` and the SAAP proof mask `r` are now seeded from caller-supplied fresh
  secret entropy, so each projection is a sound single-use M-LWE sample and each
  proof carries an independent mask, which is the property the soundness
  reduction assumes. Each context τ is used once, per the scheme's ephemeral
  design.

### Changed (breaking)

- `project_at_context`, `checked_project_at_context`, and `saap_prove` gain a
  trailing `randomness` argument. WIT `plp-project-at-context` and `saap-prove`
  gain `randomness: list<u8>`; the WASM exports fail closed on fewer than 32
  bytes; `checked_project_at_context` returns `InvalidInputLength` for short
  randomness. `plp-prove-identity` is unchanged.

  **Migration:** supply at least 32 bytes of fresh secret entropy at each call
  site, sampled anew per call. Never reuse a value or derive it from public
  data, and use each context τ once.

## [0.1.0] - 2026-08-27

### Added

- Initial release of three post-quantum identity primitives: Polymorphic Lattice Projection
  (PLP) — context-bound ephemeral identity projection and ZK ownership proof over Module-LWE;
  Selective Attribute Attestation Protocol (SAAP) — BDLOP vector commitment with
  zero-knowledge selective disclosure; and 5D Hypercube Threshold Secret Sharing (HTSS) —
  Shamir 3-of-5 secret sharing routed over a Q_5 hypercube graph.
- WASM bindings (`wasm` feature) exporting `plp_*`, `saap_*_wasm`, and `htss_*`.
- 31 `--lib` unit tests, 15 `tests/plp_tests.rs` integration tests, and 1 doctest passing on
  default features. CI proves offline generation by running it inside a network-isolated
  namespace with a negative control, rather than by in-process assertion alone.
- `puf` (SRAM PUF fuzzy extraction, research code) and `enclave` (C FFI shim) are non-default
  feature flags, out of scope for the default build and the `aethel:core` WIT world.

> **Pre-release.** This is a research implementation; do not use in production without a
> formal security audit — see the notice in [README.md](README.md).

See [README.md](README.md) for full module, feature, and security documentation.
