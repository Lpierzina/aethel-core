# Deviation register

Every place where this crate and its public specifications disagree, with the ruling and who
owns it.

The specifications in play:

- **SAAP-SPEC**: [`docs/SAAP-SPEC.md`](./SAAP-SPEC.md), the public distillation of the RFC's
  credential sections, kept in this repository.
- **RFC**: `AETHEL-SPEC-001`, the standards-track draft SAAP-SPEC is distilled from. It lives in
  a private working repository and is cited here by section number where a row concerns both.
  Disagreements that concern only the RFC's own text are tracked alongside the RFC until its
  correction lands, because a reader of this repository cannot check them.

**How to read a row.** *Code wins* means the crate is right and the specification is to be
amended. *Spec wins* means the crate is to change. *Neither* means both are wrong today and the
fix starts with the specification. A row is **Open** until whatever is wrong has been changed,
and **Closed** when nothing further is to happen, including when the answer was deliberately
"no action". Row IDs are never reused, so the numbering has gaps.

**Keeping it current.** A change that makes the crate deviate from a specification adds its row
in the same pull request. See [`CONTRIBUTING.md`](../CONTRIBUTING.md). `tests/deviations.rs`
checks that the register stays linked and that any deviation explained in a source comment
points here.

Owner for every row is the maintainer, Ed Johnson, unless the row names someone else. Tracker
IDs are the project's internal issue numbers.

## Open

| ID | Topic | Specification says | Crate does | Ruling | Status |
|---|---|---|---|---|---|
| D-01 | Credential commitment shape | SAAP-SPEC §2.2 and RFC §5.2.2 specify a commitment whose randomness dimension is smaller than its commitment dimension, and describe it as hiding | Implements that shape exactly (`CRED_T`, `CRED_L`) | **Neither.** A BDLOP commitment hides only when its randomness dimension exceeds its commitment dimension, so the specified shape does not hide. Treat a presentation as revealing every attribute it commits to, disclosed or not. The specification is corrected first, then the crate follows. See [`SECURITY.md`](../SECURITY.md) | Open. 0X3-160, 0X3-157 |
| D-03 | Parameter profiles | SAAP-SPEC §3.1 and RFC §3.2: LEVEL1, LEVEL3 and LEVEL5 | LEVEL1 only | **Code wins for what ships.** LEVEL3 and LEVEL5 are unbuilt proposals. The corrected specification replaces rank-based profiles with attribute capacity as the parameter axis | Open. 0X3-160 |
| D-04 | Issuer signature | SAAP-SPEC §4.1 and RFC §5.4: the issuer signs `t_cred` with ML-DSA | No issuer signature is produced or checked. Disclosed attributes are self-asserted | **Spec describes the target; code describes today.** An ML-DSA signature over the commitment would not help a verifier on its own. [`ISSUER-AUTHENTICATION.md`](./ISSUER-AUTHENTICATION.md) gives the construction that would | Open. 0X3-142, 0X3-97 |
| D-08 | SAAP verifier equation | The sketch in SAAP-SPEC §7, from RFC §5.7: the verifier computes `W_2' = A_τ·z_s − c·b_τ` and expects the prover's `W_2` | Adds the projection error `e_τ` to the witness (`y_e`, `z_e`), so `A_τ·z_s + z_e − c·b_τ = W_2` holds exactly | **Code wins.** The sketched equation leaves a residual `−c·e_τ` that a Fiat-Shamir verifier cannot tolerate. Explained at the point of use in `src/credential.rs` and in SAAP-SPEC §6.1, which §7 now points to | Open for the RFC text only. 0X3-150 |
| D-09 | Attribute masks | The sketch in SAAP-SPEC §7 step 1, from RFC §5.5: every response is norm-checked, `z_m` included | Attribute masks are uniform over `R_q` and not norm-checked; slot 0 shares the short mask `y_s` | **Code wins.** Attribute values are not short, so a short mask would not hide them. See SAAP-SPEC §6.2 | Open for the RFC text only. 0X3-150 |
| D-13 | Retired `saap.rs` pathway | SAAP-SPEC §10.3 and §10.4 describe a single-response prove and verify | That pathway is crate-internal and was removed from the WIT world in 0.1.5. Its challenge also does not absorb the public key it verifies against | **Neither needs it.** SAAP-SPEC labels §10.3 and §10.4 as not implemented. The dormant challenge gap is to be deleted or fixed | Open. 0X3-110 |

## Closed

| ID | Topic | Specification says | Crate does | Ruling | Why no further action |
|---|---|---|---|---|---|
| R-01 | Predicate proofs | SAAP-SPEC §9.3 and RFC §5.6 relation 3: range and membership proofs over hidden attributes | Not implemented, and no function claims to evaluate a predicate | **Code wins.** Closed with no action | It cannot be built in this protocol: bit-decomposition needs a quadratic constraint that a linear sigma protocol cannot express. See [`PREDICATE-PROOFS.md`](./PREDICATE-PROOFS.md). The planned alternative is issuer-attested flags. Do not reopen without a different proof system |
| R-02 | WASM memory bounds | SAAP-SPEC §12 and RFC §6: a 64-page cap, a fixed arena allocator, a static segment map, binary and stack ceilings | None of it | **Spec is aspirational.** Closed with no action | Nothing in the build is an enclave target, so the bounds describe hardware this crate does not build for. This has been reopened twice by readers who took §12 as a requirement. Reopen only if an enclave target is actually built |
| R-03 | HelixDB storage | SAAP-SPEC §13.3 and §14.2: graph-manifold storage properties | No storage at all | **Out of scope.** Closed with no action | The identity component is stateless by design. HelixDB is not part of `aethel-core` and is not planned for it |
| R-04 | SRAM PUF and enclave binding | RFC §4, §11 and §12 treat them as normative | Non-default `puf` and `enclave` features, research code, absent from the WIT world | **Demoted.** Closed with no action in the crate | Decided 2026-08-31: the PUF stays in the RFC as a future capability, not a normative requirement. Hardware binding cannot shape an interface every language embeds. See [`SRAM-PUF.md`](./SRAM-PUF.md) |
| R-05 | Module rank | SAAP-SPEC §3.1 and RFC §3.2 set `k = 4`, and RFC §9.2 forbids going below it | Ran at `k = 1` until 0.5.0; runs at `k = 4` since | **Spec won.** Closed by a code change in 0.5.0 (0X3-146) | Nothing left to do in the crate. Whether `k = 4` at this modulus is enough is a separate question, pending a lattice estimator run (0X3-145) |
