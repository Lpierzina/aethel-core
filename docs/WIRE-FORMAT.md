---
title: "aethel-plp-1 — Wire Format Specification"
version: "1.0.0"
date: "2026-09-10"
project: "aethel-core"
---

# `aethel-plp-1` Wire Format

> Gap this closes (SAGP-PG-001 A-4, verbatim): "No official verify crate API that
> sagp-host can call without pulling sampling internals — Host copies structs — Public:
> verify_projection(bytes, proof, context) + stable wire codec versioned aethel-plp-1"

This is a normative description of the `aethel-plp-1` wire codec, so a third-party SDK
(TypeScript, Go, or otherwise) can implement an encoder/decoder without reading Rust. The
Rust reference implementation is [`src/wire.rs`](../src/wire.rs), built on the raw struct
codecs in [`src/plp.rs`](../src/plp.rs) (`EphemeralProjection::{to_bytes,from_bytes}`,
`ZkIdentityProof::{to_bytes,from_bytes}`).

## Envelope

Every `aethel-plp-1` value — a projection or a proof — is wrapped in the same 10-byte
header:

```text
offset  size  field
0       4     magic       = 0x41 0x54 0x48 0x31  ("ATH1", crate::EIAB_MAGIC)
4       1     version     = 0x01                 (WIRE_VERSION_PLP1)
5       1     kind        = 0x01 (projection) | 0x02 (proof)
6       4     body_len    u32, little-endian, in bytes
10      ..    body        exactly body_len bytes
```

A decoder MUST reject:

- fewer than 10 bytes total (cannot contain a header) — native error: `WireLengthMismatch`
- `magic != "ATH1"` — native error: `WireBadMagic`
- `version != 1` — native error: `WireBadVersion`
- `kind` not matching the decoder being invoked (a projection decoder given `kind = 0x02`,
  or vice versa) — native error: `SerializationError`
- `body.len() != body_len` — native error: `WireLengthMismatch`

None of these four failure causes has a producer in the `aethel:core` WIT world's
`identity-error` variant (see [`identity_error.rs`](../src/identity_error.rs)); they
collapse to `serialization-error` at that boundary. A native Rust caller sees them as
distinct `IdentityError` variants.

## Projection body (`kind = 0x01`)

Exactly `64 + MODULE_K * N * 4` bytes, where `MODULE_K = 4` and `N = 256` (so
`64 + 4*256*4 = 4160` bytes for the shipped LEVEL1 parameter set):

```text
offset          size            field
0               32              tau     (context tag, padded/truncated to 32 bytes)
32              32              salt    (per-projection salt)
64              MODULE_K*N*4    public_b  (MODULE_K polynomials of N u32 coefficients, LE, component-major then coefficient-major)
```

`public_b` is `MODULE_K` polynomials laid out back-to-back; within each polynomial, `N`
coefficients as 4-byte little-endian `u32` values. Decode-then-validate: every coefficient
MUST be `< Q` (`Q = 8_380_417`), checked before any arithmetic touches it — native error on
violation: `CoefficientOutOfRange`. Note that the context matrix `A` is **not** carried on
the wire; a decoder derives it from `(tau, salt)` (`derive_context_matrix`), so an
inconsistent `A` is unrepresentable rather than merely detectable.

## Proof body (`kind = 0x02`)

Exactly `(MODULE_K*N + N + MODULE_K*N) * 4` bytes (`9216` bytes for LEVEL1):

```text
offset                      size            field
0                           MODULE_K*N*4    commitment_w  (MODULE_K polynomials, same layout as public_b)
MODULE_K*N*4                N*4             challenge_c   (1 polynomial, N u32 coefficients, LE)
MODULE_K*N*4 + N*4          MODULE_K*N*4    response_z    (MODULE_K polynomials)
```

Decode-then-validate, in order:

1. Exact length as above.
2. Every coefficient of `commitment_w`, `challenge_c` and `response_z` MUST be `< Q`.
3. `challenge_c` MUST be **ternary**: every non-zero coefficient MUST be exactly `1` or
   `Q - 1` (i.e. `-1 mod Q`), and there MUST be **exactly** `CHALLENGE_WEIGHT` (`39`) of
   them. A proof carrying any other shape did not come from an honest prover
   (`hash_to_challenge` never produces anything else) and is rejected before it reaches
   the verification equation.

All three checks are on public proof data, not secret material, so a variable-time
implementation leaks nothing.

## `verify_projection(projection, proof, context) -> Result<bool, Error>`

```text
1. proj := decode_projection(projection)   // Err on any envelope/body failure above
2. zk   := decode_proof(proof)             // likewise
3. if proj.tau != pad_tau(context): return Ok(false)
4. return Ok(Verifier::verify(proj, zk))
```

`pad_tau(context)` truncates/right-pads `context` to exactly 32 bytes with zero bytes —
the same padding every projection's `tau` field already carries. This is the "purpose
context on attach" binding: a projection built for one context does not verify against
another, even when the proof itself is honest.

**Verdict vs failure**, the crate's established rule: `Ok(false)` is a verdict — a
well-formed pair that either does not verify, or was not made for `context`. `Err` means
the input could not be decoded at all. A caller must not conflate the two.

## Worked vector

See [`tests/vectors/aethel-plp-1/valid-1.txt`](../tests/vectors/aethel-plp-1/valid-1.txt)
for a complete, checked-in example: hex-encoded `projection`, `proof`, `context`, and the
expected boolean `verify_projection` result. That directory also carries
`tampered-projection.txt`, `tampered-proof.txt` and `wrong-context.txt` — the same honest
pair with one input corrupted, each expecting `false`. All vectors are generated
deterministically from fixed seeds (see `tests/plp_vectors.rs`'s `regenerate_vectors`); do
not hand-edit them.

Both this crate's native tests (`tests/plp_vectors.rs`) and its WASM component
(`tests/component_execution.rs`, via the additive `plp-verify-bytes` WIT export) load and
verify the identical files — the "same files, two runtimes" half of A-5/X-3/X-4.

## Versioning

`aethel-plp-1`'s raw layout has already changed once (module rank 1 → 4, before this
envelope existed), which is exactly the failure mode the version byte exists to turn into
a clean rejection instead of a silent misparse. A future `aethel-plp-2` would introduce a
new `WIRE_VERSION_PLP2` constant and a decoder that dispatches on it; `WIRE_VERSION_PLP1`
and its decoder are not removed, so old bytes remain decodable by a build that still
carries both.
