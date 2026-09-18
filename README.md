# aethel-core — Post-Quantum Ephemeral Identity Engine

[![WASM](https://img.shields.io/badge/target-wasm32--unknown--unknown-green)](https://webassembly.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](#license)

> ⚠️ **Security Notice**: This is a pre-release implementation. Do not use in production without a formal security audit.

## PLP in one paragraph

An agent holds one [`signing::Identity`](src/signing.rs) (sealed at rest, never persisted
in the clear). To present to a verifier: derive a one-time PLP projection for the
verifier's context, prove ownership of it, sign the verifier's attach challenge under a
purpose-separated context (`docs/PURPOSES.md`), and hand over bytes —
[`wire::encode_projection`](src/wire.rs)/[`encode_proof`](src/wire.rs) output. The verifier
holds no secret at all: it calls [`wire::verify_projection`](src/wire.rs) and
`verify_with_purpose` on nothing but those bytes. See
[`examples/present_to_verifier.rs`](examples/present_to_verifier.rs) for the whole flow in
under 40 lines, and run it with `cargo run --example present_to_verifier`.

`aethel-core` is a `no_std`-compatible Rust library
implementing three post-quantum identity primitives, compiled natively or to
`wasm32-unknown-unknown`:

- **Polymorphic Lattice Projection (PLP)** — context-bound ephemeral identity projection and
  ZK ownership proof over Module-LWE (M-LWE).
- **Selective Attribute Attestation Protocol (SAAP)** — BDLOP vector commitment with
  selective disclosure and norm-bound verification. The commitment does not currently
  provide the hiding property the design calls for; see
  [`SECURITY.md`](./SECURITY.md#known-limitations) before relying on undisclosed
  attributes staying undisclosed.
- **Threshold secret sharing (Shamir 3-of-5) for identity backup** — a ritual the agent's
  principal or an operator runs over a sealed identity's key material, routed (as a local
  model, not a running network) over a Q_5 hypercube graph (32 nodes, 80 edges). This is
  **not** a hosted service — 8gentz does not run the 32-node cube; see
  [`docs/HTSS-TOPOLOGY.md`](docs/HTSS-TOPOLOGY.md#who-runs-htss-a-3).

## What runs today vs. what is designed

**Runs today** (covered by `cargo test`: 27 `--lib` unit tests + 18 `tests/plp_tests.rs`
integration tests + 1 doctest, all passing on default features):

- `plp` — key derivation (`MasterIdentity::from_seed`), context projection
  (`project_at_context`), ZK proof generation and verification (`Prover`, `Verifier`)
- `credential` — BDLOP credential issuance and blinding (`Credential::issue`,
  `BlindedCredential::new`) and the linked selective-disclosure proof (`credential::prove`,
  exported as `saap-verify-presentation`). **The commitment does not hide**: see `SECURITY.md`
  and `docs/DEVIATIONS.md` D-01
- `saap` — crate-internal primitives the credential module builds on. The single-response
  `saap_prove`/`verify_saap_proof` pathway was retired from the WIT world in 0.1.5 (D-13)
- `htss` — 3-of-5 threshold secret splitting and reconstruction, hypercube routing
- `sampling` — constant-time rejection sampling, CBD η=2 sampler, norm checking
- `ct_verify` — a Valgrind/ctgrind constant-time verification harness (doctest-covered)
- `identity_error` — the Rust-side mirror of the WIT world's `identity-error` variant, plus
  checked wrappers (`*_checked` functions) that return it instead of panicking
- `component` — the WebAssembly Component Model adapter implementing the `aethel:core` WIT
  world; the single WASM artifact every language binding embeds

**Designed, not yet implemented / out of scope for this crate:**

- **SRAM PUF fuzzy extraction** (`puf` module, non-default `puf` feature) — a BCH(1023,512,55)
  fuzzy extractor for deriving key material from noisy hardware SRAM. This is research code:
  its BCH encoder is a simplified placeholder (see the comments in `src/puf.rs`), it is not
  part of the default build, and it does not appear in the `aethel:core` WIT world. Enabling
  `--features puf` compiles it; the default build does not, and no exported operation reaches
  it.
- **`enclave` feature** — gates a set of `extern "C"` FFI declarations (`src/puf.rs`'s `ffi`
  module) into a C enclave shim (`c/bch_decoder.c`, `c/ct_norm.c`, `c/ct_sampling.c`) that this
  repo does not build a real target for; `c/ct_sampling.c` calls C functions declared nowhere
  in this repo. Nothing in the working code path (`plp`, `saap`, `htss`, `sampling`, `puf`
  without `enclave`) calls into it.
- **`aethel-runtime`** and the substrate repos (`pqvm`, `waven`, `wamr`, `awre`, `qies`,
  `obfuscation`) — separate repositories this crate does not depend on, build, or test.
  Nothing in this repo implies they ship alongside it.

## Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Ring | `R_q = Z_q[X]/(X^256 + 1)` |
| Modulus `q` | `8,380,417` |
| Module rank `k` | 4 (`plp::MODULE_K`) |
| Noise `η` | 2 (Centered Binomial Distribution) |
| Masking bound `γ₁` | 131,072 (2^17) |
| Challenge weight | 39 non-zero coefficients in `{±1}` (`plp::CHALLENGE_WEIGHT`) |
| Rejection bound `β` | 78, which is `39 × 2` and is checked against the challenge weight at compile time |
| Rejection ceiling | 48 for an identity proof, 192 for a credential presentation |
| PLP matrix domain separator | `"AETHEL_PLP_CTX_V3"` |
| PLP challenge domain separator | `"AETHEL_PLP_CHALLENGE_V4"` |
| SAAP challenge domain separator | `"AETHEL_SAAP_CHALLENGE_V3"` |

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| `plp` | Polymorphic Lattice Projection — context-bound ephemeral identity projection over M-LWE | Default |
| `signing` | Identity key generation, purpose-separated signing (`sign_with_purpose`/`verify_with_purpose`), and the native `Identity` → PLP projection/proof bridge | Default |
| `wire` | `aethel-plp-1` versioned wire envelope + `verify_projection(bytes, bytes, bytes) -> Result<bool, _>` | Default |
| `saap` | Selective Attribute Attestation Protocol — BDLOP commitment + ZK selective disclosure | Default |
| `credential` | Issuer-authenticated credential issuance/presentation, superseding `saap`'s public surface | Default |
| `htss` | Threshold secret sharing (Shamir 3-of-5) for identity backup, modeled over a Q_5 routing graph — a principal/operator ritual, not a hosted service | Default |
| `sampling` | Constant-time rejection sampling — 16-iteration fixed loop, CMOV, zeroization | Default |
| `ct_verify` | Constant-time verification harness | Default |
| `identity_error` | Mirror of the WIT `identity-error` variant, plus checked wrappers | Default |
| `puf` | SRAM PUF fuzzy extractor — BCH(1023,512,55) over GF(2^10), research code | Non-default (`puf` feature) |

### Which type do I hold? (X-2)

| Role | Type | Notes |
|---|---|---|
| **Agent** | one [`signing::Identity`](src/signing.rs) | Sealed at rest (`export_sealed`/`import_sealed`). Holds an ML-DSA-65 keypair and a PLP master seed together. |
| **Verifier** | nothing — bytes only | Calls `verify`/`verify_with_purpose`/`wire::verify_projection`. No secret of any kind. |
| **Internal derivation** | [`plp::MasterIdentity`](src/plp.rs) | Derived from an `Identity`'s seed on demand; prefer `Identity` in application code. |
| **aethel-vault** (separate crate) | a settlement signer key, and — `fhe-state` mode only — a TFHE key pair | Neither leaves the agent; consumes this crate for identity, purpose bytes, and `verify_projection`. |

See [`docs/PURPOSES.md`](docs/PURPOSES.md) for the full purpose-bytes registry
(`signing::purpose`) and the domain-separation rule it enforces, and
[`docs/WIRE-FORMAT.md`](docs/WIRE-FORMAT.md) for the `aethel-plp-1` wire codec.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | ✅ Yes | Standard library support, heap allocation. |
| `component` | ❌ No | Builds the WebAssembly Component Model adapter implementing the `aethel:core` WIT world. The one WASM artifact; see [The WASM Component](#the-wasm-component-l1-boundary). |
| `enclave` | ❌ No | Compiles the C enclave FFI shim (see [What runs today vs. what is designed](#what-runs-today-vs-what-is-designed)). Not buildable against a real enclave target in this repo. |
| `puf` | ❌ No | Compiles the `puf` module (SRAM PUF fuzzy extraction). Research only, and not reachable through the `aethel:core` WIT world. |

## WASM Exports

```wit
package aethel:core@0.1.0;

world aethel-core {
  export identity;       // plp-*, master-identity, credential, saap-verify-presentation
  export secret-sharing; // htss-split, htss-reconstruct
}
```

See [`wit/aethel-core.wit`](wit/aethel-core.wit) for the full WIT interface definition. It is
checked in and authoritative: bindings are generated from it, so the declared world and the
compiled artifact cannot drift apart the way they did before P3-10.

## The WASM Component (L1 boundary)

`aethel-core` builds as a **WebAssembly Component Model component** implementing the
`aethel:core` world declared in [`wit/aethel-core.wit`](wit/aethel-core.wit). This is the
artifact every language binding embeds — one shared component, never per-language crypto.

```bash
cargo build --release --target wasm32-unknown-unknown   --no-default-features --features component
wasm-tools component new   target/wasm32-unknown-unknown/release/aethel_core.wasm   -o aethel_core.component.wasm
```

Verify what you built exposes the declared world:

```bash
wasm-tools validate aethel_core.component.wasm
wasm-tools component wit aethel_core.component.wasm
```

And that it actually runs — loading it in `wasmtime` and checking every operation
against the native implementation:

```bash
cargo test --features component-tests --test component_execution
```

Those are different claims. Validating proves the artifact is well-formed; only the
execution proof shows the component and the native API compute the same answers, which is
what "one artifact embedded by every language" has to mean.

### Reproducing the published artifact

Two builds of the same source commit produce byte-identical output. The expected hash is
checked into [`component.sha256`](component.sha256) and enforced in CI, so you do not have to
take our word for what the binary contains:

```bash
sha256sum aethel_core.component.wasm
cat component.sha256
```

**The canonical build platform is CI**, and the hash in `component.sha256` is the one produced
there: `ubuntu-latest`, Rust 1.97.0, wasm-tools 1.258.0, as pinned in
`.github/workflows/component.yml`. Reproduce it on that platform and you get the same bytes;
CI proves this on every push by building twice from a clean target directory and comparing.

Building on a different OS will produce a **different hash** — this is not a
platform-independent guarantee, and we would rather say so than let you discover it. A
Windows build of this exact commit differs from the Linux one, because Rust embeds
platform-specific paths and links a different `std`. If your hash does not match and you are
not on the canonical platform, that is expected; if it does not match and you *are*, the
artifact was not built from this source.

### Component status per operation

| Operation | Status |
|---|---|
| `plp-project-at-context` | Implemented |
| `plp-prove-identity` | Implemented |
| `plp-verify` | Implemented |
| `plp-verify-bytes` | Implemented (A-4 — verify from `aethel-plp-1` wire bytes, binding the verifier's own context) |
| `encode-projection` | Implemented (A-4 — typed record to `aethel-plp-1` bytes) |
| `encode-proof` | Implemented (A-4) |
| `saap-verify-presentation` | Implemented |
| `issuer-public-parameters` | Implemented |
| `verify-signature` | Implemented |
| `htss-split` | Implemented (fixed internal nonce, see `src/component.rs`) |
| `htss-reconstruct` | Implemented |

Selective disclosure runs through the `credential` resource (`issue` / `present`) and
`saap-verify-presentation`, anchored on the PLP projection `b_τ = A_τ·s + e_τ`, whose noise is
what makes it publishable. Issuing and verifying take opposite halves of the issuer's key
pair: `issue` takes the issuer seed, `saap-verify-presentation` takes the
`issuer-public-parameters` derived from it, so a verifier holds no secret and issuer and
verifier can be separate parties. What those parameters do and do not vouch for is stated on
the type in the WIT, and at length in [`docs/ISSUER-AUTHENTICATION.md`](docs/ISSUER-AUTHENTICATION.md). An earlier `attestation` interface exported a narrower
`saap-prove` / `saap-verify` pair whose verify half could only ever deny — it needed a public
key `t = A_τ·sk` that its signature could not carry and that, having no error term, was an
exact linear image of the secret. That interface was removed in 0.1.5 rather than kept as a
surface that could never succeed.

This is the only WebAssembly artifact. The `wasm-bindgen` core module that used to sit
alongside it was retired in 0.1.5: two surfaces contradicted the one-artifact rule, and the
untyped one signalled failure with sentinel values instead of `result<T, identity-error>`.

## Target matrix (X-3)

| Role | Target | Artifact | Status |
|---|---|---|---|
| sagp-host / native verifier | native rlib, `x86_64`/`aarch64` | `aethel-core` crate, `wire::verify_projection` | Supported, tested (`cargo test`) |
| Agent SDK | `wasm32-unknown-unknown` component | `aethel_core.component.wasm` (`--features component`) | Supported, tested (`cargo test --features component-tests`) |
| Inner worker | `wasm32-wasip2` | — | Not built today. The `wasm32-wasip2` Rust target exists and this crate's default-feature code builds under it, but no CI job or shipped artifact targets it; treat as "to decide" per the gap-remediation plan, not as a supported target. |

Add `aethel-vault` to the ["Shared WASM Modules"](#shared-wasm-modules) table below: it
consumes this crate for identity, purpose bytes, and `verify_projection`, and is a
*research* module in the same sense the others there are — see that crate's own README for
its target matrix and production/research status.

## Building

### Prerequisites
- Rust 1.85+ (`rustup target add wasm32-unknown-unknown` for WASM builds)

### Native Build + Tests

```bash
cargo build
cargo test
```

### WASM Build

The WebAssembly build is the component; see
[The WASM Component (L1 boundary)](#the-wasm-component-l1-boundary) for the full recipe.

```bash
cargo build --release --target wasm32-unknown-unknown --no-default-features --features component
```

### With the `puf` Feature

```bash
cargo build --features puf
cargo test --features puf
```

## Integration Example (Rust)

The full "load an identity, present to a verifier, verify from bytes" flow lives in
[`examples/present_to_verifier.rs`](examples/present_to_verifier.rs) (run with
`cargo run --example present_to_verifier`) — see [PLP in one paragraph](#plp-in-one-paragraph)
above. The lower-level struct API it is built on:

```rust
use aethel_core::plp::{MasterIdentity, Prover, Verifier};

// Derive a master identity from a 32-byte seed (caller-supplied entropy)
let seed = [0x11u8; 32];
let identity = MasterIdentity::from_seed(&seed);

// Project at context τ (context-bound).
// `randomness` MUST be at least 32 bytes of fresh, secret entropy, sampled anew
// per projection. It does two jobs: it seeds the error term that makes the
// projection an M-LWE sample rather than an exact linear image of the secret,
// and it salts the context matrix A so two projections at one τ are independent
// samples. Reusing τ is safe; reusing `randomness` is what is not.
let tau = b"session_context_2026";
let randomness = [0x22u8; 32]; // demo value; sample fresh in real use
let projection = identity.project_at_context(tau, &randomness);

// Prove ownership. The proof is computed against the projection, so it is
// bound to that projection's A.
let proof = Prover::prove_identity(&identity, &projection, &seed)
    .expect("honest parameters");

// Verify (by any party with the projection and proof)
assert!(Verifier::verify(&projection, &proof));
```

Most application code should prefer [`signing::Identity`](src/signing.rs)'s
`project_at_context`/`prove` over calling `plp::MasterIdentity` directly — see
["Which type do I hold?"](#which-type-do-i-hold-x-2).

## Security Properties

- **Post-quantum secure**: Based on Module Learning With Errors (M-LWE), conjectured secure against quantum adversaries
- **Ephemeral identifiers**: Each context `τ` produces a mathematically independent projection — no linkability across contexts
- **Constant-time**: All secret-dependent operations use fixed-iteration loops and CMOV selection
- **No traditional crypto**: Zero AES, RSA, ECDSA, or classical elliptic curve operations
- **PLP is an identity, not an address. Spend rails stay `eip155`.** A PLP projection is
  never encoded as, hashed into, or substituted for a Base address; USDC settlement is a
  separate dialect this crate has no notion of. See
  [`docs/PLP-ALGORITHM.md` §9](docs/PLP-ALGORITHM.md#9-plp-vs-didpkheip155--two-dialects-not-two-competitors-a-2).
- **A key signs under one purpose only.** `signing::Identity::sign_with_purpose`/`verify_with_purpose`
  use FIPS 204's native context mechanism, so a signature made for one purpose (attach
  challenge, receipt, HITL approval, ...) provably does not verify under another. See
  [`docs/PURPOSES.md`](docs/PURPOSES.md).
- **Offline generation**: Identity generation (`plp` key derivation, context projection, proof generation — the `--lib` unit tests plus `tests/plp_tests.rs`) never requires network access, and this is proven by denying the capability at the boundary rather than by trusting application code to report it honestly. CI's `offline-generation` job (`.github/workflows/ci.yml`) runs that generation test suite inside a network namespace with no interface, and in the same isolated step runs a negative-control test (`tests/network_isolation_negative_control.rs`) that deliberately makes a real network call — that control is *expected to fail* there, and its failure is what proves the isolation is real. If you don't trust this claim, don't take it on faith: read `offline-generation` in the Actions tab, or reproduce it locally (Linux/WSL2) with `unshare --net --map-root-user -- cargo test --offline --lib --test plp_tests`.

## Unsafe Code

The default build (`std`, no `puf`, no `enclave`) contains exactly 5 `unsafe` blocks, all in
[`src/sampling.rs`](src/sampling.rs) (lines ~98, ~167, ~173, ~179, ~408 at time of writing),
each carrying a `// SAFETY:` comment above it explaining the invariant it relies on:

- Two `enclave_explicit_zeroize` / `PolyRq::zeroize` blocks use `core::ptr::write_volatile` in
  a loop over a pointer derived from a live `&mut` reference, sized to `size_of::<T>()`,
  followed by a `compiler_fence` — this is what makes secret zeroization survive dead-store
  elimination.
- Three blocks in `enclave_plp_prove_fixed_time` reinterpret same-sized, non-aliasing local
  `PlpProof` values as byte slices (`core::slice::from_raw_parts[_mut]`) to run a
  constant-time conditional copy (`ct_cond_copy`) without branching on secret data.

Enabling `puf` or `enclave` additionally compiles 2 more `unsafe` blocks, in `src/puf.rs`'s
`ffi` module — a wrapper around the C enclave shim described in
[What runs today vs. what is designed](#what-runs-today-vs-what-is-designed).

## Shared WASM Modules

aethel-core is one of several independently-versioned repositories intended to run alongside
each other as WASM modules loaded by a wasmer.io host. These are separate repos with their own
build and test suites — this README makes no claims about their state:

| Module | Purpose | Relationship to aethel-core | Production / research |
|--------|---------|---|---|
| `pqc-kem` | ML-KEM (FIPS 203) key encapsulation | Sibling module, not a dependency | Research |
| `pqc-sig` | ML-DSA (FIPS 204) signatures | **Direct dependency** — `signing::Identity` is built on `pqc_sig::MlDsa65Keypair` | Research |
| `privacy` | ε-Differential Privacy noise injection | Sibling module, not a dependency | Research |
| `obfuscation` | WASM binary hardening | Sibling module, not a dependency | Research |
| `aethel-vault` (repo `aethel-runtime`) | Agent-held wallet: settlement signing, spend policy, receipts | **Consumes this crate** — identity, `signing::purpose` constants, `wire::verify_projection` | Research; see that crate's own README for its target matrix and custody rules |

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on
a fresh GitHub-hosted runner.

Three jobs:

- **Build & test** — `cargo build --all-targets` / `cargo test` with default features.
- **Offline generation (network-isolated)** — re-runs the identity-generation test suite inside
  a real network namespace with no interface configured, proving generation works with zero
  network access rather than just asserting it in-process. A negative control in the same job
  confirms the isolation itself is real: a test that tries to make a network call is expected
  to fail under isolation, and the job fails loudly if it doesn't.
- **WASM test (Node)** — runs the test suite under `wasm32-unknown-unknown` via `wasm-pack test
  --node`. This is what actually exercises the zeroization test in WASM linear memory rather
  than only on native — memory that isn't returned to an OS on drop the way native heap memory
  is. The job also greps for that test by name, because a run that silently skipped it would
  otherwise still be green.

## Further Documentation

[`docs/`](./docs/) has deeper algorithm write-ups: [`PLP-ALGORITHM.md`](./docs/PLP-ALGORITHM.md)
(§9 covers PLP vs `did:pkh:eip155`), [`SAAP-SPEC.md`](./docs/SAAP-SPEC.md),
[`HTSS-TOPOLOGY.md`](./docs/HTSS-TOPOLOGY.md) ("Who runs HTSS" section),
[`SRAM-PUF.md`](./docs/SRAM-PUF.md), [`OVERVIEW.md`](./docs/OVERVIEW.md),
[`PURPOSES.md`](./docs/PURPOSES.md) (the purpose-bytes registry, A-1/X-2), and
[`WIRE-FORMAT.md`](./docs/WIRE-FORMAT.md) (the normative `aethel-plp-1` wire codec, A-4).
Each of the pre-existing files was reviewed against this README (P3-05, 2026-08-26) and
carries inline markers wherever it describes a credential-issuance layer, hardware target,
or parameter level that isn't actually shipped — read the editorial note at the top of each
file first.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Maintainer and Support

Ed Johnson is the named maintainer. This is a best-effort, single-maintainer project — see
[`STABILITY.md`](./STABILITY.md) for the release cadence and support posture, and
[`SECURITY.md`](./SECURITY.md) to report a vulnerability.

## License

Apache-2.0.

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
