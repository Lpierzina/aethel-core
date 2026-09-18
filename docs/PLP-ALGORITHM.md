---
title: "Polymorphic Lattice Projection (PLP) — Full Algorithm Specification"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-core"
---

# Polymorphic Lattice Projection (PLP) — Algorithm Deep Dive

> **P3-05 (2026-08-26) editorial note.** Sections 1–6 and 9 describe the core PLP algorithm
> and match the shipped implementation (`src/plp.rs`) closely, with one correction: §3.1's
> `KeyGen` describes deriving the seed from an SRAM PUF — the real `MasterIdentity::from_seed`
> takes a caller-supplied 32-byte seed and has no PUF dependency; PUF-based derivation is a
> non-default, research-only feature (see `aethel-core`'s README). §6.5/6.6's "enclave"
> pseudocode matches the real, shipped `sampling.rs` algorithm (in Rust) but isn't literally
> hardware-enclave-executed anywhere in this repo. §7 (hybrid cross-primitive extension) is an
> unbuilt design idea, kept with a marker. §8 (5D Toric Manifold Connection) has been removed
> entirely — it's fictional quantum error-correction math with no relationship to anything
> built or planned here, same finding as `docs/HTSS-TOPOLOGY.md`.

## 1. Introduction

To tear down static DIDs, we construct a mathematical primitive that replaces the static identifier with a **Polymorphic Lattice Projection (PLP)**.

In this system:

1. The user holds a secret polynomial vector **s ∈ R_q^k** over a cyclotomic ring **R_q = Z_q[X]/(X^N + 1)**.
2. Instead of publishing a fixed public key **b = As + e**, the system continuously mutates the public projection based on an execution context or block height parameter **τ**.
3. The verifier receives a single-use public matrix **A_τ** and output **b_τ**.
4. Under Module Learning-With-Errors (M-LWE), **b_τ** is computationally indistinguishable from uniform random noise to an observer.
5. The prover uses a Sigma-protocol (or ZK-STARK over post-quantum hashes like Poseidon2/Monolith) with rejection sampling to prove knowledge of **s** without leaking the short norm bound **∥s∥_∞ ≤ β**.

---

## 2. Mathematical Definitions and Parameters

### 2.1 Algebraic Structures

**Cyclotomic Ring (R_q):**
```
R_q = Z_q[X]/(X^N + 1)
```
where:
- **N = 256** (polynomial degree, power-of-two)
- **q = 8,380,417** (prime modulus, q ≡ 1 mod 512 for NTT compatibility)

**Module Space:**
```
R_q^k  (k-dimensional module over R_q)
```

**Infinity Norm:**
```
∥a∥_∞ = max_{0 ≤ i < N} |centered(a_i)|
```
where `centered(a_i)` maps coefficients to the range `[-(q-1)/2, (q-1)/2]`.

### 2.2 Parameter Sets

> Only LEVEL1 is implemented; LEVEL3/LEVEL5 are unbuilt proposals.

| Parameter | Notation | LEVEL1 | LEVEL3 | LEVEL5 |
|-----------|----------|--------|--------|--------|
| Ring Degree | N | 256 | 256 | 256 |
| Prime Modulus | q | 8,380,417 | 8,380,417 | 8,380,417 |
| Module Rank | k | 4 | 6 | 8 |
| Noise Distribution | χ_η | CBD(η=2) | CBD(η=2) | CBD(η=2) |
| Masking Bound | γ₁ (GAMMA1) | 131,072 (2^17) | 131,072 (2^17) | 524,288 (2^19) |
| Rejection Bound | β (BETA) | 78 | 78 | 120 |
| Rejection Threshold | γ₁ - β | 130,994 | 130,994 | 524,168 |
| Context Tag Size | τ | 256 bits | 256 bits | 384 bits |
| Attribute Capacity | m | 8 | 12 | 16 |

### 2.3 Distributions

**Centered Binomial Distribution (CBD_η):**

For η = 2, sample **a, b ← {0,1}^η** uniformly, output **(∑a_i) - (∑b_i) ∈ {-η, ..., η}**.

This produces a distribution over **{-2, -1, 0, 1, 2}** with probabilities:
```
P(-2) = P(2) = 1/16
P(-1) = P(1) = 4/16
P(0)          = 6/16
```

**Uniform Distribution over R_q:**
```
a ← R_q  (each coefficient uniform in [0, q-1])
```

**Masking Distribution S_γ₁:**
```
y ← S_γ₁^k  (each coefficient uniform in [-γ₁, γ₁])
```

---

## 3. The Full PLP Algorithm

### 3.1 Key Generation

```
Algorithm KeyGen(seed):
  Input:  Caller-supplied 32-byte seed
  Output: Master secret vector s ∈ R_q^k

  1. s ← SampleCBD_η(SHAKE-256(seed ∥ "AETHEL_MASTER_KEY_V1"))
     (matches src/plp.rs's actual domain separator and derivation)
  2. Return s
```

**Aspirational variant:** the seed above could itself come from an SRAM PUF fuzzy extractor
(see `SRAM-PUF.md`) instead of being caller-supplied — that's a non-default, research-only
feature (`puf`) in the shipped crate, not the default key-derivation path. The shipped code
does not verify `∥s∥_∞ ≤ η` post-hoc (the CBD sampler already produces coefficients in
`{-η,...,η}` by construction) or reference a "volatile enclave scratchpad" — nothing in this
repo runs inside a real hardware enclave.

**Security Note:** The master secret **s** should never be written to non-volatile storage by
calling code, and this crate's own `MasterIdentity` implements `Zeroize`/`ZeroizeOnDrop` so it
is wiped when dropped.

### 3.2 Projection Generation

```
Algorithm Project(s, τ, rng):
  Input:  Master secret s ∈ R_q^k
          Execution context τ ∈ {0,1}^256
          Randomness source rng
  Output: Ephemeral projection (A_τ, b_τ)

  1. Context Expansion:
     A_τ ← SHAKE-256("AETHEL_PLP_CTX_V3" ∥ τ ∥ salt)
     (Expand to k×k matrix of uniform R_q elements)

  2. Noise Sampling:
     e_τ ← χ_η^k  (sample k polynomials from CBD_η)

  3. Projection Computation:
     b_τ = A_τ · s + e_τ  (mod q)

  4. Return (A_τ, b_τ)
```

**Indistinguishability:** Under the hardness of M-LWE_{k,η,q}, the projection **b_τ** is computationally indistinguishable from a uniform random sample over **R_q^k** to any observer lacking knowledge of **s**.

### 3.3 Prover Algorithm (Sigma-Protocol with Rejection Sampling)

```
Algorithm Prove(s, A_τ, b_τ, τ, rng):
  Input:  Master secret s ∈ R_q^k
          Context matrix A_τ ∈ R_q^{k×k}
          Public projection b_τ ∈ R_q^k
          Context τ ∈ {0,1}^256
          Randomness source rng
  Output: ZK proof π_τ = (W, c, z)

  Loop:
    1. Sample masking vector y ← S_γ₁^k  (each coeff uniform in [-γ₁, γ₁])

    2. Compute commitment:
       W = A_τ · y  (mod q)

    3. Compute Fiat-Shamir challenge:
       c = Hash(A_τ ∥ b_τ ∥ W ∥ τ)
       Map hash digest to sparse ternary polynomial c ∈ {-1, 0, 1}^N

    4. Compute candidate response:
       z = y + c · s  (mod q)

    5. Rejection Sampling Check:
       If ∥z∥_∞ ≥ (γ₁ - β):
         Continue Loop  (Reject to prevent side-channel leakage of s)
       Else:
         Return π_τ = (W, c, z)
```

**Rejection Sampling Rationale:** The rejection condition ensures that the output distribution of **z** is statistically independent of the master secret **s**. Without rejection sampling, an adversary could use the distribution of **z** to extract information about **s** via statistical analysis.

**Constant-Time Implementation:** In enclave environments, the loop MUST execute for exactly **I_max = 16** iterations regardless of when a valid candidate is found. A constant-time multiplexer (CMOV) captures the first valid proof while continuing dummy iterations.

### 3.4 Verifier Algorithm

```
Algorithm Verify(A_τ, b_τ, τ, π_τ):
  Input:  Context matrix A_τ ∈ R_q^{k×k}
          Public projection b_τ ∈ R_q^k
          Context τ ∈ {0,1}^256
          Proof π_τ = (W, c, z)
  Output: ACCEPT or REJECT

  1. Check Response Norm Bound:
     If ∥z∥_∞ ≥ (γ₁ - β):
       Return REJECT ("Response norm out of bounds")

  2. Recompute Fiat-Shamir Challenge:
     c' = Hash(A_τ ∥ b_τ ∥ W ∥ τ)
     If c' ≠ c:
       Return REJECT ("Challenge mismatch")

  3. Verify Ring Relation:
     Compute W' = A_τ · z - c · b_τ  (mod q)
     Compute diff = W' - W
     If ∥diff∥_∞ < (β · 2):
       Return ACCEPT
     Else:
       Return REJECT ("Ring relation check failed")
```

**Verification Equation Derivation:**

Given a valid proof where **z = y + c · s**:
```
A_τ · z - c · b_τ
= A_τ · (y + c · s) - c · (A_τ · s + e_τ)
= A_τ · y + A_τ · c · s - c · A_τ · s - c · e_τ
= A_τ · y - c · e_τ
= W - c · e_τ
```

Since **∥e_τ∥_∞ ≤ β** and **∥c∥_∞ ≤ 1** (sparse ternary), we have **∥c · e_τ∥_∞ ≤ β**, so **∥W' - W∥_∞ ≤ β · 2**.

---

## 4. Security Reductions

### 4.1 Context-Unlinkability Game

**Definition 4.1 (Context-Unlinkability Game Game_A^Unlink(λ)):**

1. **Setup**: Challenger C samples master secret vector **s ← χ_η^k ⊂ R_q^k** with parameter set **λ = (N, q, k, η)**.

2. **Phase 1 (Adaptive Context Queries)**: Adversary A adaptively chooses m distinct contexts **{τ_1, τ_2, ..., τ_m}**. For each context τ_i, C generates:
   - **A_{τ_i} ← SHAKE-256("AETHEL_PLP_CTX_V3" ∥ τ_i ∥ salt_i)**
   - **e_{τ_i} ← χ_η^k**
   - **b_{τ_i} = A_{τ_i} · s + e_{τ_i} (mod q)**
   - C returns **(A_{τ_i}, b_{τ_i})** to A.

3. **Challenge Phase**: A selects two fresh target contexts **τ_0*** and **τ_1*** such that **τ* ∉ {τ_1,...,τ_m}**. C flips a uniform coin **b ← {0,1}**:
   - If **b = 0**: C generates two valid PLP instances using the same secret **s**.
   - If **b = 1**: C samples independent random secrets **s_0, s_1 ← χ_η^k**.
   - C sends **((A_{τ_0*}, b_0*), (A_{τ_1*}, b_1*))** to A.

4. **Guess**: A outputs a bit **b' ∈ {0,1}**.

The advantage of A in breaking PLP unlinkability is defined as:
```
Adv_A^Unlink(λ) = |Pr[b = b'] - 1/2|
```

### 4.2 Main Theorem

**Theorem 4.1 (Reduction to M-LWE):** Let A be a polynomial-time adversary that achieves advantage **Adv_A^Unlink(λ)** in the context-unlinkability game after making at most m context queries. Then there exists an algorithm B running in substantially the same time that solves the Decision M-LWE_{k,k+1,η,q} problem over R_q with advantage:

```
Adv_B^M-LWE(λ) ≥ (1/2) · Adv_A^Unlink(λ)
```

**Proof Strategy via Game Hopping (Game_0, Game_1, Game_2):**

```
               [ Game 0: Real Execution ]
       (Projections generated with single secret s)
                           |
                           v  <-- Indistinguishable via M-LWE_q (Lemma 4.1)
               [ Game 1: Uniform Noise ]
       (All projections replaced by uniform random noise)
                           |
                           v  <-- Structurally Identical (Lemma 4.2)
               [ Game 2: Independent Secrets ]
       (Projections generated with independent secrets s_0, s_1)
```

**Lemma 4.1:** If A can distinguish Game_0 from Game_1 with advantage ε_1, there exists an algorithm B_1 solving Dec-M-LWE_{k,k+1,η,q} with advantage ε_1.

**Lemma 4.2:** The distribution of samples in Game_2 is indistinguishable from Game_1 under Dec-M-LWE_{k,k+1,η,q}.

**Conclusion:**
```
Adv_A^Unlink(λ) ≤ 2 · Adv_B^M-LWE(λ) + Negl(λ)
```

### 4.3 Rejection Sampling Side-Channel Defense

**Theorem 4.2 (Rejection Sampling Unlinkability):** The output distribution of the response vector **z** from the Prove algorithm is statistically independent of the master secret **s**, provided the rejection condition **∥z∥_∞ < (γ₁ - β)** is enforced.

**Proof Sketch:** The masking vector **y** is sampled uniformly from **S_γ₁^k**. The response **z = y + c · s** has distribution that, conditioned on acceptance, is statistically close to uniform over **S_{γ₁-β}^k** regardless of **s**, because the rejection probability depends only on the norm of **c · s** (bounded by **β**) relative to the masking range **γ₁**.

---

## 5. Parameter Choices and Rationale

### 5.1 Modulus Selection

The prime modulus **q = 8,380,417 = 2^23 - 2^13 + 1** satisfies:

1. **NTT Compatibility**: q ≡ 1 (mod 512), enabling efficient Number Theoretic Transform (NTT) polynomial multiplications in O(N log N) time.
2. **Word-Size Efficiency**: q fits within a signed 24-bit integer, allowing vector accumulation steps in standard 32-bit registers or SIMD vector units without intermediate overflow.
3. **FIPS 204 Alignment**: This is the same modulus used in ML-DSA (CRYSTALS-Dilithium), enabling code reuse and hardware acceleration compatibility.

### 5.2 Ring Degree

**N = 256** provides:
- Sufficient polynomial dimension for 128-bit post-quantum security
- Efficient NTT butterfly operations (8 levels for N=256)
- Compact polynomial representation (256 × 23 bits ≈ 736 bytes per polynomial)

### 5.3 Rejection Bound Rationale

The rejection bound **γ₁ - β = 130,994** is chosen such that:

1. **Failure Probability**: The probability that a single iteration is rejected is approximately **1 - (2(γ₁-β)+1)^{kN} / (2γ₁+1)^{kN} ≈ 1 - e^{-kNβ/γ₁}**.
2. **16-Iteration Ceiling**: With **I_max = 16** iterations, the failure probability is approximately **(1 - p_accept)^16 ≈ 10^{-20}**, providing negligible failure probability.
3. **Security Margin**: The gap **β = 78** ensures that the response distribution is statistically indistinguishable from uniform over **S_{γ₁-β}^k**.

### 5.4 BKZ Security Analysis

To ensure 128-bit post-quantum security against dual lattice attacks (uSVP and BKZ reduction) while keeping **Adv_A^Unlink(λ) ≤ 2^{-128}**, Aethel-ID enforces the following concrete ring parameters:

| Parameter | Notation | Specification |
|-----------|----------|---------------|
| Ring Degree | N | 256 |
| Modulus | q | 8,380,417 ≈ 2^23, q ≡ 1 (mod 512) |
| Module Rank | k | 4 |
| Noise Distribution | χ_η | Centered Binomial Distribution (η=2) |
| Hermite Factor | δ_BKZ | 1.0039 (Requires BKZ block size β ≥ 400) |

---

## 6. Implementation Notes

### 6.1 Polynomial Arithmetic

**Naive Multiplication (O(N²) — Prototype Only):**
```rust
pub fn mul(&self, other: &Self) -> Self {
    let mut res = [0i64; 2 * N];
    for i in 0..N {
        for j in 0..N {
            res[i + j] = (res[i + j] + self.coeffs[i] * other.coeffs[j]) % Q;
        }
    }
    // Reduce modulo X^N + 1
    let mut final_p = Self::zero();
    for i in 0..N {
        let poly_val = (res[i] - res[i + N] + Q * Q) % Q;
        final_p.coeffs[i] = poly_val;
    }
    final_p
}
```

**Production Implementation:** Use NTT-based multiplication in O(N log N) time. The modulus q = 8,380,417 supports NTT with primitive 512th root of unity.

### 6.2 Context Matrix Derivation

The context matrix **A_τ** is derived deterministically from the execution context **τ** using SHAKE-256:

```rust
let mut hasher = Sha3_256::new();
hasher.update(b"LATTICE_CTX_SEED_V1");
hasher.update(block_context.to_le_bytes());
let seed = hasher.finalize();
let mut seed_rng = rand::rngs::StdRng::from_seed(seed.into());
let matrix_a = Poly::random_uniform(&mut seed_rng);
```

**Production Note:** Use SHAKE-256 (XOF) rather than SHA3-256 for proper domain separation and arbitrary-length output expansion.

### 6.3 Fiat-Shamir Challenge Derivation

The challenge polynomial **c** is derived from the hash of the transcript:

```rust
fn compute_challenge(a: &Poly, b: &Poly, w: &Poly, ctx: u64) -> Poly {
    let mut hasher = Sha3_256::new();
    for &c in a.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    for &c in b.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    for &c in w.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    hasher.update(ctx.to_le_bytes());
    let digest = hasher.finalize();
    // Map hash digest to a sparse ternary polynomial c in {-1, 0, 1}
    let mut c_poly = Poly::zero();
    for i in 0..32 {
        let byte = digest[i];
        c_poly.coeffs[i * 2] = (byte % 3) as i64 - 1;
        c_poly.coeffs[i * 2 + 1] = ((byte / 3) % 3) as i64 - 1;
    }
    c_poly
}
```

### 6.4 Constant-Time Norm Checking

All norm checks MUST be performed in constant time to prevent timing side-channels:

```c
uint32_t ct_check_norm_bound(const int32_t z[MODULE_K][RING_N], int32_t bound) {
    uint32_t bad_coeff_mask = 0;
    for (size_t i = 0; i < MODULE_K; i++) {
        for (size_t j = 0; j < RING_N; j++) {
            int32_t coeff = z[i][j];
            // Compute absolute value in constant time
            int32_t mask = coeff >> 31;
            int32_t abs_coeff = (coeff + mask) ^ mask;
            // Accumulate bitwise OR mask if abs_coeff >= bound
            int32_t diff = (bound - 1) - abs_coeff;
            bad_coeff_mask |= (uint32_t)(diff >> 31);
        }
    }
    // Returns 0 if all coefficients are within bounds, 0xFFFFFFFF if rejected
    return bad_coeff_mask;
}
```

### 6.5 Fixed-Iteration Loop

> This C pseudocode matches the real, shipped algorithm in `src/sampling.rs`
> (`enclave_plp_prove_fixed_time`, Rust) closely, including the fixed 16-iteration ceiling and
> constant-time capture — but nothing in this repo runs it inside an actual hardware
> enclave/TEE. "Enclave" here names the module/function, not a claim about execution
> environment.

The rejection sampling loop MUST execute for exactly **I_max = 16** iterations:

```c
void enclave_plp_prove_fixed_time(
    uint8_t *proof_out,
    const int32_t s[MODULE_K][RING_N],
    const uint8_t tau[32]
) {
    uint32_t proof_captured = 0;
    uint8_t candidate_proof[sizeof(plp_proof_t)];
    uint8_t dummy_proof[sizeof(plp_proof_t)];
    for (size_t iter = 0; iter < 16; iter++) {
        int32_t z[MODULE_K][RING_N];
        plp_generate_candidate(z, s, tau, iter);
        uint32_t reject_mask = ct_check_norm_bound(z, GAMMA1 - BETA);
        uint32_t capture_mask = (~reject_mask) & (~proof_captured);
        ct_cond_copy(candidate_proof, z, sizeof(candidate_proof), capture_mask);
        ct_cond_copy(dummy_proof, z, sizeof(dummy_proof), ~capture_mask);
        proof_captured |= capture_mask;
    }
    ct_cond_copy(proof_out, candidate_proof, sizeof(candidate_proof), proof_captured);
}
```

### 6.6 Memory Zeroization

All intermediate secret-derived data MUST be explicitly zeroized after use:

```c
void enclave_explicit_zeroize(volatile void *v, size_t n) {
    volatile char *p = (volatile char *)v;
    while (n--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}
```

---

## 7. Hybrid Cross-Primitive Extension (Aspirational)

> Design idea, not implemented. No isogeny or code-based component exists anywhere in this crate.

To eliminate single-point-of-failure from pure M-LWE reliance, the PLP can be extended with a hybrid cross-primitive construction:

```
                     +---------------------------------------+
                     |    Master Sovereign Entropy (Seed)    |
                     +---------------------------------------+
                                  /             \
                                 /               \
                                v                 v
                 +----------------------+   +----------------------+
                 | M-LWE Polynomial    |   | Code-Based/Isogeny   |
                 | Vector Basis (v1)    |   | Vector Space (v2)    |
                 +----------------------+   +----------------------+
                                  \               /
                                   \             /
                                    v           v
                     +---------------------------------------+
                     |    Hybrid Polynomial Projection       |
                     |    b_tau = (A_tau * v1) (+) (C * v2)  |
                     +---------------------------------------+
```

**Mathematical Defense:** To compromise an identity's secret space, an adversary would have to simultaneously solve a Shortest Vector Problem (SVP) on high-dimensional lattices AND a Syndrome Decoding Problem over unstructured error-correcting codes. Breaking one layer yields zero information about the underlying master seed.

---

## 8. Formal Verification Targets

(Renumbered — the original §8, "5D Toric Manifold Connection," was removed entirely; see the
editorial note at the top of this document.)

The following properties are targets for formal verification using Coq or Lean 4:

1. **Unlinkability**: `Adv_Adversary_Link(PLP_τ1, PLP_τ2) ≤ Negl(λ) + ε_DP`
2. **Soundness**: A forged proof passes verification with probability at most `Negl(λ)` under M-SIS hardness.
3. **Zero-Knowledge**: The proof transcript `(W, c, z)` is simulatable without knowledge of `s`.
4. **Constant-Time**: The `enclave_plp_prove_fixed_time` function has no secret-dependent branches (verified via Valgrind/ctgrind).

---

## References

- Lyubashevsky, V.: "Fiat-Shamir with Aborts: Applications to Lattice and Factoring-Based Signatures." ASIACRYPT 2009.
- Ducas, L. et al.: "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme." TCHES 2018.
- NIST FIPS 204: "Module-Lattice-Based Digital Signature Standard (ML-DSA)." 2024.
- Regev, O.: "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography." STOC 2005.
- Lyubashevsky, V., Peikert, C., Regev, O.: "On Ideal Lattices and Learning with Errors over Rings." EUROCRYPT 2010.

---

## 9. PLP vs `did:pkh:eip155` — two dialects, not two competitors (A-2)

> Gap this closes (SAGP-PG-001 A-2, verbatim): "SAGP currently also speaks
> did:pkh:eip155 — Two identity dialects on L0 — Wave 1: accept did:pkh for spend
> binding (wallet is on Base) AND aethel projection for who. Document the pair. Do
> not make PLP a Base address." Non-goal, verbatim (§10): "Do not make PLP replace
> Base addresses for USDC. Spend rail stays eip155; identity stays aethel."

A relying party (a fabric adapter, a gateway, a settlement counterparty) that talks to an
aethel agent will see **two different identity dialects at layer 0**, and both are correct
for what they each do:

| Dialect | What it answers | Lifetime | Held by |
|---|---|---|---|
| **`did:pkh:eip155:8453:0x...`** | *"Where do I send/receive USDC?"* | Stable — a wallet address on Base | The agent's settlement signer (a classical secp256k1 key; see `aethel-vault`, a separate crate). |
| **PLP projection (this document)** | *"Who is presenting right now?"* | Ephemeral — a fresh, unlinkable projection per context `τ` | The agent's [`signing::Identity`](../src/signing.rs) (ML-DSA-65 + PLP seed). |

These are **not two ways of naming the same thing** — they answer different questions, for
different reasons, with different lifetimes:

- **Spend rail stays `eip155`.** USDC on Base is spent by a `transferWithAuthorization`
  (EIP-3009) signed by a secp256k1 key at a stable address. A post-quantum ML-DSA
  signature cannot be verified by that contract, and nothing in this crate changes that.
  aethel-core has **no notion of an Ethereum address, chain id, or secp256k1 key at all** —
  that machinery lives in `aethel-vault`, not here.
- **Identity stays aethel.** A PLP projection `b_τ = A_τ·s + e_τ` is a fresh M-LWE sample
  per context, computationally indistinguishable from uniform noise, and reusable for
  exactly nothing beyond the context it was made for. It is the answer to "who is this,
  cryptographically, right now" — not "where do I route a payment."

### PLP is never a Base address

Nothing in this crate encodes, hashes, or truncates a PLP projection into anything that
looks like an Ethereum address (20 bytes, checksum-cased hex). `EphemeralProjection`'s wire
form ([`docs/WIRE-FORMAT.md`](./WIRE-FORMAT.md)) is `tau(32) ‖ salt(32) ‖ public_b(...)` —
structurally nothing like an address, and deliberately so. A relying party that needs "an
address-shaped identifier" for a PLP holder has misread the primitive; the correct move is
to keep the `did:pkh` binding for settlement and the PLP projection for identity, and pair
them explicitly (next section) rather than collapsing one into the other.

### The wire shape a relying party should accept

A relying party pairing the two dialects for one interaction sees something shaped like:

```text
{ projection_bytes, proof_bytes, tau, spend_did, binding_sig }
```

- `projection_bytes` / `proof_bytes` — `aethel-plp-1` envelopes (this document, §7;
  [`docs/WIRE-FORMAT.md`](./WIRE-FORMAT.md)), verified with
  [`wire::verify_projection`](../src/wire.rs).
- `tau` — the context the projection was made for; the verifier supplies this itself and
  checks it against the decoded projection, never trusting a caller-supplied `tau`.
- `spend_did` — the `did:pkh:eip155:8453:0x...` string naming the settlement address.
- `binding_sig` — optional, out of scope for this crate: a signature over
  `(projection_bytes, spend_did)` that ties a specific projection to a specific settlement
  address for one interaction, without creating a stable, cross-context linkage between
  them. Building this primitive (and whether it belongs in `aethel-core` or purely in
  documentation/SAGP) is tracked as an open decision in the gap-remediation plan; nothing
  in the shipped API depends on it existing.

The acceptance half of this pairing — SAGP/a fabric adapter agreeing to hold both dialects
side by side — is outside this crate's scope. What this document commits to is narrower and
load-bearing: **aethel-core will never grow a feature that makes a PLP projection stand in
for a Base address**, and any future spend-binding primitive will be additive, not a
replacement for either dialect.
