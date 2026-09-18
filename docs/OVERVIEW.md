---
title: "Aethel-ID: Technical Overview"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-core"
---

# Aethel-ID: Post-Quantum Ephemeral Identifier Engine

> **P3-05 (2026-08-26) editorial note.** This document was written before `aethel-core` had a
> README describing what actually ships, and it shows: an "Integration Points with Aethel-Vault"
> section and a competitive matrix comparing against Zcash/Monero pulled in Aethel-Vault
> content the charter puts out of scope for this crate, several sections describe SAAP
> credential issuance and a full binary wire format that aren't implemented, and "on-chain"
> phrasing implied blockchain integration that doesn't exist anywhere in this repo. Sections
> below are marked inline; the two out-of-scope Vault sections and the competitive matrix have
> been removed rather than corrected. Cross-check basis: `aethel-core`'s README, "What runs
> today vs. what is designed."

## Overview

**Aethel-ID** is the Post-Quantum Ephemeral Identifier Engine — a cryptographic identity system that replaces static Decentralized Identifiers (DIDs) with non-deterministic, ephemeral identity projections that leave **zero static public keys**, full stop — this crate has no blockchain, ledger, or on-chain component of any kind.

Modern Decentralized Identifiers (DIDs) are fundamentally flawed from a long-term, post-quantum privacy perspective. Even if you swap out ECDSA public keys for lattice-based PQC keys (FIPS 204/206), classical DID architecture still links state through deterministic derivation pathways or static public document schemas.

When a quantum computer with sufficient qubits analyzes a public ledger over time, these "post-quantum" static DIDs succumb to Structural Reverse Engineering via side-channel graph analysis, lattice-basis intersection attacks, and heuristic correlation.

Aethel-ID abandons the concept of a "registered identifier" entirely.

---

## Why Standard DIDs Fail Under Post-Quantum Scrutiny

Standard DIDs expose structural metadata in three critical places:

1. **Public Verification Keys**: Even if the key is an ML-DSA lattice point, holding the same static vector in a public document allows an attacker to build an immutable identity graph.
2. **Determinism in Key Derivation**: Deterministic derivation algorithms (like post-quantum HD-wallets) create mathematical relations between keys that quantum algorithms can exploit if intermediate parameters leak.
3. **Registry Fingerprinting**: Resolving a DID requires querying an on-chain state or IPFS document, creating a fixed network metadata trail.

```
CLASSICAL DID (Vulnerable):
Static DID -> Resolved Document -> Public Lattice Key -> Correlated Transactions
                                                                   |
                                                   Quantum Graph Reconstruction

POST-QUANTUM EPHEMERAL STATE (Un-linkable):
Dynamic Seed -> Ephemeral Polynomial Drift -> Blind Entropy Pool -> One-Time Zero-Knowledge Proof
```

---

## Polymorphic Lattice Projection (PLP) Algorithm

The core of Aethel-ID is the **Polymorphic Lattice Projection (PLP)** — a mathematical primitive that replaces the static identifier with a continuously mutating public projection.

### Core Concept

In this system:

1. The user holds a secret polynomial vector **s ∈ R_q^k** over a cyclotomic ring **R_q = Z_q[X]/(X^N + 1)**.
2. Instead of publishing a fixed public key **b = As + e**, the system continuously mutates the public projection based on an execution context or block height parameter **τ**.
3. The verifier receives a single-use public matrix **A_τ** and output **b_τ**.
4. Under Module Learning-With-Errors (M-LWE), **b_τ** is computationally indistinguishable from uniform random noise to an observer.
5. The prover uses a Sigma-protocol with rejection sampling to prove knowledge of **s** without leaking the short norm bound **∥s∥_∞ ≤ β**.

### Parameters

> Only LEVEL1 (module rank `k=4`) is implemented; LEVEL3/LEVEL5 are unbuilt proposals.

| Parameter | Notation | Value |
|-----------|----------|-------|
| Ring Degree | N | 256 |
| Modulus | q | 8,380,417 |
| Module Rank | k | 4 (LEVEL1), 6 (LEVEL3), 8 (LEVEL5) |
| Noise Bound | η (ETA) | 2 |
| Masking Bound | γ₁ (GAMMA1) | 131,072 (2^17) |
| Rejection Bound | β (BETA) | 78 |

### Projection Generation

```
Context Expansion:  A_τ ← SHAKE-256("AETHEL_PLP_CTX_V3" ∥ τ ∥ salt)
Noise Sampling:     e_τ ← χ_η^k over R_q
Projection:         b_τ = A_τ · s + e_τ (mod q)
```

Under the hardness of M-LWE_{k,η,q}, the projection **b_τ** is computationally indistinguishable from a uniform random sample over R_q^k to any observer lacking knowledge of **s**.

### Key Architectural Properties

1. **No Static Public Key Exists**: The user's public projection **b_τ** constantly changes based on context or block height τ. To an external actor watching the network, every transaction appears to originate from a completely new, uncorrelated keypair.
2. **Post-Quantum Zero-Knowledge**: The proof verifies that the prover knows the secret polynomial **s** corresponding to the ephemeral projection, without ever exposing **s** or static identity markers.
3. **Side-Channel Resistant Rejection Sampling**: The prover loops until the response vector **z** falls strictly within the norm bound γ₁ − β. This prevents observers from using statistical distribution analysis on **z** to extract information about **s**.

---

## SAAP Protocol Flow (Issue → Prove → Verify)

> **Partially shipped.** The Prove/Verify algorithms below match the shipped `saap_prove`/
> `verify_saap_proof`, and BDLOP commitment issuance is shipped as `credential.issue`. The
> issuer ML-DSA signature is design-only, and cannot be built in the form drawn below: the
> verifier sees the blinded commitment, never `t_cred`, so a signature over `t_cred` can be
> neither shown nor checked without reintroducing a static per-credential identifier and
> destroying unlinkability. Closing this needs a signature the holder proves knowledge of in
> zero knowledge. See [ISSUER-AUTHENTICATION.md](ISSUER-AUTHENTICATION.md) for the gap, the
> construction, and what it assumes until then.

The **Selective Attribute Attestation Protocol (SAAP)** allows a Holder to prove arbitrary statements about credential attributes without disclosing non-requested attributes, without exposing static identity identifiers, and without revealing the Issuer's signature object directly.

### Protocol Overview

```
ISSUANCE PHASE (One-time, Private Setup):
  Issuer Key + Attributes (m) ----> BDLOP Commitment (t_cred) ----> Signature σ_Issuer
                                                                         |
                                                                         v
PROVING PHASE (Selective Disclosure):                     Holder Local Runtime
  Holder local secret s + t_cred + m_revealed
         |
         +----> Randomized Blinded Commitment (C_attr)
         +----> M-LWE Ephemeral Projection (b_τ)
         +----> Lattice ZK Proof (π_SAAP) ------------------> Verifier Verification
                                                                (Zero Identifiers Disclosed)
```

### Issue Algorithm (SAAP.Issue)

1. Sample public commitment matrix **B ← R_q^(k×m)** deterministically from ContextID using SHAKE-256.
2. Sample small-norm commitment error vector **e_commit ← (CBD_η)^k**.
3. Construct homomorphic attribute vector commitment: **t_attr = B · A + e_commit (mod q)**
4. Sign message payload **M_iss = (t_attr ∥ ContextID)** under **sk_iss** to produce **Σ_iss = (c_iss, z_iss)** via ML-DSA lattice signature rules.
5. Output Credential Tuple **C_iss = (t_attr, A, ContextID, Σ_iss)**.

### Prove Algorithm (SAAP.Prove)

1. Parse disclosed subset **S = { i | M_disc[i] == 1 }**.
2. Sample polynomial blinding vector **r_blind ← (S_γ₁)^k**.
3. Compute blinded commitment: **t_blind = t_attr + B · r_blind (mod q)**
4. Compute commitment domain hash: **h_commit = SHA3-256(t_blind ∥ ContextID)**
5. **REJECTION_LOOP**:
   - Sample ephemeral masking vector **y ← (S_γ₁)^k** uniformly at random.
   - Compute linear commitment projection: **w' = A · y (mod q)**
   - Derive challenge polynomial: **c = HashToPoly(h_commit ∥ τ ∥ M_disc ∥ w' ∥ "AETHEL_SAAP_CHALLENGE_V1")**
   - Compute candidate response vector: **z = y + c · r_blind (mod q)**
   - **CONSTANT-TIME REJECTION CHECK**: If **∥z∥_∞ ≥ (γ₁ - β)**, clear y, z and GOTO REJECTION_LOOP.
6. Output Proof Transcript **π_saap = (τ, M_disc, A_S, c, z, h_commit)**.

### Verify Algorithm (SAAP.Verify)

```
Algorithm Verify-SAAP(τ, t_blind, m_pub, b_τ, π_SAAP):
  1. Check Response Vector Norms:
       If ||z_r||_∞ >= (γ_1 - β) OR ||z_s||_∞ >= (γ_1 - β) OR ||z_m||_∞ >= (γ_1 - β):
         Return REJECT ("Norm check failed")
  2. Reconstruct Commitment Matrices:
       W_1' = B_1 * z_r + [0 || z_m] - c * (t_blind - [0 || m_pub]) mod q
       W_2' = A_tau * z_s - c * b_tau mod q
  3. Validate Fiat-Shamir Challenge:
       c' = Hash(W_1' || W_2' || b_tau || t_blind || m_pub || τ)
       If c' != c:
         Return REJECT ("Challenge mismatch")
  4. Validate Predicate Constraints:
       Evaluate quadratic polynomial relations over z_m for hidden attributes.
       If predicate checks pass:
         Return ACCEPT ATTESTATION
       Else:
         Return REJECT ("Predicate check failed")
```

---

## SRAM PUF Integration and BCH Fuzzy Extractor

> **Aspirational — research code, non-default.** `aethel-core`'s `puf` module is a non-default,
> research-only feature with a simplified placeholder BCH encoder — not the crate's actual
> key-derivation path. `MasterIdentity::from_seed` takes a caller-supplied 32-byte seed;
> nothing about it requires or assumes a PUF. See `aethel-core`'s README.

A critical vulnerability of classical identity runtimes is the persistence of cryptographic master keys in non-volatile storage (Flash, EEPROM, or disk). Under physical capture or cold-boot side-channel analysis, persistent keys can be extracted.

Aethel-ID addresses this by employing a **Physical Uncloneable Function (PUF)** derived from silicon SRAM startup characteristics. By pairing the unconditioned physical noise of an SRAM array with a **Secure Fuzzy Extractor**, the master state vector **s** is never stored.

### Physical SRAM PUF Model

When an uninitialized SRAM cell powers up, the cross-coupled inverters enter a metastable state that settles into a logical 0 or 1 state. This preference is dictated by microscopic, non-deterministic threshold voltage mismatches (ΔV_th) introduced during silicon fabrication.

```
+-----------------------------------------------------------------+
|                  Silicon Die Micro-Variations                   |
|                   (SRAM PUF / Lattice Sensor)                   |
+-----------------------------------------------------------------+
                                 |
                     [ Quantum Thermal Entropy ]
                                 v
+-----------------------------------------------------------------+
|            Fuzzy Extractor / Error-Correction Engine            |
|                  (Reprojection via Helper Data)                 |
+-----------------------------------------------------------------+
                                 |
                                 v
+-----------------------------------------------------------------+
|              Master Secret Seed s (Non-Volatile)                |
|             *Exists ONLY during active ZK computation*           |
+-----------------------------------------------------------------+
```

### BCH(1023, 512, 55) Error Correction

The fuzzy extractor uses a **BCH(1023, 512, 55)** code over **GF(2^10)**:

- **Block Code Length (n_bch)**: 1023 bits
- **Information Payload Length (k_bch)**: 512 bits
- **Error Correction Capacity (t_bch)**: 55 errors per block
- **Galois Field Extension Degree (m)**: 10 (GF(2^10))
- **Generator Polynomial Degree**: 511 bits (parity length n - k = 511)

### Enrollment Phase (Gen)

1. Read primary SRAM power-up state: **R_enroll ← ReadSramUninitializedArray()**.
2. Sample a uniform random cryptographic seed **S_seed ← {0,1}^k_bch**.
3. Encode **S_seed** using systematic BCH(1023, 512, 55) encoding to yield codeword **C_code = (S_seed ∥ Parity)** in **{0,1}^n_bch**.
4. Compute secure sketch helper string: **W_sketch = R_enroll[0..n_bch-1] XOR C_code**.
5. Extract master key via SHA3-256 privacy amplification: **K_master = SHA3-256(S_seed ∥ "AETHEL_PUF_PRIVACY_AMP_V1")**.
6. Construct Helper Data string **P_helper = (W_sketch ∥ VersionTag)**.
7. Write **P_helper** to persistent non-volatile storage (NVM).

### Reconstruction Phase (Rep)

1. Fetch public helper string **W_sketch** from **P_helper**.
2. Read current SRAM power-up state: **R_reconstruct ← ReadSramUninitializedArray()**.
3. Reconstruct noisy codeword: **C_noisy = R_reconstruct[0..n_bch-1] XOR W_sketch**.
4. Execute constant-time BCH decoding on **C_noisy** using Berlekamp-Massey and Chien Search subroutines: **S_reconstructed ← BchDecode(C_noisy, t_bch=55)**. If decoding fails (uncorrectable errors > 55), ABORT immediately.
5. Re-derive deterministic master identity key: **K_master = SHA3-256(S_reconstructed ∥ "AETHEL_PUF_PRIVACY_AMP_V1")**.
6. Immediately zeroize **C_noisy**, **S_reconstructed**, and working decoder buffers using explicit compiler memory barriers.

### Volatile Lifecycle

```
                          SECURE VOLATILE LIFECYCLE
  [ Enclave Boot ] ──> [ Read SRAM W' ] ──> [ Rep(W', P) ] ──> Reconstruct s
                                                                     │
                                                                     ▼
  [ Zeroize SRAM ] <── [ Zeroize s ] <── [ Generate Proof π_τ ] <───┘
```

The master secret **s** exists in memory for at most the duration of a single proof generation cycle (**< 50 ms**).

---

## How Identifiers Are Ephemeral and Unlinkable

### Ephemeral Projection Mechanism

For every interaction context τ (e.g., a block height, a session nonce, or a domain separator), the identity constructs a fresh, short-lived lattice projection:

```
b_τ = A_τ · s + e_τ (mod q)
```

Where:
- **A_τ** is derived deterministically from τ via SHAKE-256 (public, context-specific)
- **s** is the master secret (volatile, never published)
- **e_τ** is fresh ephemeral noise (sampled per context)

### Unlinkability Proof

Because **e_τ** is sampled fresh for each context τ, two projections **b_{τ1}** and **b_{τ2}** generated by the same master key **s** satisfy:

```
Adv_Adversary_Link(b_{τ1}, b_{τ2}) ≤ Negl(λ)
```

This means the advantage of any polynomial-time adversary in linking two projections to the same identity is negligible — computationally indistinguishable from random noise under M-LWE hardness.

### Cross-Block Replay Protection

A proof **π_τ** generated for context **τ₁** is cryptographically bound to **A_{τ1}** and **b_{τ1}**. Attempting to replay it against a different context **τ₂** fails the Fiat-Shamir challenge recomputation:

```
c' = Hash(A_{τ2} ∥ b_{τ2} ∥ W ∥ τ₂) ≠ c
```

---

## Security Properties and Threat Model

### Security Dimensions

| Security Dimension | Mechanism | Guarantee | Status |
|---|---|---|---|
| Mathematical Hardness | M-LWE over R_q^k | Computationally indistinguishable from uniform noise | Shipped |
| Execution State | Constant-time software execution (`sampling.rs`, verified via `ct_verify.rs`'s Valgrind/ctgrind harness) | No timing or power side-channel leakage in the tested paths | Shipped, not literally enclave-executed |
| Key Derivation | Caller-supplied 32-byte seed (`MasterIdentity::from_seed`) | No key ever written to disk by this crate | Shipped |
| Threshold Sharing | Shamir 3-of-5 (`htss::SecretSharer`) | Fewer than 3 shares reveal nothing; see `docs/HTSS-TOPOLOGY.md` for what's local-simulation vs. aspirational | Shipped (local, in-process) |

Removed from this table: "Nullifier Correlation (Kolmogorov-Blind ε-DP noise)" — nullifiers aren't a concept that exists anywhere in this crate; that's Aethel-Vault content, out of scope here.

### Threat Model

**Threats Mitigated (by the code that ships):**

1. **Shor's Algorithm**: Cannot extract keys because no static public key is ever written anywhere by this crate — there is no persistence layer of any kind, on-chain or otherwise.
2. **Grover's Algorithm**: Cannot brute-force the state because identity bindings use collision-resistant hashes and lattice commitments operating at ≥256-bit post-quantum security margins.
3. **Cold-Boot Attacks**: The master secret **s** is never written to non-volatile storage by this crate; it only ever exists as a caller-supplied value in memory.
4. **Timing Side-Channels**: Fixed 16-iteration padded rejection sampling loop with constant-time CMOV selection prevents timing leakage (verified via `ct_verify.rs`).

**Threats named in earlier drafts of this document, not applicable to what ships:** "Graph Analysis" via nullifiers (no nullifier concept exists here) and "Power/EM Side-Channels" via first-order masking / PRNG jitter injection (no such masking is implemented — the shipped constant-time work is the rejection-sampling loop and norm check, not power-trace countermeasures).

**Concrete Security Parameters (AETHEL-SAAP-LEVEL1):**

- **128-bit post-quantum security** against dual lattice attacks (uSVP and BKZ reduction)
- Requires BKZ block size **β ≥ 400** (Hermite factor δ_BKZ = 1.0039)
- Advantage bound: **Adv_A^Unlink(λ) ≤ 2^{-128}**

### Formal Security Reduction

The security of PLP reduces to the Decision Module Learning With Errors problem:

```
Adv_B^M-LWE(λ) ≥ (1/2) · Adv_A^Unlink(λ)
```

Equivalently: **Adv_A^Unlink(λ) ≤ 2 · Adv_B^M-LWE(λ) + Negl(λ)**

---

## Threshold Secret Sharing with a Hypercube Routing Simulation (HTSS)

See [`HTSS-TOPOLOGY.md`](./HTSS-TOPOLOGY.md) for the full, corrected treatment — this section
used to duplicate (and repeat the same inaccuracies as) that document and has been replaced
with a pointer rather than fixed twice. Short version: `htss::SecretSharer` is real, local,
in-process Shamir 3-of-5 secret sharing; `HypercubeNetwork`'s dimension-disjoint routing is a
real, tested, local *simulation* of path assignment across a modeled graph, not a live network
protocol.

---

## Out of scope: Aethel-Vault

Earlier drafts of this document included an "Integration Points with Aethel-Vault" section (DID/
wallet dual-system architecture, on-chain TFHE ciphertext state, nullifier-based spend proofs)
and a "Comparative Architecture Matrix" benchmarking against Zcash/Monero using Vault-scoped
primitives (TFHE, hardware enclave key storage). Both are removed entirely: Aethel-Vault is out
of scope for this repo per the charter (§1), and neither section described anything implemented
in `aethel-core`.

---

## Wire Format: Ephemeral Identity Attestation Bundle (EIAB)

> **Aspirational — only a magic-number constant is shipped.** `lib.rs` defines
> `EIAB_MAGIC: &[u8; 4] = b"ATH1"` (mirrored in `src/sdk/client.ts`), but there is no encoder or
> decoder implementing the full bundle layout below. The real, shipped serialization is
> `EphemeralProjection::to_bytes()`/`from_bytes()` (`tau(32) + matrix_a(N*4) + public_b(N*4)`),
> which does not match this diagram (no magic header, no embedded proof response vector).

Aethel-ID replaces the JSON-LD/DID Document format with a binary-packed **Ephemeral Identity Attestation Bundle (EIAB)**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic Header ("ATH1")                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Context Parameter (τ)                   +
|                            (256 bits)                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Ephemeral Projection Vector (b_τ)            +
|                     (Packed R_q Elements)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   ZK Proof Response Vector (z)                 +
|                     (Packed R_q Elements)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## References

- FIPS 203: ML-KEM (Module Lattice Key Encapsulation Mechanism)
- FIPS 204: ML-DSA (Module Lattice Digital Signature Algorithm)
- FIPS 206: FN-DSA (FFT over NTRU Lattice Digital Signature Algorithm)
- Lyubashevsky, V. et al.: CRYSTALS-Dilithium (basis for ML-DSA/FIPS 204)
- Dodis, Y. et al.: Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data
- Suh, G.E. & Devadas, S.: Physical Unclonable Functions for Device Authentication and Secret Key Generation
- IETF Internet-Draft: draft-harper-aethel-id-00
- IACR ePrint Archive: Aethel-ID Formal Security Proofs (forthcoming)
