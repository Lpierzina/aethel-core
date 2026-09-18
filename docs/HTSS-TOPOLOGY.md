---
title: "Threshold Secret Sharing with a Hypercube Routing Simulation (HTSS)"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-core"
---

# Threshold Secret Sharing with a Hypercube Routing Simulation (HTSS) — Specification

> **P3-05 (2026-08-26) editorial note.** This document previously described HTSS as a live
> network protocol — "routes ZK proof payloads across a 5D hypercube network," "validator
> consensus nodes," "entanglement distribution," an "eavesdropper" who could observe a
> path. None of that exists in the shipped crate: `SecretSharer::split_secret`/
> `reconstruct_secret_checked` (§2) are local, in-process Shamir 3-of-5 secret sharing over a
> single `u64` — no sockets, no transport, no adversary ever observes anything. `HypercubeNetwork`/
> `HypercubePacket`/`route_payload_shares` (§1, §4) **are real, tested code**
> (`tests/plp_tests.rs::test_hypercube_routing`), not dead code — but what they implement is a
> local simulation of dimension-disjoint path assignment across a modeled graph, walked
> in-process, not an actual network protocol with live security properties. The original
> sections on 5D Toric homological quantum error-correcting codes, logical qubits, and
> stabilizer operators have been removed entirely — they have no relationship to anything built
> or planned here (quantum error correction is unrelated to classical secret sharing, and
> "entanglement" in particular doesn't mean anything for this code), and there was nothing
> accurate to salvage. What follows has been rewritten and renumbered to describe what's real.

## Overview

**HTSS** ("Homological Topological Secret Sharing" — the module name predates this document
and is kept only as an identifier, not a claim) is local, in-process Shamir 3-of-5 threshold
secret sharing, plus a local simulation of assigning the resulting 5 shares to dimension-disjoint
paths across a modeled 5D hypercube graph ($Q_5$). The graph-routing simulation is a plausible
building block for a *future* distributed deployment (real nodes, real transport, a real
adversary observing some subset of real paths) — that would be the point of building it this way
rather than as a flat array shuffle — but that deployment does not exist in this crate today.
Treat "prevents metadata leakage," "eavesdropper," and "fault-tolerant delivery" as design targets
for that future system, not properties of the code as it ships.

### Who runs HTSS (A-3)

> Gap this closes (SAGP-PG-001 A-3, verbatim): "HTSS / hypercube looks like
> infrastructure 8gentz might host — Pulls us toward identity-as-a-service — HTSS is
> the agent's or operator's backup ritual. 8gentz does not run the 32-node cube."

**HTSS is a backup/recovery ritual performed by the agent's principal or an operator over
the sealed identity's key material — it is not a hosted service, and nobody but that
principal/operator ever runs it.** Concretely:

- The 32-node, 80-edge hypercube in this document is a **routing model for how a principal
  might distribute shares to custodians** — a schema for who-holds-what, not a running
  network. Nothing in this crate opens a socket, and nothing described here implies a
  server anyone operates on the agent's behalf.
- **8gentz does not run the 32-node cube.** No SAGP component, fabric adapter, or hosted
  gateway calls `SecretSharer::split_key_material`/`reconstruct_key_material` on an
  agent's behalf. If a deployment ever needs a k-of-n shard of *operator* seeds (as
  opposed to *agent identity* material), that belongs in operator runbooks built on this
  module, not in a hosted `pqc-privacy::vault`-style service.
- **What gets split is key material the caller already holds**, never a secret this crate
  derives and keeps to itself. `htss-split`/`SecretSharer::split_key_material` take the
  secret as a parameter; the crate never reaches into a `signing::Identity` or
  `plp::MasterIdentity` to split it for you (there is no such method — see the resource
  review in `src/component.rs`'s `secret-sharing` implementation notes). Whoever calls
  `split` already had the material a caller had to supply; splitting emits nothing new.
- **The ritual, end to end**: an agent's principal (or an operator acting for them) takes
  the identity's *sealing key* (not the raw entropy — see
  [`Identity::export_sealed`](../src/signing.rs)), splits it 3-of-5 with
  `SecretSharer::split_key_material`, and distributes the five shares to five distinct
  custodians along with the 32-bit root. Recovery is the reverse: gather 3 shares, feed
  them plus the root to `SecretSharer::reconstruct_key_material` (or the WIT
  `htss-reconstruct`), get back the sealing key, and `Identity::import_sealed` the
  previously-sealed blob. This crate does not itself provide a single combined
  `export_sealed_with_recovery` convenience method today (see the STATUS note below); a
  caller composes the two documented primitives.

**Status of a combined recovery API.** A single method that seals an identity and splits
its sealing key in one call was proposed but is **not implemented** — closing this gap
today is docs-first: the ritual above is fully expressible with the primitives that already
ship (`export_sealed` + `SecretSharer::split_key_material`, and their inverses), so nothing
about "HTSS is a backup ritual, not a hosted service" depends on a new API landing. If a
combined convenience method is added later, it will be additive (a new WIT method on
`master-identity`, mirrored natively), not a replacement for the two-step composition
described here.

---

## 1. 5D Hypercube Topology

### 1.1 Graph Structure

Modeled as a graph, walked entirely in-process — not a diagram of a running network:

```
                    [ MODELED 5D HYPERCUBE GRAPH (Q_5) — local simulation ]
                          32 Vertex Nodes | 80 Edge Channels
   +------------------------------------------------------------------------------+
   |                  Source coordinate v_src ∈ {0,1}^5 (caller-supplied)         |
   |                  Secret scalar S, split into 5 Shamir shares                 |
   +------------------------------------------------------------------------------+
                                          |
                      [ Shamir Secret Sharing over F_q ]
                                          v
   +------------------------------------------------------------------------------+
   |       5 Orthogonal Route Streams (Dimension-Disjoint Paths Δ_0 ... Δ_4)      |
   +------------------------------------------------------------------------------+
        /          |          |          |          \
       v           v          v          v           v
   [Path 0]   [Path 1]   [Path 2]   [Path 3]   [Path 4]
   (Dim 0)    (Dim 1)    (Dim 2)    (Dim 3)    (Dim 4)
        \          |          |          |          /
         v         v          v          v         v
   +------------------------------------------------------------------------------+
   |               Destination coordinate v_dst ∈ {0,1}^5 (caller-supplied)       |
   |               Reconstructs S from any 3 of the 5 delivered shares            |
   +------------------------------------------------------------------------------+
```

### 1.2 Node Addressing

- **Total Nodes**: 2^5 = **32 nodes**
- **Total Edges**: 5 × 2^4 = **80 edge channels**
- **Node Address**: 5-bit binary coordinate **v ∈ {0,1}^5**
- **Neighbor Relation**: Nodes **u** and **v** are neighbors iff **Hamming(u, v) = 1** (differ in exactly one bit)
- **Maximum Distance**: 5 hops (from node 0b00000 to node 0b11111)

### 1.3 Dimension-Disjoint Routing

For a source node **v_src** and destination node **v_dst**, the **5 orthogonal dimension-disjoint paths** are constructed by permuting the order in which differing dimensions are traversed:

```
Path i: Traverse dimensions in order (d_start + i) mod 5, (d_start + i + 1) mod 5, ...
```

Each path traverses the same set of dimensions but in a different order, ensuring:
1. No two paths share an intermediate node (dimension-disjoint property)
2. Each path has length equal to the Hamming distance between source and destination
3. The union of all 5 paths covers all 5 dimensions exactly once per path

---

## 2. Shamir 3-of-5 Threshold Scheme

### 2.1 Secret Splitting

The ZK proof payload scalar **S** is split into **n = 5** shares using a **k = 3** threshold Shamir secret sharing scheme over **F_q** (MODULUS_Q = 8,380,417):

```
Algorithm SplitSecret(S, k=3, n=5, rng):
  Input:  Secret scalar S ∈ F_q
          Threshold k = 3
          Total shares n = 5
          Randomness source rng
  Output: Shares {(x_i, y_i)} for i = 1..n

  1. Construct random polynomial of degree k-1:
     f(x) = S + a_1·x + a_2·x^2  (mod q)
     where a_1, a_2 ← F_q uniformly at random

  2. Evaluate at n distinct points:
     For x = 1, 2, ..., n:
       y_x = f(x) = S + a_1·x + a_2·x^2  (mod q)

  3. Return shares: {(1, y_1), (2, y_2), (3, y_3), (4, y_4), (5, y_5)}
```

### 2.2 Secret Reconstruction

Given any **k = 3** shares **{(x_i, y_i)}**, reconstruct the secret using Lagrange interpolation:

```
Algorithm ReconstructSecret(shares):
  Input:  k shares {(x_i, y_i)} for i = 1..k
  Output: Secret scalar S ∈ F_q

  S = ∑_{i=1}^{k} y_i · L_i(0)  (mod q)

  where L_i(0) = ∏_{j≠i} (-x_j) / (x_i - x_j)  (mod q)
              = ∏_{j≠i} (q - x_j) · ModInverse(x_i - x_j, q)  (mod q)
```

### 2.3 Security Property

Any **k-1 = 2** or fewer shares reveal **zero information** about the secret **S** under the information-theoretic security of Shamir's scheme over **F_q**.

---

## 3. Illustrative Integration: Splitting a PLP Proof Payload

> Not shipped as-is. The real `SecretSharer::split_secret` takes an already-reduced `u64`
> scalar, not a `ZkIdentityProof` struct — it doesn't hash or serialize a proof itself. This
> section illustrates one way a caller *could* feed a PLP proof (`W`, `c`, `z` — see
> `plp::ZkIdentityProof`) into HTSS, not something `htss.rs` does on its own.

### 3.1 Payload Structure

A `ZkIdentityProof` consists of:

| Field | Type | Description |
|-------|------|-------------|
| W | Polynomial commitment | Commitment matrix W = A_τ · y |
| c | Challenge polynomial | Fiat-Shamir challenge c ∈ {-1,0,1}^N |
| z | Response vector | Response z = y + c·s ∈ R_q^k |

### 3.2 Payload Splitting

The proof payload could be serialized to a scalar representation and split:

```
Algorithm SplitProofPayload(π, rng):
  Input:  ZK proof π = (W, c, z)
          Randomness source rng
  Output: 5 proof segments {seg_i}

  1. Serialize π to canonical byte representation
  2. Compute payload hash: H = SHA3-256(π_bytes)
  3. Treat H as scalar S ∈ F_q (reduced mod q)
  4. Split S into 5 shares: {(i, y_i)} ← SplitSecret(S, k=3, n=5, rng)
  5. For each share i:
     path_tag_i = SHA3-256(v_src ∥ v_dst ∥ i)
     seg_i = ZkProofSegment { share_id: i, share_val: y_i, path_tag: path_tag_i }
  6. Return {seg_1, seg_2, seg_3, seg_4, seg_5}
```

### 3.3 Packet Structure

Each routed packet carries one proof segment:

```rust
pub struct ZkProofSegment {
    pub share_id: u8,       // Share index (1..=5)
    pub share_val: u64,     // Shamir share value y_i ∈ F_q
    pub path_tag: [u8; 32], // SHA3-256 path authentication tag
}

pub struct HypercubePacket {
    pub source: NodeAddress,          // Source node v_src ∈ {0,1}^5
    pub destination: NodeAddress,     // Destination node v_dst ∈ {0,1}^5
    pub current_node: NodeAddress,    // Current routing position
    pub dimension_route: Vec<usize>,  // Ordered list of dimensions to traverse
    pub route_index: usize,           // Current position in dimension_route
    pub payload: ZkProofSegment,      // Carried proof segment
}
```

---

## 4. Dimension-Disjoint Routing Algorithm

### 4.1 Path Computation

```
Algorithm ComputeOrthogonalPaths(v_src, v_dst):
  Input:  Source node v_src ∈ {0,1}^5
          Destination node v_dst ∈ {0,1}^5
  Output: 5 dimension orderings {path_0, ..., path_4}

  For d_start = 0, 1, 2, 3, 4:
    path_{d_start} = [(d_start + i) mod 5 for i in 0..5]

  Return {path_0, path_1, path_2, path_3, path_4}
```

### 4.2 Packet Routing

```
Algorithm RoutePacket(packet):
  Input:  HypercubePacket with dimension_route and current_node
  Output: Delivered packet at destination

  While packet.current_node ≠ packet.destination:
    next_dim = packet.dimension_route[packet.route_index]
    next_node = packet.current_node XOR (1 << next_dim)
    packet.current_node = next_node
    packet.route_index += 1

  Return packet
```

### 4.3 Full Routing Execution

```
Algorithm RoutePayloadShares(v_src, v_dst, shares):
  Input:  Source node v_src
          Destination node v_dst
          5 Shamir shares {(i, y_i)}
  Output: 5 delivered packets at v_dst

  routes = ComputeOrthogonalPaths(v_src, v_dst)

  For each share (i, y_i):
    route_dims = routes[i mod 5]
    path_tag = SHA3-256(v_src ∥ v_dst ∥ i)
    packet = HypercubePacket {
      source: v_src, destination: v_dst, current_node: v_src,
      dimension_route: route_dims, route_index: 0,
      payload: ZkProofSegment { share_id: i, share_val: y_i, path_tag }
    }
    delivered_packets.push(RoutePacket(packet))

  Return delivered_packets
```

---

## 5. Properties — Real vs. Aspirational

### 5.1 What's actually true today (local simulation)

- **Threshold reconstruction**: any 3 of the 5 Shamir shares reconstruct the secret; fewer than
  3 reveal nothing about it. This is standard, information-theoretic Shamir sharing over `F_q` —
  see §2.3 above.
- **Dimension-disjoint path assignment**: the 5 simulated routes computed by
  `compute_orthogonal_paths` share no intermediate graph node with each other, by construction.
  This is a property of the modeled graph, not a live security boundary.

### 5.2 Aspirational — design targets for a future distributed deployment

- **Metadata protection**: the idea that "no individual path carries the complete proof, so an
  eavesdropper controlling a subset of paths gains zero information" is a genuine property of
  the *threshold scheme* (§2.3), but calling it "eavesdropper resistance" implies a real channel
  someone could eavesdrop on, which doesn't exist here.
- **Node/path fault tolerance**: see §6 below.

---

## 6. Fault Tolerance — Aspirational Targets for a Future Distributed Deployment

> The properties below describe what a real distributed deployment of this routing model
> *should* guarantee, not what the current local, in-process code provides — there is no
> network, so nothing can currently fail, be blocked, or be adversarially controlled. Kept as a
> stated design target rather than deleted, per the sequencing note at the top of this document.

- **Node Failure Tolerance (target)**: up to **n - k = 2** nodes failing should not affect reconstruction.
- **Path Failure Tolerance (target)**: up to **2** of the 5 dimension-disjoint paths being blocked should not affect delivery.
- **Adversarial Node Tolerance (target)**: an adversary controlling up to **k-1 = 2** nodes should learn zero information about the payload.

These follow directly from the Shamir 3-of-5 threshold already implemented (§2) once real
transport and real node failure exist to reason about — they are not new cryptographic claims.

---

## 7. Implementation Notes

### 7.1 Node Address Operations

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeAddress(pub u8);

impl NodeAddress {
    /// Get the neighbor in dimension `dim` (flip bit `dim`)
    pub fn neighbor(&self, dim: usize) -> Self {
        NodeAddress(self.0 ^ (1 << dim))
    }

    /// Compute Hamming distance to another node
    pub fn hamming_distance(&self, other: &Self) -> usize {
        (self.0 ^ other.0).count_ones() as usize
    }
}
```

### 7.2 Modular Inverse for Lagrange Interpolation

```rust
fn mod_inverse(a: i64, m: i64) -> i64 {
    let mut t = 0i64; let mut newt = 1i64;
    let mut r = m; let mut newr = a % m;
    while newr != 0 {
        let quotient = r / newr;
        let temp_t = t - quotient * newt; t = newt; newt = temp_t;
        let temp_r = r - quotient * newr; r = newr; newr = temp_r;
    }
    if r > 1 { return 0; }
    if t < 0 { t += m; }
    t
}
```

### 7.3 Path Authentication

Each packet carries a **path_tag** computed as:
```
path_tag_i = SHA3-256(v_src ∥ v_dst ∥ share_id)
```

This allows the verifier to authenticate that each received packet originated from the correct source and was routed along the expected path.

---

## References

- Shamir, A.: "How to Share a Secret." Communications of the ACM, 1979.
- Leighton, F.T.: "Introduction to Parallel Algorithms and Architectures: Arrays, Trees, Hypercubes." Morgan Kaufmann, 1992.
