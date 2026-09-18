# Issuer authentication

Status: **not implemented**. This states the gap precisely, says why the design
sketched in `OVERVIEW.md` cannot be built as written, and pins the construction
that closes it.

Read this alongside `issuer-public-parameters` in `wit/aethel-core.wit`, which
is the surface the gap shows up on.

## The gap

Issuance is a BDLOP commitment:

```
t_cred = B_1 · r + (0^L ‖ m)
```

where `m` carries the holder's master secret in slot 0 and the attribute values
in slots 1..8, `r` is short commitment randomness, and `B_1` is the issuer's
public matrix. Presentation blinds it, `t_blind = t_cred + B_1 · r_blind`, and
proves knowledge of a short `r*` and hidden messages opening `t_blind`, linked to
the holder's PLP projection by a shared witness.

Every input to that is available to the holder. `B_1` has to be, or the holder
could not blind. `m` is the holder's own secret plus the attribute values. `r` is
randomness the holder can sample. So a holder can construct a `t_cred` over their
own identity with attributes of their choosing, present it, and it verifies.

The verification relation establishes that a presentation opens to a short
preimage under `B_1` and belongs to the identity that made it. It does not
establish that an issuer authorised the attribute values, because nothing in the
relation is a function of an issuer secret.

What currently stands in for issuer authorisation is that the issuer seed is
secret and `credential.issue` demands it. That is an access-control property of
this component's API, not a cryptographic one: it binds an attacker who goes
through the world and not an attacker who reimplements four lines of module
arithmetic. It is worth having, and it is not unforgeability.

Splitting the public parameters out (P3-01) does not change this either way. It
narrows the blast radius on the verifier side, which was the acute problem: a
verifier no longer holds the issuing secret, so issuer and verifier can be
separate organisations and a verifier can be a public endpoint. Holders are
unchanged, and were never protected against.

## Why the sketched design does not work

`OVERVIEW.md` describes issuance as ending in an issuer ML-DSA signature
`σ_Issuer` over `t_cred`. That cannot be verified in this protocol.

The verifier never sees `t_cred`. It sees `t_blind`, a freshly re-randomised
commitment, and it sees it precisely because two showings of one credential must
not be linkable. Presenting `σ_Issuer` alongside would reinstate `t_cred` as a
static, credential-unique identifier carried in the clear on every showing. That
is the exact correlation handle selective disclosure exists to remove: every
verifier a holder ever presents to could link their showings to each other, and
collude to link them across verifiers.

So the signature cannot travel with the presentation, and the object it signs
cannot be shown. A signature that can be neither shown nor checked is not a
signature scheme.

## What closes it

A signature the holder proves knowledge of in zero knowledge, rather than one it
sends. This is the standard shape for an anonymous credential and the shape this
protocol was always going to need.

Concretely, a Boyen/ABB-style lattice signature, issued with a gadget trapdoor:

1. **Setup.** The issuer generates `B_1` together with a trapdoor `R` for it
   (Micciancio-Peikert: publish `B_1 = [Ā | G − ĀR]`, keep `R`). `B_1` remains
   the published parameter; the trapdoor becomes the issuer's actual secret, in
   place of today's seed. The published form stops being a 32-byte seed and
   becomes the matrix, because a trapdoored matrix is not the image of a public
   seed under a XOF, which is what makes the trapdoor a secret at all.
2. **Issuance.** The issuer samples a short `σ` satisfying a message-dependent
   relation `A_m · σ = u`, where `A_m` is built from `B_1` and the committed
   attributes. Producing a short preimage requires the trapdoor; SIS says nobody
   else can. This replaces "the holder commits and the issuer never participates"
   with an issuance the issuer must actually run.
3. **Presentation.** The holder proves, in zero knowledge, knowledge of a short
   `σ` satisfying that relation for the committed messages, alongside the two
   relations already proved. Nothing issuer-specific is revealed, so
   unlinkability survives.
4. **Verification.** Unchanged in shape: check the transcript against `B_1`. Now
   a passing transcript means an issuer holding the trapdoor participated.

## What that costs

This is not wiring, and it should not be attempted as an increment on the
current sigma protocol.

- **A trapdoor sampler.** Discrete Gaussian preimage sampling over a lattice
  with a gadget trapdoor. Getting the sampler's distribution wrong leaks the
  trapdoor, gradually and silently, exactly the failure mode this crate already
  wrote a rejection-sampling loop to avoid. It is not safe to hand-roll and it is
  not covered by the primitives currently vendored.
- **A ZK proof for a new relation.** The existing proof is a linear sigma
  protocol over fixed matrices. Proving knowledge of a signature adds a relation
  with a message-dependent matrix. Proof size and prover time both grow
  substantially.
- **A larger published parameter.** `B_1` at 52 KB travels to every verifier
  instead of 32 bytes, and can no longer be re-derived, so it must be
  distributed and pinned as a blob.
- **A breaking change to issuance.** `credential.issue` becomes a protocol
  between holder and issuer rather than a single local call, because the issuer
  has to run the sampler over the holder's committed messages.

## Why the signature cannot simply be proved in zero knowledge

The natural question is whether the holder can prove knowledge of an ML-DSA
signature over the commitment, rather than replacing the signature scheme. It
cannot, and the reason is structural rather than a matter of cost.

In ML-DSA the message binds to the signature only through the hash that produces
the challenge: `c = H(mu || w1)`. Every algebraic part of verification, the
matrix, the public key, the response, the challenge, and the norm check, is
independent of the message. So a proof that establishes knowledge of a short
`(z, c, w)` satisfying the verification equation is satisfied by **any**
signature the issuer ever produced, on any message. It cannot attest which
credential was signed, which is the entire content of the claim.

Binding the message means proving a SHAKE-256 evaluation in zero knowledge,
along with HighBits and the hint decomposition. That is a general-purpose proof
system over millions of constraints, with post-quantum proof sizes above 100 KB.
It is not a relation that can be added to this sigma protocol.

One consequence worth stating plainly, because it is easy to assume otherwise:
the issuer signature produced at issuance is useful to the **holder**, who
learns the credential came from the issuer and can refuse a malformed one. It
does nothing for the **verifier**, who never sees it. Adding the signature to
issuance does not move the unforgeability question at all.

## Until then

State the assumption rather than implying it is not there.

`aethel:core` as shipped is sound for deployments where the holder is not the
adversary for attribute values: attestations a holder makes about themselves,
identity linkage, unlinkable presentation of self-asserted attributes, and any
setting where the attribute values are corroborated outside this protocol. It is
not sound as a credential system where a holder benefits from lying about an
attribute and the verifier's only evidence is the presentation.

The WIT documentation on `issuer-public-parameters` says this at the point of
use, which is where someone about to make the wrong assumption will be looking.
