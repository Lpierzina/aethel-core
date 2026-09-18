# Predicate proofs over hidden attributes

Status: **not implemented, and not implementable in this protocol**. This states
what a predicate proof would have to establish, why the design sketched in
`SAAP-SPEC.md` §9.3 cannot establish it, and what the two real options are.

Read this alongside §9.3, which scopes the relation out, and alongside
`ISSUER-AUTHENTICATION.md`, which reaches the same conclusion about a different
relation for the same underlying reason.

## The claim a predicate proof has to support

A holder commits an attribute, say a date of birth or a spend limit, and later
convinces a verifier that the hidden value satisfies a threshold, without
revealing the value. `attr >= T`.

Selective disclosure of a whole attribute already works, and is exact. What
follows is only about the hidden case.

## Why the sketched design does not work

§9.3 proposes decomposing the difference into bits and proving each bit is
binary:

```
m_age - 21 = sum_k b_k * 2^k     with b_k in {0,1}
```

Three independent problems. Any one of them is fatal on its own.

### 1. Bit-ness is a quadratic constraint

`b in {0,1}` is `b * (b - 1) = 0`. The shipped proof is a linear sigma protocol
over `R_q`: every relation it checks is linear in the witness. There is no
linear way to express a quadratic constraint, and no choice of parameters
changes that. Expressing it needs a product argument, which is a different proof
system rather than another relation inside this one.

The obvious escape, checking that a response is small instead of proving
bit-ness, does not work either. Attribute masks are drawn uniformly over `R_q`
precisely so that they hide values that are not short, as §6.2 explains. A
uniformly masked response carries no information about the norm of what it
masks. Making the mask short so that a norm check means something would stop it
hiding the attribute. The two requirements are in direct opposition on the same
slot.

### 2. The verification relation only holds modulo q

The verifier checks a `Z_q`-linear identity over the limb decomposition. With
`q` near `2^23` and attribute values spanning 64 bits, the map from limb tuples
to `Z_q` is many-to-one by a wide margin, so a great many limb tuples satisfy
the identity for any given claimed value. A value just below the threshold has a
representation whose limbs are all non-negative and all inside their bound.

Both natural repairs, bounding the top limb and decomposing the complement as
well, are arguments about integers. They do not survive reduction modulo `q`. A
`Z_q`-linear statement about a quantity larger than `q/2` carries no information
about the integer it is supposed to describe. That is the same fact that forced
the four-limb encoding in `encode_attribute` in the first place, and it applies
equally to a bit decomposition.

### 3. Shortness of a response does not bound the witness

This is the deepest of the three, and it is a property of sigma protocols with
ring challenges rather than a flaw in any particular construction.

What two accepting transcripts yield is a bound on `c * w`, where `c` is the
difference of two challenges. They yield no bound on `w`. There exist witnesses
whose coefficients are as large as the ring allows but whose product with every
challenge is small, because the challenge coefficients cancel. A prover holding
such a witness masks it honestly, passes every norm check, and has proved
nothing about the value.

This is the standard relaxed opening. It is exactly what BDLOP binding is proved
under, and it is entirely adequate for the two relations that are built. It
cannot express a range.

Moving to a challenge space with small inverses, binary or monomial challenges,
makes extraction exact and kills this objection. It replaces it with another:
soundness then needs many parallel repetitions under one transcript, the
per-repetition acceptance rate has to be very close to one for the whole proof
to survive, and the mask must therefore be enormous relative to the range. The
bound that comes out is looser than the threshold by a large multiple of the
range width. That is not a threshold.

## What a passing proof does establish

Stated exactly, so it can be quoted rather than paraphrased.

Two accepting transcripts yield a challenge difference `c` and witnesses
`r, s, e, m` satisfying the verification relations, with

```
||r_i||inf, ||s||inf, ||e||inf  <  2 * (gamma1 - beta)
```

where the extracted witnesses are `c` times the real ones. Nothing bounds the
real `r*`, `s`, `e`, or any attribute value. A passing proof establishes that
the blinded commitment opens, in the relaxed sense, to some polynomial in each
slot. **It establishes no bound on any hidden attribute.**

## The two real options

### Issuer-attested predicate flags

The issuer commits a boolean or a bucket index in its own slot: `age >= 18`,
`limit >= 1000`. Showing one is disclosure, which is exact and linear and
already works.

Cost is one slot per flag, and the honest product claim is "thresholds the
issuer chose to attest", not "range proof". Note that this option depends on
issuance being unforgeable, which it is not today; see
`ISSUER-AUTHENTICATION.md`. A flag a holder can mint for themselves attests
nothing.

### Exact range proofs over a product-capable proof system

Bit decomposition plus a product argument, in the ENS20 or LNP22 line. This is
the real answer and it is a proof system, not a relation. It needs a partially
splitting modulus, since a fully splitting `q` gives poor soundness for product
arguments, and `q = 8380417` splits completely. It needs a new challenge space
and garbage commitments. Published figures put it in the tens of kilobytes per
predicate.

It is the same machinery `ISSUER-AUTHENTICATION.md` needs. Those two gaps share
one dependency, and building it is a programme rather than a ticket.

## What is not an option

An approximate range proof with slack. For the reasons in section 3 there is no
honest version of one here, for an age check or for a spend limit. The slack is
not a tuning parameter that can be driven small; it is a constant multiple of
the range width, which is the quantity being bounded.
