# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## Known limitations

A cryptographic review of the identity and credential paths completed on 2026-09-08
found three properties this crate had described as stronger than the implementation
provided. They are recorded here rather than in a private tracker because the
affected code was published, and each entry says which releases it applies to. Two
are closed in `0.5.0`; one is open.

None of these are reports from a third party, and none are being withheld pending a
fix. The work to strengthen each is scoped and in progress.

### The projection ran below the module rank its specification requires

**Affects 0.4.0 and earlier. Fixed in 0.5.0.**

`AETHEL-SPEC-001` §3.2 sets a module rank of `k = 4` for the parameter profile this
crate targets, and §9.2 states that implementations must not reduce it below that.
In `0.4.0` `plp` operated at rank 1: the master secret, the context matrix and the
projection were each a single ring element rather than a rank-4 module. The
lattice-hardness argument written for rank 4 therefore did not apply to the shipped
code, and the margin protecting a master secret from the projections derived from it
was smaller than the specification's analysis assumes.

The identity path now runs at `k = 4` throughout, sourced from `plp::MODULE_K`. This
changes the wire encoding of every projection and proof, so anything produced by
`0.4.0` will not verify against the fix and cannot be migrated. Regenerate
identities rather than attempting to carry them forward.

### The credential commitment does not provide the hiding property claimed for it

**Open. Affects 0.4.0 and 0.5.0.**

`AETHEL-SPEC-001` §7 specifies the credential commitment matrix with a randomness
dimension smaller than its commitment dimension. A BDLOP commitment is hiding only
when that relationship runs the other way, so that the randomness term is
pseudorandom under Module-LWE. This crate implements the specified shape faithfully;
the shape itself is the defect.

Until the shape is corrected, treat a presentation as revealing the attribute values
it commits to, disclosed or not, and do not rely on two presentations of one
credential being unlinkable. The specification is being corrected before the
implementation follows it.

### The rejection-sampling bound was not derived from the challenge space

**Affects 0.4.0 and earlier. Fixed in 0.5.0.**

In `0.4.0` the challenge polynomial had 60 non-zero coefficients while `β = 78` is
the value corresponding to a challenge of weight 39. The rejection-sampling argument
requires `β` to be at least the largest coefficient of the challenge multiplied by
the witness, and at weight 60 it was not. Measured behaviour stayed far from the
bound, so the practical leakage was negligible, but the argument did not carry as
written and the extraction bounds stated for every other relation depend on the
true value.

The challenge weight is now 39, which makes `β = 78` and `γ₁ = 2^17` correct as
written and the parameter set exactly the profile the specification defines. The
relationship is asserted at compile time, so raising the weight without raising the
bound fails the build rather than silently invalidating the argument.

### What to do with this today

`aethel-core` is `0.x` and the README already says not to use it in production
without a formal audit. That guidance stands and these findings sharpen it.

The `plp` identity path now runs at its specified module rank with a rejection
bound derived from its challenge space. The credential path should still be treated
as pre-release: the commitment shape above is a defect in the specification, and
correcting the specification comes before changing the implementation to follow
it.
