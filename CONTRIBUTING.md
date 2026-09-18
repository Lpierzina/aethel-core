# Contributing to aethel-core

## Current posture: not taking external PRs yet

This project is implemented and maintained by a single named maintainer (Ed Johnson), not a
team with a review pipeline built for external contributions. That means:

- **Issues are welcome** — bug reports, questions, and feature requests. They're read and
  triaged on a best-effort basis.
- **External pull requests are not being merged right now.** Not because contributions aren't
  wanted long-term, but because there's no review capacity to do them justice yet. Opening one
  won't get an insulting silence, but expect it to sit until capacity exists, or to be closed
  with a note rather than merged.
- If you want to contribute code, **open an issue first** to discuss the change before writing
  it. That avoids spending your time on something that can't be reviewed or merged in a
  reasonable window.

This posture is stated here because pretending otherwise wastes contributors' time. It will be
revised, and this file updated, if and when that capacity changes.

## Development

```bash
cargo build
cargo test
```

See [`README.md`](./README.md) for the full build matrix (WASM target, `puf` feature, etc.)
and what's covered by the test suite.

## Deviating from a specification

This crate implements `AETHEL-SPEC-001` and [`docs/SAAP-SPEC.md`](./docs/SAAP-SPEC.md), and it
does not always agree with them. Every disagreement lives in
[`docs/DEVIATIONS.md`](./docs/DEVIATIONS.md): what the specification says, what the crate does,
which one wins, and who owns it.

**A change that makes the crate deviate from a specification adds its register row in the same
pull request.** That applies whether the deviation is a fix to a specification defect or a
decision to depart from it. A deviation found after merge is a defect in this process, not
only in the code.

- If the deviation is explained in a source comment headed `# Deviation from ...`, that comment
  names its register row. `tests/deviations.rs` fails if it does not.
- Deviations that are resolved with no action stay in the register, under **Closed**, with the
  reason. A register that only lists open problems teaches the next reader to reopen the
  closed ones.
