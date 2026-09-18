//! Shared `aethel-plp-1` test vectors (A-5 / X-4).
//!
//! Loads the checked-in hex vector files under `tests/vectors/aethel-plp-1/`
//! and asserts [`aethel_core::wire::verify_projection`] agrees with each
//! vector's recorded expected verdict. These are the *native* side of the
//! "shared vectors" story: [`tests/component_execution.rs`] drives the same
//! files through the WASM component's `plp-verify-bytes`, so a third party
//! (or another language SDK) has fixed bytes to check either runtime against
//! rather than only in-process agreement between them.
//!
//! # Regenerating
//!
//! Vectors are generated deterministically from fixed seeds by
//! `regenerate_vectors` below, which is `#[ignore]`d so a normal `cargo test`
//! run never silently rewrites them. Regenerate with:
//!
//! ```bash
//! cargo test --test plp_vectors -- --ignored regenerate_vectors
//! ```
//!
//! Never hand-edit a vector file: if the derivation changes, regenerate.

use aethel_core::signing::Identity;
use aethel_core::wire;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/aethel-plp-1")
}

/// One loaded vector: `aethel-plp-1` envelope bytes for a projection and a
/// proof, a context to verify against, and the expected verdict.
struct Vector {
    name: String,
    projection: Vec<u8>,
    proof: Vec<u8>,
    context: Vec<u8>,
    expected: bool,
}

/// Parse one `key=hex` (or `key=true`/`key=false`) per line. Plain text, not
/// JSON — `serde_json` is not a dependency of this crate (see A-5's proposed
/// fix), and `hex` already is, as a dev-dependency.
fn parse_vector(path: &std::path::Path) -> Vector {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read vector file {}: {e}", path.display()));

    let mut projection = None;
    let mut proof = None;
    let mut context = None;
    let mut expected = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{}: expected `key=value`, got {line:?}", path.display()));
        match key {
            "projection" => projection = Some(hex::decode(value).expect("hex-decode projection")),
            "proof" => proof = Some(hex::decode(value).expect("hex-decode proof")),
            "context" => context = Some(hex::decode(value).expect("hex-decode context")),
            "expected" => {
                expected = Some(match value {
                    "true" => true,
                    "false" => false,
                    other => panic!("{}: expected true/false, got {other:?}", path.display()),
                })
            }
            other => panic!("{}: unknown vector field {other:?}", path.display()),
        }
    }

    Vector {
        name: path.file_name().unwrap().to_string_lossy().into_owned(),
        projection: projection
            .unwrap_or_else(|| panic!("{}: missing `projection`", path.display())),
        proof: proof.unwrap_or_else(|| panic!("{}: missing `proof`", path.display())),
        context: context.unwrap_or_else(|| panic!("{}: missing `context`", path.display())),
        expected: expected.unwrap_or_else(|| panic!("{}: missing `expected`", path.display())),
    }
}

fn load_vectors() -> Vec<Vector> {
    let mut paths: Vec<_> = fs::read_dir(vectors_dir())
        .expect("read tests/vectors/aethel-plp-1 — did you run regenerate_vectors?")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false))
        .collect();
    // Deterministic iteration order so failures are reproducible run to run.
    paths.sort();
    paths.iter().map(|p| parse_vector(p)).collect()
}

/// The vector tests *are* the verification (A-5's own words): every checked
/// -in file must agree with `verify_projection` on its recorded verdict.
#[test]
fn all_vectors_match_their_expected_verdict() {
    let vectors = load_vectors();
    assert!(
        !vectors.is_empty(),
        "no vector files found under tests/vectors/aethel-plp-1 — \
         run `cargo test --test plp_vectors -- --ignored regenerate_vectors`"
    );

    let mut saw_valid = false;
    let mut saw_tampered_projection = false;
    let mut saw_tampered_proof = false;
    let mut saw_wrong_context = false;

    for v in &vectors {
        match wire::verify_projection(&v.projection, &v.proof, &v.context) {
            Ok(verdict) => assert_eq!(
                verdict, v.expected,
                "vector {}: expected {} but verify_projection returned {}",
                v.name, v.expected, verdict
            ),
            Err(e) => panic!("vector {} failed to decode at all: {e:?}", v.name),
        }

        if v.name.starts_with("valid") {
            saw_valid = true;
        } else if v.name.starts_with("tampered-projection") {
            saw_tampered_projection = true;
        } else if v.name.starts_with("tampered-proof") {
            saw_tampered_proof = true;
        } else if v.name.starts_with("wrong-context") {
            saw_wrong_context = true;
        }
    }

    assert!(saw_valid, "no valid vector present");
    assert!(
        saw_tampered_projection,
        "no tampered-projection vector present"
    );
    assert!(saw_tampered_proof, "no tampered-proof vector present");
    assert!(saw_wrong_context, "no wrong-context vector present");
}

/// Negative control: a loader that ignored the `expected` field entirely
/// would still pass the test above by coincidence (it would just be
/// asserting `verify_projection` against itself). Mutate a byte of a known
/// -valid vector's projection *after* loading and confirm the mismatch is
/// actually detected — proving the comparison above is load-bearing.
#[test]
fn a_mutated_vector_is_detected_as_a_mismatch() {
    let vectors = load_vectors();
    let valid = vectors
        .iter()
        .find(|v| v.expected)
        .expect("at least one valid vector must be present for this control");

    let mut mutated_projection = valid.projection.clone();
    let last = mutated_projection.len() - 1;
    mutated_projection[last] ^= 0xFF;

    match wire::verify_projection(&mutated_projection, &valid.proof, &valid.context) {
        Ok(verdict) => assert!(
            !verdict,
            "mutating one byte of a valid vector's projection did not change the verdict — \
             either the mutation missed every meaningful byte or the check is not decisive"
        ),
        Err(_) => {
            // A decode failure is also a valid detection of the mutation.
        }
    }
}

/// Regenerate every vector file from fixed seeds. `#[ignore]`d so this never
/// runs as part of a normal `cargo test`, and never hand-edit the output —
/// rerun this instead.
#[test]
#[ignore]
fn regenerate_vectors() {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("create tests/vectors/aethel-plp-1");

    // ── valid-1: a straightforward honest projection/proof pair ──────────
    let id1 = Identity::generate(&[0x51u8; 32]).expect("generate");
    let tau1: &[u8] = b"aethel-plp-1-vector-context-v1";
    let rho1 = [0x62u8; 32];
    let proj1 = id1.project_at_context(tau1, &rho1).expect("project");
    let proof1 = id1.prove(tau1, &rho1).expect("prove");
    let proj1_bytes = wire::encode_projection(&proj1);
    let proof1_bytes = wire::encode_proof(&proof1);
    write_vector(&dir, "valid-1.txt", &proj1_bytes, &proof1_bytes, tau1, true);

    // ── valid-2: a second, independent identity/context/randomness ───────
    let id2 = Identity::generate(&[0x73u8; 32]).expect("generate");
    let tau2: &[u8] = b"aethel-plp-1-vector-context-v2";
    let rho2 = [0x84u8; 32];
    let proj2 = id2.project_at_context(tau2, &rho2).expect("project");
    let proof2 = id2.prove(tau2, &rho2).expect("prove");
    let proj2_bytes = wire::encode_projection(&proj2);
    let proof2_bytes = wire::encode_proof(&proof2);
    write_vector(&dir, "valid-2.txt", &proj2_bytes, &proof2_bytes, tau2, true);

    // ── tampered-projection: flip the low byte of public_b's first
    // coefficient. The envelope header is 10 bytes (magic4+version1+kind1+
    // len4); the projection body is tau(32)‖salt(32)‖public_b, so byte 10+64
    // is the low byte of public_b's first u32 coefficient.
    let mut tampered_projection = proj1_bytes.clone();
    tampered_projection[10 + 64] ^= 0x01;
    assert!(
        wire::decode_projection(&tampered_projection).is_ok(),
        "tampered-projection vector must still decode (range check must not trip) — \
         pick a different offset if this fails"
    );
    write_vector(
        &dir,
        "tampered-projection.txt",
        &tampered_projection,
        &proof1_bytes,
        tau1,
        false,
    );

    // ── tampered-proof: flip the low byte of commitment_w's first
    // coefficient (the first byte of the proof envelope's body).
    let mut tampered_proof = proof1_bytes.clone();
    tampered_proof[10] ^= 0x01;
    assert!(
        wire::decode_proof(&tampered_proof).is_ok(),
        "tampered-proof vector must still decode (range check must not trip) — \
         pick a different offset if this fails"
    );
    write_vector(
        &dir,
        "tampered-proof.txt",
        &proj1_bytes,
        &tampered_proof,
        tau1,
        false,
    );

    // ── wrong-context: the honest pair, verified against a context nobody
    // ever projected at.
    write_vector(
        &dir,
        "wrong-context.txt",
        &proj1_bytes,
        &proof1_bytes,
        b"a-context-nobody-used",
        false,
    );

    // Sanity: every file this function just wrote must load back and agree
    // with itself before we call the run done.
    for v in load_vectors() {
        let got = wire::verify_projection(&v.projection, &v.proof, &v.context);
        assert_eq!(
            got,
            Ok(v.expected),
            "freshly written vector {} disagrees with itself",
            v.name
        );
    }
}

fn write_vector(
    dir: &std::path::Path,
    name: &str,
    projection: &[u8],
    proof: &[u8],
    context: &[u8],
    expected: bool,
) {
    let content = format!(
        "projection={}\nproof={}\ncontext={}\nexpected={}\n",
        hex::encode(projection),
        hex::encode(proof),
        hex::encode(context),
        expected,
    );
    fs::write(dir.join(name), content)
        .unwrap_or_else(|e| panic!("write {}: {e}", dir.join(name).display()));
}
