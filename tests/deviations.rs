//! The deviation register is only useful if it is where people look (C2-02).
//!
//! Before `docs/DEVIATIONS.md` existed, the one worked-out deviation in this
//! crate lived in a source comment, the last place a specification auditor
//! looks, and each disagreement between the crate and its specifications was
//! rediscovered by whoever next read both. These tests keep the register linked
//! from where readers start, keep its row IDs usable as references, and make any
//! deviation explained in source point back to its row.

use std::fs;
use std::path::Path;

const REGISTER: &str = include_str!("../docs/DEVIATIONS.md");
const SPEC: &str = include_str!("../docs/SAAP-SPEC.md");
const README: &str = include_str!("../README.md");
const CONTRIBUTING: &str = include_str!("../CONTRIBUTING.md");

/// The row IDs in the register's tables, in order of appearance.
fn register_ids() -> Vec<&'static str> {
    REGISTER
        .lines()
        .filter_map(|line| line.strip_prefix("| "))
        .filter_map(|rest| rest.split(" |").next())
        .map(str::trim)
        .filter(|id| id.starts_with("D-") || id.starts_with("R-"))
        .collect()
}

#[test]
fn the_register_is_linked_from_where_readers_start() {
    assert!(SPEC.contains("DEVIATIONS.md"), "docs/SAAP-SPEC.md does not link the register");
    assert!(README.contains("docs/DEVIATIONS.md"), "README.md does not link the register");
    assert!(
        CONTRIBUTING.contains("docs/DEVIATIONS.md"),
        "CONTRIBUTING.md does not state the same-PR rule for the register"
    );
}

/// Row IDs are how source comments, the spec and the README point into the
/// register, so each must name exactly one row.
#[test]
fn register_row_ids_are_unique() {
    let ids = register_ids();
    assert!(!ids.is_empty(), "no D- or R- rows found; the table format changed");
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "duplicate register id among {ids:?}");
}

/// The register keeps deviations closed on purpose, not only open ones, so a
/// later reader does not reopen them. At least the two named in C2-02 AC3 must
/// be there.
#[test]
fn the_register_keeps_the_deviations_closed_on_purpose() {
    let closed = REGISTER
        .split("## Closed")
        .nth(1)
        .expect("the register has no Closed section");
    for topic in ["Predicate proofs", "WASM memory bounds"] {
        assert!(closed.contains(topic), "the Closed section does not record {topic}");
    }
}

/// A deviation explained at the point of use in source has to name its row, so
/// the explanation and the register cannot drift apart.
#[test]
fn every_deviation_explained_in_source_points_at_the_register() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut missing = Vec::new();
    for entry in fs::read_dir(&src).expect("read src/") {
        let path = entry.expect("dir entry").path();
        if path.extension().map_or(true, |ext| ext != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source file");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("# Deviation from") {
                let window = &lines[i..lines.len().min(i + 6)];
                if !window.iter().any(|l| l.contains("docs/DEVIATIONS.md")) {
                    missing.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these deviation sections do not name their register row: {missing:?}"
    );
}
