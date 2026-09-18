//! The SAAP spec's status note and its section labels must agree.
//!
//! `docs/SAAP-SPEC.md` opens with a note listing which sections are implemented
//! and which are not, and each section carries its own status line. They drifted
//! apart once (C2-01): four sections were labelled **Implemented** while the note
//! still listed them as not implemented, so a reader who trusted the nearer label
//! read a specification for something that did not exist. This test fails
//! whenever the two disagree, in either direction.
//!
//! The convention it enforces:
//!
//! - The note has one line per status, `> - Implemented: §2, §5, ...`, and the
//!   same for `Not implemented`, `Aspirational` and `Out of scope`.
//! - A section's own status line starts with `**Implemented**`, and appears
//!   before that section's first sub-heading.

const SPEC: &str = include_str!("../docs/SAAP-SPEC.md");

/// Section numbers the note lists after `label:`, without the `§`.
fn listed(doc: &str, label: &str) -> Vec<String> {
    let prefix = format!("> - {label}:");
    doc.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|rest| {
            rest.split(',')
                .map(|s| s.trim().trim_start_matches('§').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The section number a heading line introduces, e.g. "4.1" for
/// "### 4.1 Issuer Signature" or "5" for "## 5. Issue Algorithm".
fn heading_number(line: &str) -> Option<String> {
    let rest = line.strip_prefix('#')?.trim_start_matches('#').trim_start();
    let token = rest.split_whitespace().next()?.trim_end_matches('.');
    let numeric = !token.is_empty() && token.chars().all(|c| c.is_ascii_digit() || c == '.');
    numeric.then(|| token.to_string())
}

/// Each numbered section with its own body: the lines after its heading, up to
/// the next heading of any level.
fn sections(doc: &str) -> Vec<(String, Vec<&str>)> {
    let mut out: Vec<(String, Vec<&str>)> = Vec::new();
    let mut current: Option<(String, Vec<&str>)> = None;
    for line in doc.lines() {
        if line.starts_with('#') {
            if let Some(done) = current.take() {
                out.push(done);
            }
            current = heading_number(line).map(|n| (n, Vec::new()));
        } else if let Some((_, body)) = current.as_mut() {
            body.push(line);
        }
    }
    out.extend(current);
    out
}

fn labelled_implemented(body: &[&str]) -> bool {
    body.iter().any(|line| line.trim_start().starts_with("**Implemented**"))
}

/// Every way the note and the labels disagree. Empty means they agree.
fn problems(doc: &str) -> Vec<String> {
    let sections = sections(doc);
    let body_of = |n: &str| sections.iter().find(|(num, _)| num == n).map(|(_, b)| b);
    let implemented = listed(doc, "Implemented");
    let mut out = Vec::new();

    if implemented.is_empty() {
        out.push("the note has no `> - Implemented:` line".to_string());
    }
    for label in ["Implemented", "Not implemented", "Aspirational", "Out of scope"] {
        for n in listed(doc, label) {
            match body_of(&n) {
                None => out.push(format!("the note lists §{n} as {label}, but there is no §{n}")),
                Some(body) if label == "Implemented" && !labelled_implemented(body) => out.push(
                    format!("the note lists §{n} as Implemented, but §{n} has no **Implemented** line"),
                ),
                Some(body) if label != "Implemented" && labelled_implemented(body) => out.push(
                    format!("the note lists §{n} as {label}, but §{n} is labelled **Implemented**"),
                ),
                Some(_) => {}
            }
        }
    }
    for (n, body) in &sections {
        if labelled_implemented(body) && !implemented.contains(n) {
            out.push(format!("§{n} is labelled **Implemented**, but the note does not list it"));
        }
    }
    out
}

#[test]
fn the_spec_status_note_and_section_labels_agree() {
    let found = problems(SPEC);
    assert!(
        found.is_empty(),
        "docs/SAAP-SPEC.md disagrees with itself:\n  {}",
        found.join("\n  ")
    );
}

/// Negative control, and the exact defect C2-01 fixed: a section the note lists
/// as not implemented, labelled Implemented anyway.
#[test]
fn the_check_catches_a_not_implemented_section_labelled_implemented() {
    let planted = "> - Implemented: §1\n> - Not implemented: §2\n\n\
                   ## 1. One\n\n**Implemented** here.\n\n\
                   ## 2. Two\n\n**Implemented** here too.\n";
    let found = problems(planted);
    assert!(
        found.iter().any(|p| p.contains("§2 as Not implemented")),
        "the contradiction was not reported: {found:?}"
    );
}

/// Negative control for the other direction: a section labelled Implemented
/// that the note never mentions.
#[test]
fn the_check_catches_an_implemented_label_the_note_does_not_list() {
    let planted = "> - Implemented: §1\n\n## 1. One\n\n**Implemented** here.\n\n\
                   ## 2. Two\n\n**Implemented** here too.\n";
    let found = problems(planted);
    assert!(
        found.iter().any(|p| p.contains("§2 is labelled **Implemented**, but the note does not list it")),
        "the unlisted label was not reported: {found:?}"
    );
}

/// Positive control: a note and labels that agree produce no problems, so the
/// real test above can pass for the right reason.
#[test]
fn the_check_passes_a_consistent_document() {
    let planted = "> - Implemented: §1\n> - Not implemented: §2\n\n\
                   ## 1. One\n\n**Implemented** here.\n\n\
                   ## 2. Two\n\n**Not implemented.**\n";
    assert!(problems(planted).is_empty(), "{:?}", problems(planted));
}
