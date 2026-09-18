//! Native cost of the SAAP verifier, for comparison against the same
//! operations through the WebAssembly component (spec Q3).
//!
//! The SDK benchmark shows verify_presentation costing ~297ms end to end, of
//! which ~231ms is wasmtime instantiation. This measures the same cryptographic
//! work compiled natively, so the residual can be attributed either to the
//! lattice arithmetic itself or to the wasm execution penalty.
//!
//!   cargo run --release --example bench_native

use aethel_core::credential::{
    prove, verify, BlindedCredential, Credential, IssuerParams,
};
use aethel_core::plp::MasterIdentity;
use std::time::Instant;

const ISSUER_SEED: &[u8] = b"the issuer's secret seed, 32 byte";
const ISSUE_R: &[u8] = b"issuance randomness, 32 bytes ok";
const BLIND_R: &[u8] = b"blinding randomness, 32 bytes ok";
const PRES_R: &[u8] = b"presentation randomness, 32 byte";
const RHO: &[u8] = b"projection randomness, 32 bytes!";
const TAU: &[u8] = b"checkout-session";

fn bench<F: FnMut()>(label: &str, iters: usize, mut f: F) {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let per = start.elapsed() / iters as u32;
    println!("{label:<40} {per:>12.3?}  (n={iters})");
}

fn main() {
    println!("\naethel-core native cost (no wasm)");
    println!("{}", "=".repeat(60));
    if cfg!(debug_assertions) {
        println!("WARNING: debug build, use --release\n");
    }

    let params = IssuerParams::from_seed(ISSUER_SEED).expect("issuer params");
    let id = MasterIdentity::from_seed(&[0x42u8; 32]);
    let attrs = [3u64, 19_900_101, 0, 0, 0, 0, 0, 0];

    let cred = Credential::issue(&params, &id, &attrs, ISSUE_R).expect("issue");
    let blinded = BlindedCredential::new(&params, &cred, BLIND_R).expect("blind");
    let proj = id.project_at_context(TAU, RHO);

    let p = prove(&params, &blinded, &id, &proj, TAU, RHO, 0b0000_0001, PRES_R).expect("prove");
    assert!(
        verify(&params, &p, blinded.commitment(), &proj, TAU).expect("verify"),
        "fixture does not verify, benchmark is meaningless"
    );

    println!("-- verifier --");
    bench("credential::verify  (SAAP verify)", 50, || {
        let ok = verify(&params, &p, blinded.commitment(), &proj, TAU).expect("verify");
        assert!(ok);
    });

    println!("\n-- prover --");
    bench("credential::prove   (present)", 50, || {
        let _ = prove(&params, &blinded, &id, &proj, TAU, RHO, 0b0000_0001, PRES_R).expect("prove");
    });

    println!("\n-- setup --");
    bench("Credential::issue", 50, || {
        let _ = Credential::issue(&params, &id, &attrs, ISSUE_R).expect("issue");
    });
    bench("project_at_context", 50, || {
        let _ = id.project_at_context(TAU, RHO);
    });

    // Issuance still expands B_1 from the seed on every call through the
    // component, because `credential.issue` carries the seed and keeps nothing
    // between calls. Verification no longer does: it takes a prepared
    // `issuer-public-parameters` resource, so a verifier pays the expansion once
    // when it derives or deserialises its parameters and never again. B_1 is
    // CRED_T x CRED_L = 13 x 4 = 52 polynomials, 52 KB, expanded via SHAKE-256,
    // which is why the two are worth timing separately.
    println!("
-- issuer matrix expansion --");
    bench("IssuerParams::from_seed (52 KB, once per verifier)", 50, || {
        let _ = IssuerParams::from_seed(ISSUER_SEED).expect("issuer params");
    });
    bench("verify with prepared params", 50, || {
        let ok = verify(&params, &p, blinded.commitment(), &proj, TAU).expect("verify");
        assert!(ok);
    });
    bench("issue INCLUDING from_seed", 50, || {
        let fresh = IssuerParams::from_seed(ISSUER_SEED).expect("issuer params");
        let _ = Credential::issue(&fresh, &id, &attrs, ISSUE_R).expect("issue");
    });

    println!("{}", "=".repeat(60));
}
