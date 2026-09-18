//! Present a PLP identity to a verifier, end to end (A-1).
//!
//! Load or create an `Identity`, derive a one-time PLP projection and proof
//! for a verifier-supplied context, sign the verifier's attach challenge
//! under a purpose-separated context, and verify everything on the other
//! side using only bytes. No network access; run with:
//!
//! ```bash
//! cargo run --example present_to_verifier
//! ```

use aethel_core::signing::{purpose, verify_with_purpose, Identity};
use aethel_core::wire;
use rand::RngCore;

fn main() {
    // 1. Load or create the agent's identity. A real agent seals this to
    //    disk with `Identity::export_sealed`/`import_sealed`; this demo
    //    generates fresh entropy each run instead.
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let id = Identity::generate(&entropy).expect("generate identity");

    // 2. One-time projection for this verifier session: `tau` is the
    //    verifier's context, `rho` is fresh secret randomness.
    let tau = b"verifier-session-2026-09-10";
    let mut rho = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rho);
    let projection = id.project_at_context(tau, &rho).expect("project");
    let proof = id.prove(tau, &rho).expect("prove");

    // 3. What goes on the wire: versioned `aethel-plp-1` envelopes, plus the
    //    public key.
    let projection_bytes = wire::encode_projection(&projection);
    let proof_bytes = wire::encode_proof(&proof);
    let public_key = id.public_key();

    // 4. Sign the verifier's attach challenge under the PLP-presentation
    //    purpose (see `docs/PURPOSES.md`) — never under a different purpose.
    let challenge = b"attach-challenge-supplied-by-the-verifier";
    let signature = id
        .sign_with_purpose(purpose::PLP_PRESENT_V1, challenge)
        .expect("sign");

    // 5. Verifier side, from bytes only.
    let verified = wire::verify_projection(&projection_bytes, &proof_bytes, tau)
        .expect("verify_projection: undecodable input");
    let signature_ok =
        verify_with_purpose(&public_key, purpose::PLP_PRESENT_V1, challenge, &signature)
            .expect("verify_with_purpose: undecodable input");

    assert!(verified, "an honest projection/proof pair failed to verify");
    assert!(
        signature_ok,
        "an honest purpose-separated signature failed to verify"
    );

    // identity_id = SHA3-256(projection_bytes) — counts projections, not
    // people (KPI-001). Left as an exercise: `sha3::Shake256`/`Sha3_256` is
    // already a dependency of this crate.
    println!(
        "presented and verified: projection {} bytes, proof {} bytes, signature {} bytes",
        projection_bytes.len(),
        proof_bytes.len(),
        signature.len()
    );
}
