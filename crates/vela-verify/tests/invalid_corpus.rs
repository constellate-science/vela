//! The mutation corpus: a verifier that cannot REJECT known-invalid
//! witnesses is a rubber stamp (the SWE-bench Verified lesson — 59.4%
//! of audited tasks had tests that pass wrong solutions). Every file in
//! corpus/invalid/ must fail verification; a corpus entry that PASSES
//! is a CI failure demanding a verifier fix or corpus correction.

use std::fs;
use std::path::PathBuf;

#[test]
fn every_invalid_witness_is_rejected() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/invalid");
    let mut checked = 0usize;
    let mut wrongly_accepted = Vec::new();
    for entry in fs::read_dir(&dir).expect("corpus/invalid must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        // Parse failures count as rejection (the witness can't even
        // enter the verifier) — recorded the same way.
        let witness: Result<vela_verify::Witness, _> = serde_json::from_str(&raw);
        match witness {
            Err(_) => {
                checked += 1;
            }
            Ok(w) => {
                checked += 1;
                let r = vela_verify::verify_witness(&w);
                if r.ok {
                    wrongly_accepted.push(format!(
                        "{}: ACCEPTED ({})",
                        path.file_name().unwrap().to_string_lossy(),
                        r.message
                    ));
                }
            }
        }
    }
    assert!(checked >= 10, "corpus too small: {checked}");
    assert!(
        wrongly_accepted.is_empty(),
        "verifier accepted known-invalid witnesses:\n{}",
        wrongly_accepted.join("\n")
    );
}
