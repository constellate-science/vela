//! RFC 6962-style Merkle hash tree over the event log — the P2 transparency-log
//! core. A leaf is an event's content-address preimage
//! ([`crate::events::event_content_preimage_bytes`]), so a log leaf is exactly
//! the event's `vev_` content address: immune to legitimate re-signing
//! (signature/id are excluded from the preimage) and reproducible byte-for-byte
//! by any independent implementation.
//!
//! Domain separation per RFC 6962: leaf hash = SHA-256(0x00 || leaf), interior
//! node = SHA-256(0x01 || left || right), and the empty tree hashes to
//! SHA-256("") (NOT the protocol's `NULL_HASH`).
//!
//! `verify_inclusion` reconstructs the root from the proof ALONE (no access to
//! the full tree), mirroring `inclusion_proof`'s structure — so it is correct by
//! construction against both the generator and the RFC node rules.
//!
//! Consistency proofs (RFC 6962 §2.1.2) are a documented fast-follow; the
//! signed-tree-head + inclusion path is the load-bearing minimal core.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 Merkle hash.
pub type Hash = [u8; 32];

/// RFC 6962: MTH of the empty list = SHA-256 of the empty string.
pub fn hash_empty() -> Hash {
    Sha256::digest([]).into()
}

/// RFC 6962 leaf hash: SHA-256(0x00 || leaf).
pub fn hash_leaf(leaf: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(leaf);
    h.finalize().into()
}

/// RFC 6962 interior node hash: SHA-256(0x01 || left || right).
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (requires `n >= 2`).
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash (root) of a list of leaf preimages (RFC 6962 §2.1).
pub fn merkle_root(leaves: &[Vec<u8>]) -> Hash {
    match leaves.len() {
        0 => hash_empty(),
        1 => hash_leaf(&leaves[0]),
        n => {
            let k = largest_pow2_lt(n);
            hash_node(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Inclusion (audit) proof for the leaf at index `m` in `leaves` (RFC 6962
/// §2.1.1). Returns the sibling-subtree hashes ordered leaf -> root, or `None`
/// if `m` is out of range.
pub fn inclusion_proof(leaves: &[Vec<u8>], m: usize) -> Option<Vec<Hash>> {
    if m >= leaves.len() {
        return None;
    }
    fn build(leaves: &[Vec<u8>], m: usize, out: &mut Vec<Hash>) {
        let n = leaves.len();
        if n <= 1 {
            return;
        }
        let k = largest_pow2_lt(n);
        if m < k {
            build(&leaves[..k], m, out);
            out.push(merkle_root(&leaves[k..]));
        } else {
            build(&leaves[k..], m - k, out);
            out.push(merkle_root(&leaves[..k]));
        }
    }
    let mut path = Vec::new();
    build(leaves, m, &mut path);
    Some(path)
}

/// Verify an inclusion proof by reconstructing the root from `(leaf, m, n,
/// proof)` alone. Returns true iff the reconstructed root equals `root` and the
/// proof is fully consumed (no extra siblings).
pub fn verify_inclusion(leaf: &[u8], m: usize, n: usize, proof: &[Hash], root: &Hash) -> bool {
    if m >= n {
        return false;
    }
    fn recon(
        m: usize,
        n: usize,
        leaf_hash: &Hash,
        proof: &[Hash],
        idx: &mut usize,
    ) -> Option<Hash> {
        if n == 1 {
            return Some(*leaf_hash); // m == 0
        }
        let k = largest_pow2_lt(n);
        if m < k {
            let left = recon(m, k, leaf_hash, proof, idx)?;
            let right = *proof.get(*idx)?;
            *idx += 1;
            Some(hash_node(&left, &right))
        } else {
            let right = recon(m - k, n - k, leaf_hash, proof, idx)?;
            let left = *proof.get(*idx)?;
            *idx += 1;
            Some(hash_node(&left, &right))
        }
    }
    let leaf_hash = hash_leaf(leaf);
    let mut idx = 0usize;
    match recon(m, n, &leaf_hash, proof, &mut idx) {
        Some(r) => idx == proof.len() && &r == root,
        None => false,
    }
}

/// Consistency proof that the size-`m` tree is a prefix of the size-`n` tree
/// (RFC 6962 §2.1.2). Returns the audit nodes proving `MTH(D[0:m])` is contained
/// in `MTH(D[0:n])`, or `None` if `m == 0` or `m > n`. For `m == n` the proof is
/// empty (the two roots must be equal). Pairs with [`verify_consistency`].
pub fn consistency_proof(leaves: &[Vec<u8>], m: usize) -> Option<Vec<Hash>> {
    let n = leaves.len();
    if m == 0 || m > n {
        return None;
    }
    if m == n {
        return Some(Vec::new());
    }
    // RFC 6962 SUBPROOF(m, D[0:n], true).
    fn subproof(m: usize, leaves: &[Vec<u8>], b: bool, out: &mut Vec<Hash>) {
        let n = leaves.len();
        if m == n {
            // The subtree root is already known to the verifier iff b (it is the
            // first tree's root / a previously-derived node); otherwise it must
            // be supplied.
            if !b {
                out.push(merkle_root(leaves));
            }
            return;
        }
        let k = largest_pow2_lt(n);
        if m <= k {
            subproof(m, &leaves[..k], b, out);
            out.push(merkle_root(&leaves[k..]));
        } else {
            subproof(m - k, &leaves[k..], false, out);
            out.push(merkle_root(&leaves[..k]));
        }
    }
    let mut path = Vec::new();
    subproof(m, leaves, true, &mut path);
    Some(path)
}

/// Verify a consistency proof between two signed tree heads: that the tree of
/// size `m` with root `first` is a prefix of the tree of size `n` with root
/// `second` (RFC 6962 §2.1.2). Reconstructs BOTH roots from the proof alone and
/// requires the proof to be fully consumed. This is the Certificate-Transparency
/// reference verification algorithm; it pairs with [`consistency_proof`].
pub fn verify_consistency(m: usize, n: usize, first: &Hash, second: &Hash, proof: &[Hash]) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && first == second;
    }
    if m == 0 {
        // The empty tree is a prefix of every tree; nothing to prove.
        return proof.is_empty();
    }
    // m < n, m > 0, proof must be non-empty.
    let mut node = m - 1;
    let mut last = n - 1;
    // Climb past the levels where the m-boundary node is a right child: those
    // nodes are common to both trees and need no proof material yet.
    while node & 1 == 1 {
        node >>= 1;
        last >>= 1;
    }

    let mut idx = 0usize;
    // Seed: if m is an exact power of two, the size-m subtree root IS `first`
    // and is not carried in the proof; otherwise the first proof node seeds both
    // reconstructions.
    let (mut hash1, mut hash2) = if node > 0 {
        match proof.first() {
            Some(h) => {
                idx = 1;
                (*h, *h)
            }
            None => return false,
        }
    } else {
        (*first, *first)
    };

    while node > 0 {
        if node & 1 == 1 {
            // right child: sibling on the left, shared by both trees
            let Some(p) = proof.get(idx) else {
                return false;
            };
            idx += 1;
            hash1 = hash_node(p, &hash1);
            hash2 = hash_node(p, &hash2);
        } else if node < last {
            // left child with a right sibling that exists only in the new tree
            let Some(p) = proof.get(idx) else {
                return false;
            };
            idx += 1;
            hash2 = hash_node(&hash2, p);
        }
        node >>= 1;
        last >>= 1;
    }
    // Finish the new tree's remaining upper-right spine.
    while last > 0 {
        let Some(p) = proof.get(idx) else {
            return false;
        };
        idx += 1;
        hash2 = hash_node(&hash2, p);
        last >>= 1;
    }

    idx == proof.len() && &hash1 == first && &hash2 == second
}

/// Hex-encode a Merkle hash (lower-case, no prefix).
pub fn to_hex(h: &Hash) -> String {
    hex::encode(h)
}

/// `sha256:<hex>` form, matching the protocol's hash string convention.
pub fn to_commitment(h: &Hash) -> String {
    format!("sha256:{}", hex::encode(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("event-{i}").into_bytes()).collect()
    }

    #[test]
    fn empty_root_is_sha256_of_empty_string() {
        // RFC 6962 known answer.
        assert_eq!(
            to_hex(&merkle_root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn single_and_two_leaf_structure() {
        let d0 = b"d0".to_vec();
        let d1 = b"d1".to_vec();
        assert_eq!(merkle_root(std::slice::from_ref(&d0)), hash_leaf(&d0));
        assert_eq!(
            merkle_root(&[d0.clone(), d1.clone()]),
            hash_node(&hash_leaf(&d0), &hash_leaf(&d1))
        );
    }

    #[test]
    fn inclusion_roundtrip_all_indices_all_sizes() {
        for n in 1..=33usize {
            let ls = leaves(n);
            let root = merkle_root(&ls);
            for m in 0..n {
                let proof = inclusion_proof(&ls, m).expect("proof");
                assert!(
                    verify_inclusion(&ls[m], m, n, &proof, &root),
                    "valid proof must verify (n={n}, m={m})"
                );
            }
            assert!(inclusion_proof(&ls, n).is_none(), "out-of-range index");
        }
    }

    #[test]
    fn tamper_is_rejected() {
        let ls = leaves(7);
        let root = merkle_root(&ls);
        let proof = inclusion_proof(&ls, 3).unwrap();
        // wrong leaf bytes
        assert!(!verify_inclusion(b"forged", 3, 7, &proof, &root));
        // wrong index
        assert!(!verify_inclusion(&ls[3], 2, 7, &proof, &root));
        // wrong tree size that changes the proof shape (length mismatch) is rejected.
        // NOTE: sizes sharing the same top split (e.g. 6/7/8 for a left-half leaf)
        // reconstruct the same root from an inclusion proof alone — that ambiguity
        // is resolved by the signed STH, which binds tree_size and root together.
        assert!(!verify_inclusion(&ls[3], 3, 4, &proof, &root));
        // flipped sibling in the proof
        let mut bad = proof.clone();
        bad[0][0] ^= 0xff;
        assert!(!verify_inclusion(&ls[3], 3, 7, &bad, &root));
        // truncated / extra proof
        assert!(!verify_inclusion(
            &ls[3],
            3,
            7,
            &proof[..proof.len() - 1],
            &root
        ));
        let mut extra = proof.clone();
        extra.push([0u8; 32]);
        assert!(!verify_inclusion(&ls[3], 3, 7, &extra, &root));
        // wrong root
        let mut wrong_root = root;
        wrong_root[0] ^= 0xff;
        assert!(!verify_inclusion(&ls[3], 3, 7, &proof, &wrong_root));
    }

    #[test]
    fn order_matters() {
        let a = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let b = vec![b"a".to_vec(), b"c".to_vec(), b"b".to_vec()];
        assert_ne!(merkle_root(&a), merkle_root(&b));
    }

    #[test]
    fn consistency_roundtrip_all_pairs() {
        for n in 1..=33usize {
            let ls = leaves(n);
            let root_n = merkle_root(&ls);
            for m in 1..=n {
                let root_m = merkle_root(&ls[..m]);
                let proof = consistency_proof(&ls, m).expect("proof for 1<=m<=n");
                assert!(
                    verify_consistency(m, n, &root_m, &root_n, &proof),
                    "valid consistency proof must verify (m={m}, n={n}, proof_len={})",
                    proof.len()
                );
                // m == n must be an empty proof.
                if m == n {
                    assert!(proof.is_empty(), "m==n proof must be empty (n={n})");
                }
            }
            // m == 0 and m > n are not provable.
            assert!(consistency_proof(&ls, 0).is_none());
            assert!(consistency_proof(&ls, n + 1).is_none());
        }
    }

    #[test]
    fn consistency_tamper_is_rejected() {
        let ls = leaves(20);
        let (m, n) = (7usize, 20usize);
        let root_m = merkle_root(&ls[..m]);
        let root_n = merkle_root(&ls);
        let proof = consistency_proof(&ls, m).unwrap();

        // wrong old root
        let mut bad_first = root_m;
        bad_first[0] ^= 0xff;
        assert!(!verify_consistency(m, n, &bad_first, &root_n, &proof));
        // wrong new root
        let mut bad_second = root_n;
        bad_second[0] ^= 0xff;
        assert!(!verify_consistency(m, n, &root_m, &bad_second, &proof));
        // flipped proof node
        let mut bad = proof.clone();
        bad[0][0] ^= 0xff;
        assert!(!verify_consistency(m, n, &root_m, &root_n, &bad));
        // truncated / extra proof
        assert!(!verify_consistency(
            m,
            n,
            &root_m,
            &root_n,
            &proof[..proof.len() - 1]
        ));
        let mut extra = proof.clone();
        extra.push([0u8; 32]);
        assert!(!verify_consistency(m, n, &root_m, &root_n, &extra));
        // a DIFFERENT old tree (not actually a prefix) must fail: take size-m
        // root from a divergent leaf set.
        let other = {
            let mut o = ls[..m].to_vec();
            o[m - 1] = b"divergent".to_vec();
            merkle_root(&o)
        };
        assert!(!verify_consistency(m, n, &other, &root_n, &proof));
        // m > n rejected
        assert!(!verify_consistency(n, m, &root_n, &root_m, &proof));
    }
}
