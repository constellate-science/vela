#!/usr/bin/env python3
"""submit.py — one command to submit a Sidon witness to the Vela record.

You found a Sidon set in the n-dimensional 0/1 cube larger than the current
best bound (see bounds.json). This submits it as a signed state transition
with YOUR key on it. The flow is:

    1. re-verify your witness with the frozen verifier (vela reproduce)
    2. build the finding bundle (the lower-bound claim + your witness)
    3. self-sign and POST it to the hub (vela registry propose)

Acceptance into the canonical frontier is a separate human review step; this
is the external WRITE — "someone other than the maintainer signed a transition
into the registry."

Prerequisites (one-time):
    - the `vela` binary on PATH         (cargo install, or a release binary)
    - a keypair + identity:  vela id create --handle <you>

Usage:
    python3 submit.py <witness.json>
    python3 submit.py <witness.json> --dry-run      # verify + build, do not POST
    python3 submit.py <witness.json> --vfr <vfr_id> --to <hub-url>

A witness file is:
    {"kind": "sidon", "n": 20, "points": [[0,1,0,...], ...], "claimed_size": 1990}
each point a 0/1 vector of length n; the set is Sidon iff all pairwise sums
(with repetition) are distinct.
"""
import argparse, hashlib, json, subprocess, sys, tempfile, urllib.request, os, datetime

# The Sidon frontier on the public hub (override with --vfr / --to).
DEFAULT_VFR = "vfr_496956067dc5ad79"
DEFAULT_HUB = "https://hub.constellate.science"
# bounds.json lives next to this script; also published in the public repo.
HERE = os.path.dirname(os.path.abspath(__file__))
BOUNDS_LOCAL = os.path.join(HERE, "bounds.json")
BOUNDS_URL = (
    "https://raw.githubusercontent.com/constellate-science/vela/main/"
    "frontiers/sidon-sets/bounds.json"
)


def die(msg):
    print(f"submit: {msg}", file=sys.stderr)
    sys.exit(1)


def sha256_file(path):
    return "sha256:" + hashlib.sha256(open(path, "rb").read()).hexdigest()


def self_check_sidon(points):
    """A pure-Python mirror of the frozen verifier: every pairwise sum (with
    repetition) of the 0/1 vectors must be distinct. Lets you sanity-check
    before you even have `vela` installed; the authoritative check is
    `vela reproduce`."""
    seen = set()
    for i in range(len(points)):
        for j in range(i, len(points)):
            s = tuple(a + b for a, b in zip(points[i], points[j]))
            if s in seen:
                return False, f"collision at points {i},{j}"
            seen.add(s)
    return True, f"{len(seen)} pairwise sums all distinct"


def current_best(n):
    """The current accepted lower bound for a(n), from bounds.json (local
    copy, else the public URL). Returns None if unavailable."""
    data = None
    if os.path.exists(BOUNDS_LOCAL):
        data = json.load(open(BOUNDS_LOCAL))
    else:
        try:
            with urllib.request.urlopen(BOUNDS_URL, timeout=10) as r:
                data = json.loads(r.read())
        except Exception:
            return None
    for b in data.get("bounds", []):
        if b["n"] == n:
            return b["best_lower_bound"]
    return None


def build_finding(n, size, witness):
    """A minimal, faithful finding bundle: the lower-bound claim plus the
    witness as a sibling of `finding` in the payload (the verifier re-checks
    the witness; the reviewer accepts the transition)."""
    text = (
        f"OEIS A309370 a({n}) >= {size}: a Sidon set of {size} distinct binary "
        f"vectors in {{0,1}}^{n} under componentwise integer addition, all "
        f"pairwise sums distinct. Frozen-verified by vela-verify (sidon kind)."
    )
    finding = {
        "assertion": {"text": text, "type": "computational",
                      "direction": None, "relation": None, "entities": []},
        "confidence": {
            "kind": "frontier_epistemic", "method": "frozen_verifier",
            "score": 1.0, "extraction_confidence": 1.0,
            "basis": "deterministic re-check by vela-verify (sidon); review required for acceptance",
        },
        "flags": {"contested": False, "declining": False, "gap": False,
                  "gravity_well": False, "negative_space": False, "retracted": False},
        "evidence": {"evidence_type": "computational", "effect_size": None},
    }
    return {"finding": finding, "witness": witness}


def main():
    ap = argparse.ArgumentParser(description="Submit a Sidon witness to the Vela record.")
    ap.add_argument("witness", help="path to the witness JSON")
    ap.add_argument("--vfr", default=DEFAULT_VFR, help="frontier id (vfr_…)")
    ap.add_argument("--to", default=None, help="hub URL (default: your configured identity's hub)")
    ap.add_argument("--key", default=None, help="path to your Ed25519 key (default: configured identity)")
    ap.add_argument("--actor", default=None, help="your actor id (default: configured identity)")
    ap.add_argument("--vela", default="vela", help="path to the vela binary")
    ap.add_argument("--dry-run", action="store_true", help="verify + build, but do not POST")
    args = ap.parse_args()

    # ── 1. read + sanity-check the witness ───────────────────────────────
    try:
        w = json.load(open(args.witness))
    except Exception as e:
        die(f"cannot read witness {args.witness}: {e}")
    if w.get("kind") != "sidon":
        die(f"not a sidon witness (kind={w.get('kind')!r})")
    n = w.get("n")
    pts = w.get("points") or []
    size = w.get("claimed_size") or len(pts)
    if not isinstance(n, int) or not pts:
        die("witness missing integer `n` or non-empty `points`")
    # Pure-Python self-check is O(size^2); skip it for large sets (the frozen
    # Rust verifier below is the authoritative, fast check either way).
    if len(pts) <= 1500:
        ok, detail = self_check_sidon(pts)
        if not ok:
            die(f"witness is NOT a Sidon set: {detail}")
        print(f"  self-check  ok   a({n}) >= {size}  ({detail})")
    else:
        print(f"  self-check  skipped (size {size} > 1500); relying on vela reproduce")

    # ── 2. frozen verifier (authoritative) ───────────────────────────────
    try:
        out = subprocess.run([args.vela, "reproduce", args.witness],
                             capture_output=True, text=True)
    except FileNotFoundError:
        die(f"`{args.vela}` not found. Install vela, or pass --vela <path>. "
            "(The self-check above already passed, but the record requires the frozen verifier.)")
    repro = (out.stdout + out.stderr).strip()
    if out.returncode != 0:
        die(f"frozen verifier rejected the witness:\n{repro}")
    print(f"  vela reproduce  ok   {repro.splitlines()[0].strip()}")

    # ── 3. is it actually a beat? ────────────────────────────────────────
    best = current_best(n)
    if best is None:
        verdict = "unknown (could not read bounds.json)"
    elif size > best:
        verdict = f"BEATS the current best a({n}) >= {best} by {size - best}"
    elif size == best:
        verdict = f"TIES the current best a({n}) >= {best} (independent confirmation)"
    else:
        verdict = f"BELOW the current best a({n}) >= {best}; submitting anyway is allowed but will not improve the bound"
    print(f"  frontier    {verdict}")

    # ── 4. build the finding bundle payload ──────────────────────────────
    payload = build_finding(n, size, w)
    reason = f"Sidon lower bound a({n}) >= {size}, frozen-verified (sidon)."

    if args.dry_run:
        print("\n  --dry-run: not submitting. Payload preview:")
        print("  " + json.dumps(payload["finding"]["assertion"]["text"]))
        print(f"  would run: {args.vela} registry propose {args.vfr} "
              f"--kind finding.add --reason {reason!r} --payload <stdin>")
        return

    # ── 5. self-sign + POST to the hub (vela registry propose) ───────────
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(payload, tf)
        payload_path = tf.name
    cmd = [args.vela, "registry", "propose", args.vfr,
           "--kind", "finding.add", "--reason", reason,
           "--payload", payload_path, "--json"]
    if args.to:    cmd += ["--to", args.to]
    if args.key:   cmd += ["--key", args.key]
    if args.actor: cmd += ["--actor", args.actor]
    res = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(payload_path)
    if res.returncode != 0:
        die(f"hub submission failed:\n{(res.stdout + res.stderr).strip()}")

    # ── 6. emit a citable receipt ────────────────────────────────────────
    try:
        hub_resp = json.loads(res.stdout)
    except Exception:
        hub_resp = {"raw": res.stdout.strip()}
    receipt = {
        "ok": True,
        "frontier_id": args.vfr,
        "sequence": "oeis:A309370",
        "claim": payload["finding"]["assertion"]["text"],
        "n": n, "size": size,
        "beats": {"previous_best": best, "delta": (size - best) if best is not None else None},
        "witness_sha256": sha256_file(args.witness),
        "verifier": {"kind": "sidon", "crate": "vela-verify", "reproduce": repro.splitlines()[0].strip()},
        "proposal_id": hub_resp.get("proposal_id"),
        "status": hub_resp.get("status", "pending_review"),
        "hub": args.to or DEFAULT_HUB,
        "submitted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "note": "The external WRITE is recorded. Acceptance into the canonical frontier is a separate human review step.",
    }
    print("\n  submitted. receipt:")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
