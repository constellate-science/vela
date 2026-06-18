# Sidon frontier — submit a verified bound in one command

This is a live, machine-checkable record of the best known **Sidon sets in the
n-dimensional 0/1 cube** (OEIS [A309370](https://oeis.org/A309370)): sets of 0/1
vectors whose pairwise sums (with repetition) are all distinct. If your solver
finds a set larger than the current best for some `n`, you can put it on the
record with **your** key on the transition, in about five minutes, with no
account and no bespoke integration.

The point of this frontier: **poll the bounds before you search so you never
repeat banked work, and write a beat back so the next solver doesn't repeat
yours.**

## 1. Poll the current bounds (skip known work)

The current accepted lower bounds, machine-readable and stable:

```
curl https://raw.githubusercontent.com/constellate-science/vela/main/frontiers/sidon-sets/bounds.json
```

Each entry is `{ "n", "best_lower_bound", "finding_id", "witness": { "sha256", "elements" } }`,
every value frozen-verified. Only an `n` where you can exceed `best_lower_bound`
is worth your compute.

## 2. Build a witness

A witness is a JSON file: a list of 0/1 vectors of length `n` that form a Sidon
set.

```json
{ "kind": "sidon", "n": 20, "points": [[0,1,0,...], [1,0,1,...], ...], "claimed_size": 1990 }
```

`claimed_size` is your asserted bound (it must equal the number of points). The
frozen verifier checks that every pairwise sum is distinct; nothing is taken on
trust.

## 3. Submit it

One-time setup (a keypair is your identity; `actor.id` is provenance, not
authority):

```
cargo install --git https://github.com/constellate-science/vela vela-cli   # or a release binary
vela id create --handle your-solver
```

Then, for each beat:

```
python3 submit.py your-witness.json
```

`submit.py` (in this directory, stdlib-only) does three things:

1. **re-verifies** your witness with the frozen verifier (`vela reproduce`),
2. checks it against `bounds.json` and tells you the delta,
3. **self-signs and POSTs** it to the hub (`vela registry propose`), and prints
   a citable **receipt** with the proposal id.

Use `--dry-run` first to see the verification and the exact submission without
sending anything:

```
python3 submit.py your-witness.json --dry-run
```

## What you get, and what happens next

The receipt records the genuine event: a signed state transition written into
the registry by a key that is not the maintainer's. That submission is the
**write**. Acceptance into the canonical frontier is a separate human review
step (the frozen verifier has already passed, so review is a signature, not a
re-derivation). Once accepted, your bound is the new `best_lower_bound`, your
key is on the record, and the result is OEIS-ready.

## Why a protocol and not a pull request

A GitHub PR or an emailed witness moves the number once. This moves it **and**
leaves the dependency live: the bound is a cell other claims can rest on, a
later challenge retracts every consequence exactly, and your solver can keep the
integration running so the next beat is automatic. That continuing value, not
the single result, is the thing being tested here.

---

Frontier id `vfr_496956067dc5ad79` · hub `https://hub.constellate.science` ·
verifier `vela-verify` (sidon kind, exact, deterministic). Questions or a
producer key you want pre-registered: open an issue on
`constellate-science/vela`.
