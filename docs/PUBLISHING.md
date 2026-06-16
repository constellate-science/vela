# Publishing Vela frontiers

This document defines the public release path for frontier state. It
covers three distribution surfaces:

- GitHub release artifacts: immutable files, proof packets, manifests,
  and checksums.
- Hub mirror: signed transport for a live `vfr_*` entry.
- Optional dataset-style mirror: a Hugging Face dataset repository or
  equivalent archive carrying the same release pack.

The local frontier remains the authority. A mirror helps other people
find and verify state. It does not make the science true.

## Current reference package

The public demo frontier in this repository is:

```text
examples/sidon-a309370/
```

It is the public subset of the Sidon-set frontier of record (OEIS
A309370): verified witnesses plus the replay machinery to re-check
them. Read these files first:

- `examples/sidon-a309370/README.md`
- `docs/PROTOCOL.md` (the wire spec)
- `docs/VERIFICATION_GATE.md` (when a claim earns `verified`)
- `docs/REVIEWER_PLAYBOOK.md`

## GitHub release artifact pack

Build the binary and prove the package replays before assembling
release assets:

```bash
cargo build --release --bin vela

# every claimed construction re-checks from the stored witnesses
./target/release/vela reproduce examples/sidon-a309370

# frontier quality + strict signals
./target/release/vela check <frontier> --strict --json

# export a proof packet for the release
./target/release/vela proof <frontier> --out /tmp/<frontier>-proof-packet
```

A release pack is a directory of immutable files with a top-level
checksum manifest. The minimum set:

- the frontier state file (`frontier.json` or the frontier repo archive)
- the proof packet (`tar -czf <frontier>-proof-packet.tar.gz ...`)
- `CITATION.cff`
- `LICENSE-APACHE`, `LICENSE-MIT`
- `SHA256SUMS` (`shasum -a 256 <files> > SHA256SUMS`)

Use a GitHub release when you want a citable frozen package. Upload
the files as release assets for the matching tag.

## Checksum verification

Every release pack has a top-level `SHA256SUMS` file. Verify before
using the pack:

```bash
shasum -a 256 -c SHA256SUMS
```

Then validate the proof packet:

```bash
tar -xzf sidon-a309370-proof-packet.tar.gz
vela verify sidon-a309370-proof-packet   # replay + hash + signature check
```

This proves that the packet is internally replayable and hash-bound.
It does not prove the claims matter; it proves they are what was
signed.

## Hub mirror

The public hub mirrors signed frontier state:

```text
https://hub.constellate.science
```

For a fresh frontier file, publish with:

```bash
vela sign generate-keypair --out keys
vela actor add ./frontier.json reviewer:you \
  --pubkey "$(cat keys/public.key)"

vela registry publish ./frontier.json \
  --owner reviewer:you \
  --key keys/private.key \
  --to https://hub.constellate.science \
  --json
```

For split frontier repositories, materialize and lock before
publishing a snapshot:

```bash
vela frontier materialize <frontier>
vela lock <frontier>
vela check <frontier> --strict --json
vela proof <frontier> --out /tmp/<frontier>-proof
```

The hub can withhold or go stale. It should not be treated as the
scientific authority. Consumers should verify with `vela registry pull`,
`vela check`, and `vela verify`.

## Optional dataset-style mirror

A Hugging Face mirror is optional. Treat it as a dataset-style
distribution of the same GitHub release assets, not a different source
of truth. Mirror the release pack bytes unchanged — including
`SHA256SUMS`, `CITATION.cff`, and both license files — and write the
dataset card to:

- Lead with the frontier scope and current claim boundary.
- Link the GitHub release tag that produced the mirror.
- Include the checksum verification commands.
- Preserve the license fields from the frontier manifest.
- State that hub mirrors are transport, not authority.

## Citation

For software metadata, start with `CITATION.cff`. For a frontier
release, also cite the release tag plus the frontier state:

```text
Vela contributors. <Frontier name>. Vela release <tag>. Frontier
state package, proof packet, and review trail.
```

Include:

- GitHub release URL.
- Hub `vfr_*` entry if published.
- Snapshot hash from the proof packet manifest.
- Access date for mirrors.

Do not cite Vela as resolving the science. Cite it as a reviewable
frontier state package.

## License

Repository code is dual-licensed Apache-2.0 OR MIT. See
`LICENSE-APACHE` and `LICENSE-MIT`.

Frontier manifests declare their own content/data licenses, for
example:

```yaml
license:
  content: CC-BY-4.0
  code: Apache-2.0
  data: varies
```

Source papers and external data retain their original terms. Vela
stores source identity, locators, evidence spans, and artifact
records; it should not redistribute license-restricted source bytes
unless the artifact license permits it.

## Release gate

Before publishing:

```bash
cargo test --workspace
python3 conformance/verify.py
vela check <frontier> --strict --json
vela reproduce examples/sidon-a309370
```

The gate is intentionally boring: replay, conformance, strict checks.
If any step fails, the packaged artifacts may still be useful for
review, but the release is not certified.
