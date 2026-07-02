# Security policy

## Reporting a vulnerability

Email the maintainer (Will Blair, william.blair0708@gmail.com); do not
open a public issue. Include reproduction steps and the affected
component. You will get an acknowledgment, and a fix or an honest
assessment before any public disclosure.

## What to read first

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is the substrate's honest
read on its own attack surface: what is defended, what is not, and what
is deferred. If you think you have found a hole, check whether it is
already named there — several real gaps are documented as accepted or
deferred rather than defended.

## Scope notes

- The trust story never depends on the hub: a consumer's
  `git clone` + `vela check --strict` verifies everything locally.
  Hub compromise is availability and discovery, not integrity
  (THREAT_MODEL.md A11).
- No AI or agent identity sits in any trust path; the engine refuses
  `agent:`/`ci:` actors on every decision verb. A bypass of that
  refusal is a vulnerability — report it.
- Private keys never belong in a repo. `keys/` and `*.key` are
  gitignored by scaffolding (A17); a reference frontier carrying a
  private key is a vulnerability even if the key looks disposable.
