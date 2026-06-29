# Erdős formalization fidelity

This is a Vela frontier repository.

- State entrypoint: `frontier.json`
- Manifest: `frontier.yaml`
- Lockfile: `vela.lock`
- Template: `default`

Run:

```bash
vela check . --strict --json
vela integrity . --json
vela proof . --out proof/latest
```
