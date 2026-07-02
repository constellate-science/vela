#!/usr/bin/env bash
# Sign one statement-faithfulness verdict (`vsa_`) into the Erdős fidelity
# frontier (examples/erdos-formalization): add a finding for the problem and
# attest the reviewer's verdict on whether the formal statement faithfully
# encodes the informal Erdős problem.
#
# KEY CUSTODY: only a human reviewer can sign — StatementAttestation::build and
# the CLI reject any `agent:` actor. Run this yourself, with your identity
# configured (`vela id show`) or via VELA_ACTOR_ID / VELA_KEY_PATH.
#
# Usage:
#   bash scripts/seed-erdos-formalization.sh <problem> <faithful|variant|unfaithful> "<note>" [--sign]
# Without --sign it prints the plan and writes nothing.
#
# Env: VELA (binary, default `vela`), FRONTIER (default
#   examples/erdos-formalization), REVIEWER (default reviewer:will-blair),
#   FC_DIR (local formal-conjectures checkout used to hash the formal statement
#   bytes; falls back to a zero hash when the file is absent).
set -euo pipefail

VELA="${VELA:-vela}"
FRONTIER="${FRONTIER:-examples/erdos-formalization}"
REVIEWER="${REVIEWER:-reviewer:will-blair}"
FC_DIR="${FC_DIR:-$HOME/personal/formal-conjectures}"

SIGN=0; ARGS=()
for a in "$@"; do [ "$a" = "--sign" ] && SIGN=1 || ARGS+=("$a"); done
N="${ARGS[0]:?problem number required}"
VERDICT="${ARGS[1]:?verdict required (faithful|variant|unfaithful)}"
NOTE="${ARGS[2]:?note required (an attestation without reasoning is a rubber stamp)}"

FC_FILE="$FC_DIR/FormalConjectures/ErdosProblems/$N.lean"
if [ -f "$FC_FILE" ]; then HASH=$(shasum -a 256 "$FC_FILE" | awk '{print $1}'); else HASH=$(printf '%064d' 0); fi
FORMAL_REF="google-deepmind/formal-conjectures@HEAD:FormalConjectures/ErdosProblems/$N.lean"

echo "problem $N -> $VERDICT   (formal_statement_hash ${HASH:0:12}…)"
echo "   note: $NOTE"
if [ "$SIGN" != "1" ]; then
  echo "(dry run — pass --sign to add the finding and sign the verdict as $REVIEWER)"
  exit 0
fi

[ -d "$FRONTIER/.vela" ] || "$VELA" init "$FRONTIER" --name "Erdős formalization fidelity" --no-git
VF=$("$VELA" finding add "$FRONTIER" \
      --assertion "The Formal Conjectures statement for Erdős problem $N faithfully represents the informal problem." \
      --type theoretical --source "erdos-fc-sync fidelity frontier" \
      --author "$REVIEWER" --apply --json | grep -oE 'vf_[0-9a-f]+' | head -1)
"$VELA" attest "$FRONTIER" "$VF" --verdict "$VERDICT" \
  --informal-ref "erdosproblems.com/$N" --formal-ref "$FORMAL_REF" \
  --formal-statement-hash "$HASH" --note "$NOTE" --as "$REVIEWER"
echo "signed. next: vela frontier materialize $FRONTIER && git push  # git push is publication; bind once with vela hub register-git"
