#!/usr/bin/env bash
# Seed the Erdős statement-fidelity frontier (examples/erdos-formalization)
# with reviewer:will-blair's signed faithfulness verdicts.
#
# KEY CUSTODY: only a human reviewer can sign a `vsa_` statement attestation
# (StatementAttestation::build and the CLI both reject any `agent:` actor).
# Run this YOURSELF, with your identity configured (`vela id show`) or via
# VELA_ACTOR_ID / VELA_KEY_PATH. An agent prepared this script; it cannot run
# the signing step for you.
#
# Default is a DRY PREVIEW: it prints the plan (problem, verdict, note, the
# formal-statement hash it would bind) and writes nothing. Review the
# match-check packets first (in erdos-fc-sync: `python match_packet.py <n>`),
# then rerun with --sign to init the frontier, add one finding per problem,
# and write the signed verdicts.
#
# Usage:
#   bash scripts/seed-erdos-formalization.sh           # dry preview, no writes
#   bash scripts/seed-erdos-formalization.sh --sign    # init + findings + sign
#
# Env: VELA (binary, default `vela`), FRONTIER (default
#   examples/erdos-formalization), REVIEWER (default reviewer:will-blair),
#   FC_DIR (local formal-conjectures checkout for hashing the formal statement
#   bytes, default $HOME/personal/formal-conjectures).
set -euo pipefail

VELA="${VELA:-vela}"
FRONTIER="${FRONTIER:-examples/erdos-formalization}"
REVIEWER="${REVIEWER:-reviewer:will-blair}"
FC_DIR="${FC_DIR:-$HOME/personal/formal-conjectures}"
SIGN=0; [ "${1:-}" = "--sign" ] && SIGN=1

# problem | verdict | note  (verdicts mirror erdos-fc-sync/overrides.yaml;
# adjust per the match-check packet before signing — this is your judgment).
ROWS='214|unfaithful|Hosted proof is complete, but proves an existential coloring result rather than the universal boxed problem.
337|unfaithful|Hosted proof is a counterexample/existence theorem and needs a fresh match-check before linking to the FC statement.
205|variant|Treat as conditional until the hosted theorem is confirmed to have no non-problem hypothesis.
1148|variant|Hosted theorem takes Duke'"'"'s theorem as a hypothesis; #print axioms alone would not catch this.'

hash_fc() {
  local f="$FC_DIR/FormalConjectures/ErdosProblems/$1.lean"
  if [ -f "$f" ]; then shasum -a 256 "$f" | awk '{print $1}'
  else echo "0000000000000000000000000000000000000000000000000000000000000000"; fi
}

[ "$SIGN" = "1" ] && echo "== SIGNING as $REVIEWER ==" || echo "== DRY PREVIEW (no writes) — rerun with --sign to execute =="

if [ "$SIGN" = "1" ] && [ ! -d "$FRONTIER/.vela" ]; then
  # --no-git: the other examples/ frontiers are plain dirs tracked by the
  # substrate repo, not nested git repos. The frontier's state lives in .vela/.
  "$VELA" init "$FRONTIER" --name "Erdős formalization fidelity" --no-git
fi

while IFS='|' read -r N VERDICT NOTE; do
  [ -z "$N" ] && continue
  HASH=$(hash_fc "$N")
  FORMAL_REF="google-deepmind/formal-conjectures@HEAD:FormalConjectures/ErdosProblems/$N.lean"
  echo "-- problem $N -> $VERDICT"
  echo "   note: $NOTE"
  echo "   formal_statement_hash: $HASH"
  if [ "$SIGN" = "1" ]; then
    VF=$("$VELA" finding add "$FRONTIER" \
          --assertion "The Formal Conjectures statement for Erdős problem $N faithfully represents the informal problem." \
          --type theoretical --source "erdos-fc-sync fidelity frontier" \
          --author "$REVIEWER" --apply --json | grep -oE 'vf_[0-9a-f]+' | head -1)
    echo "   finding: $VF"
    "$VELA" attest "$FRONTIER" "$VF" --verdict "$VERDICT" \
      --informal-ref "erdosproblems.com/$N" --formal-ref "$FORMAL_REF" \
      --formal-statement-hash "$HASH" --note "$NOTE" --reviewer "$REVIEWER"
  fi
done <<< "$ROWS"

echo
echo "Next:"
echo "  1) (if dry) review packets/match-check/erdos_<n>.md, then rerun with --sign"
echo "  2) vela frontier materialize $FRONTIER && vela frontier audit $FRONTIER"
echo "  3) vela publish $FRONTIER --to https://hub.constellate.science"
echo "  4) append $FRONTIER to scripts/workspace.json so conformance discovers it"
echo "  5) point erdos-fc-sync FIDELITY_URL at the hub snapshot; refresh fidelity_cache.json"
