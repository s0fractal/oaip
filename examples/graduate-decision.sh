#!/usr/bin/env bash
# Graduate a tamper-evident-but-UNSIGNED decision into a SIGNED Warrant.
#
# OAIP's accept bridge isn't code-specific: the same "subject + evidence + a
# reason → signed Warrant" move graduates ANY external decision that is
# attributed and tamper-evident but not yet signed — for example a `decision`
# node in a mind-os / workos thought-graph, whose README calls per-author
# cryptographic signatures "the deliberate next tier". This bridge IS that tier:
# it reads the decision's public projection and files a Warrant that ratifies it,
# citing the source node as evidence — WITHOUT the source taking a hard
# dependency on Warrant.
#
# Self-contained (embeds an example decision). To graduate a REAL one:
#   workos-gh get --json <node_id> | ./graduate-decision.sh -   # (read from stdin)
set -euo pipefail

WARRANT="${WARRANT_CLI:-python3 $HOME/Projects/warrant/impl/warrant.py}"
D=$(mktemp -d); cd "$D"

# an example decision projection (shape of `mind-os get --json`)
cat > decision.json <<'JSON'
{ "node_id": "sha256:50edb8119414ecd94a7c58385a08cdd5c5d0c19fb1137517a8d654ceeb648daf",
  "type": "decision",
  "title": "Product wedge: solo dev + AI agent + one repo",
  "meta": { "rationale": "The job is a durable, queryable project brain in Git, so AI output does not drown the dev." } }
JSON

$WARRANT --store store init >/dev/null
$WARRANT keygen --out dev.key >/dev/null

# canonical subject: the graduated decision
python3 - <<'PY'
import json
d = json.load(open("decision.json"))
subj = {"graduated_from": "mind-os", "node_id": d["node_id"], "type": d["type"],
        "title": d["title"], "rationale": d["meta"]["rationale"]}
open("subject.json", "w").write(json.dumps(subj, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
PY

SUBJ=$($WARRANT --store store blob add subject.json)
EV=$($WARRANT --store store blob add decision.json)          # the tamper-evident source as evidence
echo "Graduation policy v0: ratify a decision as a signed Warrant." > policy.txt
POL=$($WARRANT --store store blob add policy.txt)
NODE=$(python3 -c "import json;print(json.load(open('decision.json'))['node_id'].split(':')[1][:12])")

WID=$($WARRANT --store store accept --subject "$SUBJ" --under "$POL" \
  --reason "ratify: $(python3 -c "import json;print(json.load(open('decision.json'))['meta']['rationale'])")" \
  --evidence "$EV" --note "graduated decision $NODE" \
  --actor fable-5@s0fractal --key dev.key)

echo "decision node: $(python3 -c "import json;print(json.load(open('decision.json'))['node_id'][:24])") (tamper-evident, UNSIGNED)"
echo "graduated -> signed Warrant: $WID"
echo
echo "### warrant why (now a signed, hash-addressed decision)"
$WARRANT --store store why "$WID" | sed 's/^/  /'
echo "### verify"
$WARRANT --store store verify | tail -1 | sed 's/^/  /'
