#!/usr/bin/env bash
# OAIP worked example: intent -> run -> claim -> accept (signed Warrant),
# including the §4 refusal (a command that exits 0 while breaking an invariant
# is NOT accepted). Self-contained: builds a throwaway git repo in a tempdir.
set -euo pipefail

OAIP="python3 $(cd "$(dirname "$0")/.." && pwd)/impl/oaip.py"
oaip() { $OAIP "$@"; }

DEMO=$(mktemp -d)
# This ledger's signing key and keyring live in a TRUST ROOT *outside* the
# workspace — that is the point: the observed command must not be able to read
# the key that signs its acceptances or rewrite the keyring that decides whose
# acceptances count. A throwaway one, so the demo leaves nothing in the reader's
# own ~/.config (and note it must NOT be under $DEMO, which is the workspace).
DEMO_TRUST=$(mktemp -d)
export XDG_CONFIG_HOME="$DEMO_TRUST"
cd "$DEMO"
git init -q && git config user.email demo@oaip && git config user.name demo
cat > auth.py <<'PY'
def login(token, now):
    exp = token.get("exp")
    return exp is not None and exp > now
PY
cat > test_auth.py <<'PY'
from auth import login
assert login({"exp": 100}, 50) is True
assert login({"exp": 100}, 200) is False   # expired rejected
assert login({}, 50) is False              # missing exp rejected
print("auth invariants hold")
PY
git add -A && git commit -qm "initial auth" >/dev/null

# A NOTE ON `--allow-check-effects`, BELOW. `python3 test_auth.py` imports
# `auth`, so CPython writes `__pycache__/auth.cpython-*.pyc` into the observed
# workspace — an ordinary, harmless check that nevertheless MUTATES what is
# being observed, after the execution's after-state was already snapshotted.
# OAIP refuses such a claim by default (section 3 shows the refusal); the flag
# files it with the check's own effects cited as evidence, so no record of this
# run can be read as "nothing changed". It observes; it does not confine.
echo "### 1. a GOOD change: add a docstring, invariant still holds -> ACCEPTED"
oaip init >/dev/null
I=$(oaip intent "document login and keep expiry rejection")
cat > /tmp/good.sh <<'SH'
python3 - <<'PY'
import pathlib
p = pathlib.Path("auth.py")
p.write_text('"""Auth: reject expired or exp-less tokens."""\n' + p.read_text())
PY
SH
E=$(oaip run --intent "$I" -- bash /tmp/good.sh); echo "  $E"
EID=$(echo "$E" | grep -oE 'execution [0-9a-f-]+' | awk '{print $2}')
C=$(oaip claim --execution "$EID" --predicate auth.rejects-expired \
        --check "python3 test_auth.py" --allow-check-effects); echo "  $C"
CID=$(echo "$C" | grep -oE 'claim [0-9a-f-]+' | awk '{print $2}')
oaip accept --claim "$CID" --actor agent-a@host | sed 's/^/  /'

echo
echo "### 2. a BAD change: exits 0 but breaks the invariant -> REFUSED"
I2=$(oaip intent "regression: make login accept everything")
cat > /tmp/bad.sh <<'SH'
printf 'def login(token, now):\n    return True  # BUG\n' > auth.py
SH
E2=$(oaip run --intent "$I2" -- bash /tmp/bad.sh); echo "  $E2"
EID2=$(echo "$E2" | grep -oE 'execution [0-9a-f-]+' | awk '{print $2}')
C2=$(oaip claim --execution "$EID2" --predicate auth.rejects-expired \
         --check "python3 test_auth.py" --allow-check-effects); echo "  $C2"
CID2=$(echo "$C2" | grep -oE 'claim [0-9a-f-]+' | awk '{print $2}')
oaip accept --claim "$CID2" --actor agent-a@host 2>&1 | sed 's/^/  /' \
  || echo "  [correctly refused: execution success is not acceptance]"

echo
echo "### 3. a check that MUTATES the workspace, with no flag -> REFUSED"
echo "###    (the check's own writes land after the execution was snapshotted,"
echo "###     so a claim filed here would report effects the record does not list)"
I3=$(oaip intent "show what an unobserved check side effect looks like")
E3=$(oaip run --intent "$I3" -- true); echo "  $E3"
EID3=$(echo "$E3" | grep -oE 'execution [0-9a-f-]+' | awk '{print $2}')
oaip claim --execution "$EID3" --predicate workspace.unchanged \
  --check "touch check-escaped-container" 2>&1 | sed 's/^/  /' \
  || echo "  [correctly refused: the validation check mutated the observed workspace]"

echo
echo "### ledger"; oaip log | sed 's/^/  /'
echo "### the Warrant store verifies"; oaip verify | sed 's/^/  /'
echo
echo "demo workspace: $DEMO"
echo "trust root (key + keyring, outside it): $(oaip trust-root --path)"
