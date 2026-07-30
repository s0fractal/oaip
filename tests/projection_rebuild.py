#!/usr/bin/env python3
"""SPEC §5 as an executable MUST: delete the projection, rebuild it, same graph.

WHY
---
§5 says the canonical layer is content-addressed artifacts plus the Warrant store,
and that the relational index is a *projection* which "MUST be reconstructable
from the canonical layer" — "Deleting the projection and rebuilding it from
artifacts + warrants MUST yield the same graph." The SPEC closes with "the
projection is disposable; the content-addressed causal graph is the truth."

Until 2026-07-30 the opposite was true, and no test could have caught it because
there was no rebuild path to run. Records existed only as SQLite rows:
`ledger.db` was deleted and the invocation, the exit code, the before/after tree
snapshots, the environment fingerprint and the intent link were gone — none of
them appeared anywhere content-addressed. The projection WAS the source of truth,
which is the one thing §5 forbids.

This test is the reason that cannot come back quietly.

WHAT IT CHECKS
--------------
1. A live run produces a graph.
2. `oaip rebuild` reconstructs it from `.oaip/artifacts` alone — the database is
   deleted first, so a rebuild that needed the database would be circular.
3. The graph is identical, field by field, not merely the same row counts.
4. Rebuilding twice is idempotent: a projection that drifts on the second rebuild
   is not a projection.
5. The fields that were lost before are individually present, named one by one,
   so a future regression says which fact went missing rather than "counts
   differ".
6. The claim→warrant ACCEPTANCE edge survives rebuild. §5 names the canonical
   layer as "artifacts + warrants", and rebuild read only the artifacts: the
   warrants table was never repopulated, so `oaip log` lost its WARRANT line —
   the protocol's most important fact — at the first rebuild. This file was
   complicit: TABLES omitted `warrants`, so the comparison could not see the
   loss. Fixed 2026-07-30; the edge is re-derived from the Warrant store
   (accept records name the claim's subject blob hash).
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# `warrants` was deliberately absent from this tuple until 2026-07-30, which is
# how the projection could silently lose the claim→warrant edge on rebuild —
# the one fact this protocol exists to record. It is in the graph; it is in the
# comparison.
TABLES = ("intents", "executions", "effects", "claims", "attributions",
          "warrants")
ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def snapshot(db):
    """Every row of every table, as comparable text.

    `effects.id` is an AUTOINCREMENT surrogate and `attributions.effect_id` points
    at it, so both are dropped: a rebuild is allowed to renumber rows it never
    promised to preserve. Everything a record actually asserts is compared.
    """
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    out = {}
    for t in TABLES:
        rows = []
        for r in con.execute(f"SELECT * FROM {t}"):
            d = dict(r)
            if t == "effects":
                d.pop("id", None)
            if t == "attributions":
                d.pop("effect_id", None)
            rows.append(json.dumps(d, sort_keys=True))
        out[t] = sorted(rows)
    con.close()
    return out


def main():
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "w"
        work.mkdir()
        shutil.copytree(ROOT / "impl", work / "impl")
        subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "--allow-empty", "-m", "init"],
                       cwd=work, check=True)
        run = lambda *a: subprocess.run([sys.executable, "impl/oaip.py", *a],
                                        cwd=work, capture_output=True, text=True)
        run("init")
        r = run("do", "--intent", "add a file", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi >> f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup: the one-shot flow did not accept\n", r.stdout, r.stderr)
            return 1

        db = work / ".oaip" / "ledger.db"
        before = snapshot(db)
        case("a live run produced a graph",
             all(before[t] for t in ("intents", "executions", "effects",
                                     "claims", "warrants")))

        # The acceptance edge, named before rebuild so its loss is a regression
        # in THIS fact, not a diff in a dictionary. `log`'s WARRANT line is the
        # protocol's most important sentence; until 2026-07-30 `rebuild` never
        # repopulated the warrants table, so the line survived `do` and died at
        # the first rebuild.
        log_before = run("log")
        case("log shows the WARRANT line before rebuild",
             "WARRANT" in log_before.stdout, log_before.stdout)
        wr = json.loads(before["warrants"][0])
        for field in ("claim_id", "warrant_id", "created_at"):
            case(f"warrant.{field} is present before rebuild",
                 wr.get(field) not in (None, ""))

        # The fields that vanished before. Named individually so a regression says
        # WHICH fact was lost, not that two dictionaries differ.
        ex = json.loads(before["executions"][0])
        for field in ("command", "exit_code", "before_tree", "after_tree",
                      "env_fp", "stdout_hash", "intent_id"):
            case(f"execution.{field} is present before rebuild",
                 ex.get(field) not in (None, ""))

        out = run("rebuild")
        case("rebuild ran", out.returncode == 0, out.stdout + out.stderr)
        after = snapshot(db)

        for t in TABLES:
            case(f"{t}: identical after rebuild from artifacts alone",
                 before[t] == after[t],
                 f"\n      before={before[t][:1]}\n      after ={after[t][:1]}")

        ex2 = json.loads(after["executions"][0]) if after["executions"] else {}
        for field in ("command", "exit_code", "before_tree", "after_tree",
                      "env_fp", "stdout_hash", "intent_id"):
            case(f"execution.{field} survived the projection",
                 ex2.get(field) == ex.get(field),
                 f"before={ex.get(field)!r} after={ex2.get(field)!r}")

        wr2 = json.loads(after["warrants"][0]) if after["warrants"] else {}
        for field in ("claim_id", "warrant_id", "created_at"):
            case(f"warrant.{field} survived the projection",
                 wr2.get(field) == wr.get(field),
                 f"before={wr.get(field)!r} after={wr2.get(field)!r}")
        log_after = run("log")
        case("log still shows the WARRANT line after rebuild",
             "WARRANT" in log_after.stdout, log_after.stdout)

        run("rebuild")
        case("rebuilding twice is idempotent", snapshot(db) == after)

    print("\nPROJECTION-REBUILD: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
