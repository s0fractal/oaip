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
   (accept records carry the accepted claim's id in their signed subject.note).
7. Rebuild does not LAUNDER a forged acceptance. Address-matching
   (sha256(canon(body)) == filename) is satisfied by construction by anyone who
   can write a file: a hand-written accept with a real claim's subject hash and
   junk sigs made `oaip rebuild` print warrant=2 and `oaip log` print "(signed
   decision)" for it (2026-07-30 adversarial review). Rebuild now verifies the
   store through the Warrant CLI before deriving any edge, and fails closed —
   including when no Warrant CLI can run at all.
8. A subject COLLISION cannot project an acceptance onto a FAILED claim. The
   claim subject {predicate, execution, effects} excludes the check command and
   verdict, so `--check true` and `--check false` over one execution collide;
   subject-hash edge derivation attached the real signed warrant to the
   UNSUPPORTED claim after rebuild (§5 MUST violation, same review). New
   accepts carry an explicit oaip-claim:<id> note; legacy accepts without one
   fall back to subject-hash matching restricted to supported claims.
"""
import hashlib
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


def canon(obj):
    """Byte-for-byte the implementation's JCS canon — the address function an
    attacker also controls, which is the point of cases 7/8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def make_repo(tmp, name="w"):
    work = Path(tmp) / name
    work.mkdir()
    shutil.copytree(ROOT / "impl", work / "impl")
    subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "init"],
                   cwd=work, check=True)
    run = lambda *a, **kw: subprocess.run([sys.executable, "impl/oaip.py", *a],
                                          cwd=work, capture_output=True,
                                          text=True, **kw)
    run("init")
    return work, run


def main():
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp)
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

    with tempfile.TemporaryDirectory() as tmp:
        # --- case 7 + the P2s: forged and corrupt DECISION-layer records.
        # Every attack here files a record whose FILENAME IS a legal address;
        # what distinguishes them from cmd_accept's output is that no key ever
        # signed them — the exact thing the old address-only gate never looked at.
        work, run = make_repo(tmp)
        r = run("do", "--intent", "add a file", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi >> f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup(7): the one-shot flow did not accept\n",
                  r.stdout, r.stderr)
            return 1
        db = work / ".oaip" / "ledger.db"
        recdir = work / ".oaip" / "warrants" / "records"

        # P2: a stray non-record .json (a notes file, a zero-byte editor drop)
        # used to brick rebuild with "does not match its own address" — a
        # forgery diagnosis for a benign file. Refuse, but say what it is.
        stray = recdir / "notes.json"
        stray.write_bytes(b"")
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("stray notes.json: rebuild refuses", r.returncode != 0, out[-300:])
        case("stray notes.json: diagnosed as a stray file, not a forgery",
             "stray file" in out and "does not match its own address" not in out,
             out[-300:])
        stray.unlink()

        # P2: a crafted NON-DICT body at its own valid address crashed rebuild
        # with an AttributeError. A refusal is a decision; a traceback is an
        # accident.
        addr = sha256(canon("junk"))
        (recdir / f"{addr}.json").write_text(
            json.dumps({"body": "junk", "sigs": []}))
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("non-dict body at a valid address: a refusal, not a traceback",
             r.returncode != 0 and "Traceback" not in out
             and "no body object" in out, out[-300:])
        (recdir / f"{addr}.json").unlink()

        # THE FORGERY (case 7): a real accept body, ts bumped so it is a NEW
        # record at its own valid address, "signed" with bytes no key produced.
        # The old gate (address matching) passes it by construction — the
        # negative control proves that — and rebuild then printed warrant=2
        # while `oaip verify` knew the signature was junk.
        real = None
        for p in sorted(recdir.glob("*.json")):
            env = json.loads(p.read_text())
            if env["body"].get("decision") == "accept":
                real = env
        fbody = dict(real["body"])
        fbody["ts"] = fbody["ts"] + 1
        fid = sha256(canon(fbody))
        (recdir / f"{fid}.json").write_text(json.dumps(
            {"body": fbody, "sigs": [{"actor": "attacker", "key": "00" * 32,
                                      "sig": "11" * 64}]}))
        case("negative control: the forgery satisfies address-matching "
             "(the old gate, by construction)", sha256(canon(fbody)) == fid)
        pre = snapshot(db)
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("forged (unsigned) acceptance: rebuild REFUSES to derive the edge",
             r.returncode != 0, out[-300:])
        case("the refusal cites verification, not addressing",
             "verify" in out, out[-300:])
        case("the existing projection was left untouched", snapshot(db) == pre)
        (recdir / f"{fid}.json").unlink()

        # Fail CLOSED: records exist and NOTHING can verify them. Deriving the
        # edges anyway would silently re-open case 7.
        r = subprocess.run(
            [sys.executable, "impl/oaip.py", "rebuild"], cwd=work,
            capture_output=True, text=True,
            env=dict(os.environ,
                     WARRANT_CLI=f"{sys.executable} /nonexistent/warrant.py"))
        out = r.stdout + r.stderr
        case("no runnable Warrant CLI: rebuild fails closed, says so",
             r.returncode != 0 and "no runnable Warrant" in out, out[-300:])

        # The honest store still rebuilds after all of the above.
        r = run("rebuild")
        case("the honest store still rebuilds cleanly", r.returncode == 0,
             r.stdout + r.stderr)

        # P2: an accept whose claim record is gone from the canonical layer was
        # skipped SILENTLY. A missing half of the protocol's central edge is at
        # least a warning.
        for p in (work / ".oaip" / "artifacts").iterdir():
            try:
                doc = json.loads(p.read_text())
            except ValueError:
                continue
            if isinstance(doc, dict) and doc.get("oaip_record") == "claim@v1":
                p.unlink()
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an accept naming a vanished claim: edge skipped WITH a warning",
             r.returncode == 0 and "WARN" in out and "no such claim" in out,
             out[-300:])

    with tempfile.TemporaryDirectory() as tmp:
        # --- case 8: the subject COLLISION. One execution, one predicate, two
        # claims with opposite checks — identical subject hashes by
        # construction, because the subject excludes the check and the verdict.
        work, run = make_repo(tmp)
        iid = run("intent", "collide").stdout.strip()
        r = run("run", "--intent", iid, "--", "sh", "-c", "echo hi > f.txt")
        eid = r.stdout.split()[1]
        ra = run("claim", "--execution", eid, "--predicate", "p",
                 "--check", "true")
        cid_a = ra.stdout.split()[1]
        r = run("accept", "--claim", cid_a, "--actor", "tester@local")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup(8): accept of the supported claim failed\n",
                  r.stdout, r.stderr)
            return 1
        rb = run("claim", "--execution", eid, "--predicate", "p",
                 "--check", "false")
        cid_b = rb.stdout.split()[1]
        case("setup: claim B is UNSUPPORTED", "UNSUPPORTED" in rb.stdout,
             rb.stdout)
        db = work / ".oaip" / "ledger.db"
        con = sqlite3.connect(db)
        subs = dict(con.execute("SELECT id, subject_hash FROM claims"))
        con.close()
        case("setup: the two claims collide (identical subject hashes)",
             subs[cid_a] == subs[cid_b], subs)

        before = snapshot(db)
        case("before rebuild: exactly one edge, to the supported claim",
             len(before["warrants"]) == 1
             and json.loads(before["warrants"][0])["claim_id"] == cid_a,
             before["warrants"])
        r = run("rebuild")
        case("rebuild ran", r.returncode == 0, r.stdout + r.stderr)
        after = snapshot(db)
        case("warrants table IDENTICAL across rebuild despite the collision "
             "(§5: the same graph)", before["warrants"] == after["warrants"],
             f"\n      before={before['warrants']}\n      after ={after['warrants']}")
        case("the FAILED claim gained no acceptance edge",
             all(json.loads(w)["claim_id"] != cid_b for w in after["warrants"]),
             after["warrants"])

        # LEGACY accepts carry no oaip-claim note; the fallback is subject-hash
        # matching restricted to SUPPORTED claims. File one directly with the
        # real key (bypassing cmd_accept, as any pre-fix store did).
        wcli = (os.environ.get("WARRANT_CLI")
                or f"{sys.executable} "
                   f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()
        rr = subprocess.run(
            wcli + ["--store", ".oaip/warrants", "accept",
                    "--subject", subs[cid_a], "--under", ".oaip/policy.txt",
                    "--reason", "legacy accept without a note",
                    "--actor", "legacy@local", "--key", ".oaip/dev.key"],
            cwd=work, capture_output=True, text=True)
        lwid = rr.stdout.strip().splitlines()[-1] if rr.stdout.strip() else ""
        if len(lwid) != 64:
            case("setup: legacy accept filed via the Warrant CLI", False,
                 rr.stdout + rr.stderr)
        else:
            r = run("rebuild")
            case("rebuild with a legacy accept ran", r.returncode == 0,
                 r.stdout + r.stderr)
            rows = [json.loads(w) for w in snapshot(db)["warrants"]]
            case("legacy accept: edge derived to the SUPPORTED claim only",
                 any(w["claim_id"] == cid_a and w["warrant_id"] == lwid
                     for w in rows)
                 and all(w["claim_id"] != cid_b for w in rows), rows)

    print("\nPROJECTION-REBUILD: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
