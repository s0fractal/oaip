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
   decision)" for it (2026-07-30 adversarial review). Rebuild refuses the whole
   rebuild when the store does not verify, and when no Warrant CLI can run at
   all. That was NOT sufficient on its own — see case 9.
8. A subject COLLISION cannot project an acceptance onto a FAILED claim. The
   claim subject {predicate, execution, effects} excludes the check command and
   verdict, so `--check true` and `--check false` over one execution collide;
   subject-hash edge derivation attached the real signed warrant to the
   UNSUPPORTED claim after rebuild (§5 MUST violation, same review). New
   accepts carry an explicit oaip-claim:<id> note; rebuild follows that.
8b. The FALLBACK for note-less records was itself ATTACKER-SELECTABLE. "Has no
   note" is the writer's choice, and `note.startswith("oaip-claim:")` made even
   the prefix's LETTER CASE the writer's choice — so anyone able to file an
   accept, using this project's own real key, could route it to subject-hash
   guessing in a brand-new store. The prefix is now matched case-insensitively,
   and the fallback needs BOTH `--allow-legacy-links` AND a record older than the
   note convention as stamped in `.oaip/store.json` by `init` — a criterion the
   filer of a record cannot choose.
9. An ATTACKER'S OWN KEY cannot launder an acceptance. Case 7 only rules out
   signatures no key produced; this one is cryptographically perfect — a fresh
   `warrant keygen` key signs a well-formed accept naming a real SUPPORTED claim
   nobody accepted, claiming an actor id it does not own. `warrant verify` exits
   0 for it BY SPECIFICATION (Warrant SPEC §5 puts key↔actor binding out of
   scope; §5.1 makes bound/unbound "a report"), so before this case `oaip
   rebuild` printed warrant=1 and `oaip log` printed "(signed decision)" for it.
   OAIP now requires the signer to be bound to the actor in its own keyring
   (`.oaip/trust.json`). The same block pins two ways the gate was evadable:
   `WARRANT_CLI=/usr/bin/true` (exit 0 is not a verification — the CLI must emit
   a parseable `warrant.verify-report@v0`), and a CLI that never exits (every
   call is timeout-bounded).
10. CONCURRENCY. `rebuild` deleted the projection and rebuilt it in place, with
   nothing excluding a second rebuild and NO UNIQUE constraint on the protocol's
   central edge: four concurrent rebuilds left four identical rows for one store
   record, and a concurrent accept + rebuild raised an uncaught
   sqlite3.OperationalError and lost the insert. Rebuild now holds an advisory
   lock, builds under a temporary name and `os.replace`s it into place, and the
   edge is UNIQUE(claim_id, warrant_id).
"""
import hashlib
import time
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# THE TRUST ROOT IS NO LONGER IN THE WORKSPACE (O4, 2026-07-30), so every ledger
# this file creates keeps its key and keyring under a THROWAWAY
# XDG_CONFIG_HOME. Set in the environment rather than passed per-run, so that
# every subprocess inherits it — including the ones that rebuild the environment
# from scratch — and so no test run writes into the operator's own ~/.config.
import atexit as _atexit                                          # noqa: E402
import shutil as _shutil                                          # noqa: E402
import tempfile as _tempfile                                      # noqa: E402
_XDG = _tempfile.mkdtemp(prefix="oaip-test-xdg-")
os.environ["XDG_CONFIG_HOME"] = _XDG
_atexit.register(lambda: _shutil.rmtree(_XDG, ignore_errors=True))


def trust_root(work):
    """Where this ledger's key and keyring actually live — asked of the tool,
    not recomputed here, so the test cannot disagree with the implementation
    about the one path the whole property is about."""
    r = subprocess.run([sys.executable, str(ROOT / "impl" / "oaip.py"),
                        "trust-root", "--path"], cwd=work,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot resolve the trust root in {work}: "
                         f"{r.stdout}{r.stderr}")
    return Path(r.stdout.strip())
# `warrants` was deliberately absent from this tuple until 2026-07-30, which is
# how the projection could silently lose the claim→warrant edge on rebuild —
# the one fact this protocol exists to record. It is in the graph; it is in the
# comparison.
#
# `artifacts` was absent for the same reason and cost the same kind of fact:
# rebuild inserted every artifact as kind "rebuilt", destroying "record:claim",
# "claim-subject", "stdout" and "check-transcript" on a CLEAN, honest store — a
# real post-rebuild graph difference that six-of-seven tables could not show
# (2026-07-30, second adversarial round). The tuple is now every table the
# schema defines, and `schema_tables_are_all_compared` below refuses to let a
# future table be added to the schema and forgotten here.
TABLES = ("intents", "states", "executions", "effects", "claims",
          "attributions", "warrants", "artifacts")
ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def snapshot(db):
    """Every row of every table, as comparable text.

    Nothing is dropped any more. `effects.id` used to be an AUTOINCREMENT
    surrogate (and `attributions.effect_id` pointed at it), so both had to be
    excluded from the comparison — a rebuild was allowed to renumber rows it
    never promised to preserve. §2.5/§2.6 give Effect and Attribution real
    record ids, so those two columns are now facts the canonical layer asserts
    and the comparison holds them too.
    """
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    out = {}
    for t in TABLES:
        rows = []
        for r in con.execute(f"SELECT * FROM {t}"):
            rows.append(json.dumps(dict(r), sort_keys=True))
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
        # EVERY table the schema defines is compared. Twice now a fact has
        # survived rebuild-as-code and died in the comparison instead, because
        # this tuple was shorter than the schema: the claim→warrant edge, then
        # `artifacts.kind`. So the tuple is checked against the database itself.
        con = sqlite3.connect(db)
        schema_tables = sorted(
            r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE "
                                      "type='table' AND name NOT LIKE 'sqlite_%'"))
        con.close()
        case("every table in the schema is in the comparison "
             "(the comparison cannot be shorter than the graph)",
             schema_tables == sorted(TABLES),
             f"schema={schema_tables} compared={sorted(TABLES)}")

        before = snapshot(db)
        case("a live run produced a graph",
             all(before[t] for t in ("intents", "executions", "effects",
                                     "claims", "warrants", "artifacts")))

        # The artifact KINDS, named individually: "rebuilt" for all of them was
        # the defect, and a diff of two dictionaries would not say which fact went.
        kinds_before = {json.loads(r)["hash"]: json.loads(r)["kind"]
                        for r in before["artifacts"]}
        for want in ("record:intent", "record:state", "record:execution",
                     "record:effect", "record:attribution", "record:claim",
                     "claim-subject", "environment-probe", "toolchain-probe",
                     "check", "stdout"):
            case(f"artifacts carry kind {want!r} before rebuild",
                 want in kinds_before.values(), sorted(set(kinds_before.values())))

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
        for field in ("invocation", "status", "exit_code", "input_state",
                      "output_state", "environment", "output", "intent_id",
                      "actor", "runtime"):
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
        for field in ("invocation", "status", "exit_code", "input_state",
                      "output_state", "environment", "output", "intent_id",
                      "actor", "runtime"):
            case(f"execution.{field} survived the projection",
                 ex2.get(field) == ex.get(field),
                 f"before={ex.get(field)!r} after={ex2.get(field)!r}")

        wr2 = json.loads(after["warrants"][0]) if after["warrants"] else {}
        for field in ("claim_id", "warrant_id", "created_at"):
            case(f"warrant.{field} survived the projection",
                 wr2.get(field) == wr.get(field),
                 f"before={wr.get(field)!r} after={wr2.get(field)!r}")
        kinds_after = {json.loads(r)["hash"]: json.loads(r)["kind"]
                       for r in after["artifacts"]}
        case("artifacts.kind survived the projection (not all 'rebuilt')",
             kinds_after == kinds_before,
             f"before={sorted(set(kinds_before.values()))} "
             f"after={sorted(set(kinds_after.values()))}")

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

        # P3 (F12): a DIRECTORY named <hex64>.json is a legal record ADDRESS that
        # is not a record. The except clause had been narrowed to ValueError, so
        # `read_bytes()` raised IsADirectoryError and a traceback replaced every
        # diagnosis. Same for a directory at an artifact address.
        (recdir / f"{'a' * 64}.json").mkdir()
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("a DIRECTORY at a record address: a refusal, not a traceback",
             r.returncode != 0 and "Traceback" not in out
             and "IsADirectoryError" in out and "not a record" in out, out[-300:])
        (recdir / f"{'a' * 64}.json").rmdir()
        (work / ".oaip" / "artifacts" / ("b" * 64)).mkdir()
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("a DIRECTORY at an artifact address: a refusal, not a traceback",
             r.returncode != 0 and "Traceback" not in out
             and "not an artifact" in out, out[-300:])
        (work / ".oaip" / "artifacts" / ("b" * 64)).rmdir()

        # P3 (F13): a fault in the DECISION layer used to be announced as
        # "corrupt artifact(s) in the canonical layer", sending the reader to the
        # wrong directory. Name the layer that is actually broken.
        stray = recdir / "notes.json"
        stray.write_bytes(b"")
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("a store-layer fault is diagnosed as a DECISION-layer fault",
             "decision layer" in out and "corrupt artifact" not in out,
             out[-300:])
        stray.unlink()
        art = next(p for p in (work / ".oaip" / "artifacts").iterdir()
                   if p.is_file())
        keep = art.read_bytes()
        art.write_bytes(keep + b" ")
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an artifact-layer fault still names the ARTIFACT directory",
             "corrupt artifact" in out and ".oaip/artifacts" in out, out[-300:])
        art.write_bytes(keep)

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
        # least a warning — and, since the third adversarial round (C2-F1b), a
        # non-zero exit: the previous projection asserted that edge, this one
        # cannot, and "the same graph" is exactly what §5 promised. A rebuild
        # that drops the protocol's central fact must not report success.
        for p in (work / ".oaip" / "artifacts").iterdir():
            try:
                doc = json.loads(p.read_text())
            except ValueError:
                continue
            if isinstance(doc, dict) and doc.get("claim") == "0.1":
                p.unlink()
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an accept naming a vanished claim: edge skipped WITH a warning",
             "WARN" in out and "no such claim" in out, out[-300:])
        case("...and the rebuild that dropped the edge does NOT exit 0",
             r.returncode != 0 and "LOST an acceptance edge" in out, out[-400:])

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

        # --- case 8b (F8): THE FALLBACK WAS ATTACKER-SELECTABLE.
        #
        # "Carries no oaip-claim note" is a property the WRITER chooses, and
        # `note.startswith("oaip-claim:")` made even the prefix's LETTER CASE the
        # writer's choice. So anyone who could file an accept could route it to
        # the weaker subject-hash path in a brand-new store and fan one warrant
        # onto every claim with a colliding subject — using this project's own
        # real key, so nothing about the signature was wrong. Reproduced before
        # the fix: both filings below produced an edge and `oaip verify` reported
        # 0 errors.
        #
        # `--actor tester@local`, the actor case 8's own accept already bound to
        # this ledger's key: these cases are about the LINK, and an unbound actor
        # would make them pass or fail for the F7 reason instead.
        wcli = (os.environ.get("WARRANT_CLI")
                or f"{sys.executable} "
                   f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()

        def file_accept(*extra, reason="direct filing"):
            rr = subprocess.run(
                wcli + ["--store", ".oaip/warrants", "accept",
                        "--subject", subs[cid_a], "--under", ".oaip/policy.txt",
                        "--reason", reason, *extra,
                        "--actor", "tester@local",
                    "--key", str(trust_root(work) / "dev.key")],
                cwd=work, capture_output=True, text=True)
            out = rr.stdout.strip().splitlines()
            return out[-1] if out else ""

        nowid = file_accept(reason="no note at all")
        cvwid = file_accept("--note", f"OAIP-CLAIM:{cid_b}",
                            reason="a case-variant prefix")
        if len(nowid) != 64 or len(cvwid) != 64:
            case("setup(8b): both downgrade attempts filed via the Warrant CLI",
                 False, f"{nowid!r} {cvwid!r}")
        else:
            r = run("rebuild")
            out = r.stdout + r.stderr
            case("rebuild with two link-downgraded accepts ran",
                 r.returncode == 0, out[-400:])
            rows = [json.loads(w) for w in snapshot(db)["warrants"]]
            wids = {w["warrant_id"] for w in rows}
            case("note OMITTED in a store that requires one: NO edge derived",
                 nowid not in wids, rows)
            case("the refusal says which fact is missing (which claim, not "
                 "which signature)", "carries no oaip-claim" in out, out[-500:])
            case("case-variant prefix `OAIP-CLAIM:` is the EXPLICIT link, not a "
                 "downgrade: it is read, and refused for naming the FAILED claim",
                 cvwid not in wids and "check FAILED" in " ".join(out.split()),
                 out[-600:])
            case("the FAILED claim still has no acceptance edge",
                 all(w["claim_id"] != cid_b for w in rows), rows)
            case("the one honest edge is untouched",
                 [w["claim_id"] for w in rows] == [cid_a], rows)

            # --allow-legacy-links does NOT cover a record this store's own
            # format marker says had every chance to carry the link.
            r = run("rebuild", "--allow-legacy-links")
            out = r.stdout + r.stderr
            rows = [json.loads(w) for w in snapshot(db)["warrants"]]
            case("--allow-legacy-links does not resurrect a NON-legacy record",
                 nowid not in {w["warrant_id"] for w in rows}
                 and "not a legacy record" in out, out[-500:])

            # A store with NO format marker may genuinely predate the note
            # convention. There, and only there, the operator can opt in — and is
            # told exactly what the guess can get wrong.
            (work / ".oaip" / "store.json").unlink()
            r = run("rebuild", "--allow-legacy-links")
            out = r.stdout + r.stderr
            rows = [json.loads(w) for w in snapshot(db)["warrants"]]
            case("a store with no format marker + explicit opt-in: the legacy "
                 "edge IS derived, to the SUPPORTED claim only",
                 any(w["claim_id"] == cid_a and w["warrant_id"] == nowid
                     for w in rows)
                 and all(w["claim_id"] != cid_b for w in rows), rows)
            case("and the opt-in prints a loud warning naming the risk",
                 "GUESSING by subject hash" in out
                 and "never accepted" in out, out[-500:])
            r = run("rebuild")
            case("without the flag the same store derives no legacy edge",
                 nowid not in {json.loads(w)["warrant_id"]
                               for w in snapshot(db)["warrants"]},
                 r.stdout + r.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        # --- case 8c (C3-F1, THIRD adversarial round): THE STORE-FORMAT MARKER
        # FAILED OPEN. `note_convention_since()` returned None — "this store
        # predates the convention" — for every unreadable `.oaip/store.json`:
        # truncated file, missing field, wrong type. So one corrupt byte promoted
        # a BRAND-NEW store to a legacy one, and `--allow-legacy-links` then ran
        # the subject-hash guess while printing the false sentence "Only records
        # filed before this store had a format marker are eligible" — about a
        # store that has one, sitting right there. A marker that is present and
        # unreadable is the one case where OAIP knows that it does not know.
        work, run = make_repo(tmp)
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup(8c): the one-shot flow did not accept\n",
                  r.stdout, r.stderr)
            return 1
        db = work / ".oaip" / "ledger.db"
        con = sqlite3.connect(db)
        cid, subj = con.execute("SELECT id, subject_hash FROM claims").fetchone()
        con.close()
        wcli = (os.environ.get("WARRANT_CLI")
                or f"{sys.executable} "
                   f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()
        rr = subprocess.run(
            wcli + ["--store", ".oaip/warrants", "accept", "--subject", subj,
                    "--under", ".oaip/policy.txt", "--reason", "no note at all",
                    "--actor", "tester@local",
                    "--key", str(trust_root(work) / "dev.key")],
            cwd=work, capture_output=True, text=True)
        nowid = (rr.stdout.strip().splitlines() or [""])[-1]
        if len(nowid) != 64:
            print("FAIL  setup(8c): the note-less accept did not file\n",
                  rr.stdout, rr.stderr)
            return 1
        meta = work / ".oaip" / "store.json"
        honest_marker = meta.read_bytes()
        for name, content in (("truncated", b"{\"oaip_store\": \"oaip-st"),
                              ("field missing",
                               b'{"oaip_store":"oaip-store@v1"}'),
                              ("field of the wrong type",
                               b'{"note_convention_since":"soon",'
                               b'"oaip_store":"oaip-store@v1"}')):
            meta.write_bytes(content)
            r = run("rebuild", "--allow-legacy-links")
            out = r.stdout + r.stderr
            case(f"a store.json that is {name}: rebuild REFUSES",
                 r.returncode != 0, out[-300:])
            case(f"...and does NOT run the subject-hash guess ({name})",
                 "GUESSING by subject hash" not in out, out[-300:])
            case(f"...and does not claim the store has no marker ({name})",
                 "this store had a format marker" not in out, out[-400:])
            case(f"...and names this ledger's own metadata, not another layer "
                 f"({name})", "store.json" in out and "corrupt artifact" not in out,
                 out[-300:])
            rows = [json.loads(w) for w in snapshot(db)["warrants"]]
            case(f"...and no legacy edge was written ({name})",
                 all(w["warrant_id"] != nowid for w in rows), rows)
        meta.write_bytes(honest_marker)
        r = run("rebuild", "--allow-legacy-links")
        case("with the marker restored, the same store rebuilds again",
             r.returncode == 0, (r.stdout + r.stderr)[-300:])

    with tempfile.TemporaryDirectory() as tmp:
        # --- case 9 (F7/F3): AN ATTACKER'S OWN KEY MUST NOT LAUNDER AN ACCEPTANCE.
        #
        # Case 7 above only rules out signatures no key produced. This one is
        # cryptographically PERFECT: a freshly generated Ed25519 key signs a
        # well-formed accept naming a real, SUPPORTED claim that nobody accepted,
        # claiming an actor id it does not own. `warrant verify` exits 0 for it —
        # by SPECIFICATION, since Warrant SPEC §5 puts key↔actor binding out of
        # scope and §5.1 makes bound/unbound "a report". Measured on this branch
        # before the fix: `oaip rebuild` -> warrant=1 and `oaip log` printed
        # "WARRANT 41d32da62a81…  (signed decision)" for a claim nobody accepted.
        #
        # So the binding must be enforced by OAIP, over OAIP's own keyring
        # (.oaip/trust.json), which only `oaip accept` and `oaip bind` write.
        work, run = make_repo(tmp)
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup(9): the one-shot flow did not accept\n",
                  r.stdout, r.stderr)
            return 1
        real_edges = len(snapshot(work / ".oaip" / "ledger.db")["warrants"])

        # a SECOND claim, supported, that nobody ever accepted
        iid = run("intent", "unaccepted").stdout.strip()
        eid = run("run", "--intent", iid, "--", "sh", "-c",
                  "echo two > g.txt").stdout.split()[1]
        cid = run("claim", "--execution", eid, "--predicate", "q",
                  "--check", "true").stdout.split()[1]
        con = sqlite3.connect(work / ".oaip" / "ledger.db")
        subj_hash = con.execute("SELECT subject_hash FROM claims WHERE id=?",
                                (cid,)).fetchone()[0]
        con.close()

        wcli = (os.environ.get("WARRANT_CLI")
                or f"{sys.executable} "
                   f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()
        w = lambda *a: subprocess.run(list(wcli) + list(a), cwd=work,
                                      capture_output=True, text=True)
        w("keygen", "--out", "attacker.key")
        shutil.copy(work / ".oaip" / "artifacts" / subj_hash, work / "subj.json")
        sb = w("--store", ".oaip/warrants", "blob", "add", "subj.json").stdout.strip()
        pol = w("--store", ".oaip/warrants", "blob", "add",
                ".oaip/policy.txt").stdout.strip()
        rr = w("--store", ".oaip/warrants", "accept", "--subject", sb,
               "--under", pol, "--reason", "an acceptance nobody made",
               "--note", f"oaip-claim:{cid}", "--actor", "tester@local",
               "--key", "attacker.key")
        fwid = rr.stdout.strip().splitlines()[-1] if rr.stdout.strip() else ""
        if len(fwid) != 64:
            print("FAIL  setup(9): the attacker's accept did not file\n",
                  rr.stdout, rr.stderr)
            return 1

        # THE NEGATIVE CONTROL: the old gate — `warrant verify` exiting 0 — is
        # fully satisfied. If this ever stops holding, the cases below prove
        # nothing about OAIP, only that Warrant changed.
        vr = w("--store", ".oaip/warrants", "verify")
        case("negative control: `warrant verify` exits 0 for the attacker's "
             "accept (binding is a WARN by Warrant SPEC §5)",
             vr.returncode == 0 and "binding" not in vr.stdout.lower()
             or vr.returncode == 0, vr.stdout + vr.stderr)

        r = run("rebuild")
        out = r.stdout + r.stderr
        case("attacker-keyed accept: rebuild still rebuilds the honest records",
             r.returncode == 0, out[-400:])
        rows = [json.loads(x) for x in
                snapshot(work / ".oaip" / "ledger.db")["warrants"]]
        case("attacker-keyed accept: NO acceptance edge was derived from it",
             all(x["warrant_id"] != fwid for x in rows), rows)
        case("the honest acceptance edge is still there",
             len(rows) == real_edges, rows)
        case("the refusal names the BINDING, not the signature bytes",
             "not bound to" in out.lower() and "trust.json" in out, out[-400:])
        case("the impersonated claim gets no WARRANT line in `oaip log`",
             fwid[:16] not in run("log").stdout, run("log").stdout)
        vr = run("verify")
        case("`oaip verify` now FAILS on an acceptance with an unknown signer",
             vr.returncode != 0 and fwid[:12] in (vr.stdout + vr.stderr),
             (vr.stdout + vr.stderr)[-400:])

        # F9: the gate must not be "some program exited 0". /usr/bin/true is a
        # runnable file that exits 0 having verified nothing, and it re-opened
        # case 7 in full: rebuild derived every edge from an unverified store.
        (work / ".oaip" / "warrants" / "records" / f"{fwid}.json").unlink()
        r = subprocess.run([sys.executable, "impl/oaip.py", "rebuild"], cwd=work,
                           capture_output=True, text=True,
                           env=dict(os.environ, WARRANT_CLI="/usr/bin/true"))
        out = r.stdout + r.stderr
        case("a stub CLI that merely exits 0 does not pass as a verifier",
             r.returncode != 0 and "verify-report" in out, out[-400:])

        # F11: a CLI that never exits used to hang rebuild forever, silently.
        sleeper = work / "sleeper.py"
        sleeper.write_text("import time\ntime.sleep(600)\n")
        t0 = time.time()
        r = subprocess.run([sys.executable, "impl/oaip.py", "rebuild"], cwd=work,
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ,
                                    WARRANT_CLI=f"{sys.executable} {sleeper}",
                                    OAIP_WARRANT_TIMEOUT="3"))
        out = r.stdout + r.stderr
        case("a Warrant CLI that never exits is a bounded refusal, not a hang",
             r.returncode != 0 and time.time() - t0 < 45, f"{time.time()-t0:.0f}s "
             + out[-300:])

        # C2-F2 (third adversarial round): the BOUND ITSELF was parsed with a
        # bare `int()` at import time, so `OAIP_WARRANT_TIMEOUT=notanint` killed
        # EVERY subcommand with a ValueError traceback pointing at a line of
        # oaip.py rather than at the variable the operator set. A setting that
        # cannot be used is refused by name.
        def with_timeout(value, *argv):
            return subprocess.run([sys.executable, "impl/oaip.py", *argv],
                                  cwd=work, capture_output=True, text=True,
                                  env=dict(os.environ,
                                           OAIP_WARRANT_TIMEOUT=value))

        for bad in ("notanint", "0", "-5", "12.5"):
            rr = with_timeout(bad, "log")
            out = rr.stdout + rr.stderr
            case(f"OAIP_WARRANT_TIMEOUT={bad!r}: a diagnosis, not a traceback",
                 rr.returncode != 0 and "Traceback" not in rr.stderr
                 and "OAIP_WARRANT_TIMEOUT" in out,
                 f"rc={rr.returncode} {out[-200:]}")
        # The negative control: a usable value is not refused, and neither is an
        # empty one (which means "unset", i.e. the 120s default).
        for good in ("30", " "):
            rr = with_timeout(good, "rebuild")
            out = rr.stdout + rr.stderr
            case(f"OAIP_WARRANT_TIMEOUT={good!r} is accepted",
                 "OAIP_WARRANT_TIMEOUT" not in out
                 and "Traceback" not in rr.stderr, f"rc={rr.returncode} {out[-200:]}")

        # And the honest store still rebuilds, with the real edge intact.
        r = run("rebuild")
        rows = [json.loads(x) for x in
                snapshot(work / ".oaip" / "ledger.db")["warrants"]]
        case("after all of the above the honest store rebuilds, edge intact",
             r.returncode == 0 and len(rows) == real_edges,
             r.stdout + r.stderr + str(rows))

    with tempfile.TemporaryDirectory() as tmp:
        # --- case 10 (F10): CONCURRENCY. `rebuild` deleted ledger.db and rebuilt
        # it in place, with nothing excluding a second rebuild and no UNIQUE
        # constraint on the protocol's central edge. Measured before the fix: four
        # concurrent `oaip rebuild` runs left FOUR identical rows for ONE store
        # record, and — depending on timing — a FileNotFoundError traceback from
        # `DB.unlink()` racing another process's unlink. A concurrent accept +
        # rebuild raised an uncaught sqlite3.OperationalError and lost the insert.
        work, run = make_repo(tmp)
        r = run("do", "--intent", "add a file", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup(10): the one-shot flow did not accept\n",
                  r.stdout, r.stderr)
            return 1
        db = work / ".oaip" / "ledger.db"
        expect = snapshot(db)

        procs = [subprocess.Popen([sys.executable, "impl/oaip.py", "rebuild"],
                                  cwd=work, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
                 for _ in range(4)]
        outs = [(p.wait(timeout=180), p.stdout.read()) for p in procs]
        case("4 concurrent rebuilds: none tracebacks",
             all("Traceback" not in o for _, o in outs),
             next((o for _, o in outs if "Traceback" in o), "")[-400:])
        case("4 concurrent rebuilds: all succeed",
             all(rc == 0 for rc, _ in outs), str([rc for rc, _ in outs]))
        got = snapshot(db)
        case("4 concurrent rebuilds: ONE edge per store record, not four",
             got["warrants"] == expect["warrants"],
             f"\n      expect={expect['warrants']}\n      got   ={got['warrants']}")
        case("4 concurrent rebuilds: the whole graph is still the same graph",
             got == expect, [t for t in TABLES if got[t] != expect[t]])

        # The edge is UNIQUE in the schema, so even a single-process double insert
        # cannot double-count it. Named separately from the race, because the race
        # is timing and the constraint is a fact about the projection.
        con = sqlite3.connect(db)
        sql = con.execute("SELECT sql FROM sqlite_master WHERE name='warrants'"
                          ).fetchone()[0]
        con.close()
        case("the acceptance edge carries a UNIQUE constraint",
             "UNIQUE" in sql.upper(), sql)

        # accept racing rebuild: the insert must survive, not vanish.
        iid = run("intent", "concurrent").stdout.strip()
        eid = run("run", "--intent", iid, "--", "sh", "-c",
                  "echo z > z.txt").stdout.split()[1]
        cid = run("claim", "--execution", eid, "--predicate", "z",
                  "--check", "true").stdout.split()[1]
        pa = subprocess.Popen([sys.executable, "impl/oaip.py", "accept",
                               "--claim", cid, "--actor", "tester@local"],
                              cwd=work, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        pr = subprocess.Popen([sys.executable, "impl/oaip.py", "rebuild"],
                              cwd=work, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        oa, orb = pa.communicate(timeout=180), pr.communicate(timeout=180)
        case("accept racing rebuild: neither tracebacks",
             "Traceback" not in oa[0] and "Traceback" not in orb[0],
             (oa[0] + orb[0])[-400:])
        case("accept racing rebuild: both succeed",
             pa.returncode == 0 and pr.returncode == 0,
             f"accept={pa.returncode} rebuild={pr.returncode} "
             + (oa[0] + orb[0])[-300:])
        # Whichever order they ran in, one more rebuild must SEE the acceptance:
        # the Warrant record is canonical, so an insert lost from the projection is
        # recoverable — but only if the record was filed at all.
        run("rebuild")
        rows = [json.loads(x) for x in snapshot(db)["warrants"]]
        case("accept racing rebuild: the acceptance is not lost",
             any(x["claim_id"] == cid for x in rows), rows)

    print("\nPROJECTION-REBUILD: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
