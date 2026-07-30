#!/usr/bin/env python3
"""A store written by the PRE-CHANGE code must still be readable (SPEC §6.4).

WHY THIS TEST EXISTS
--------------------
2026-07-30 aligned the reference implementation with SPEC §2: every record type
changed shape and the projection's columns changed with them. Ledgers written
before that exist, and the failure mode of a format change is never "it does not
work" — it is "it works, and quietly asserts something else". Three specific
ways this change could have broken one, each with a case below:

  1. `oaip log` on an old projection dies with `sqlite3.OperationalError: no
     such column: objective`. A traceback where the answer is one sentence.
  2. `oaip rebuild` reads the canonical layer, finds no record it recognises,
     and writes an EMPTY projection while exiting 0 — the ledger silently
     erased, reported as a successful reconstruction.
  3. The acceptance edge — the one fact this protocol exists to record — is not
     re-derived, because the legacy claim record is not a v0.1 claim and the
     derivation only looks at v0.1 claims.

THE FIXTURE IS THE REAL PRE-CHANGE PROGRAM
------------------------------------------
`tests/fixtures/oaip_prechange.py` is a byte copy of `impl/oaip.py` at commit
85298f0 ("merge feat/packaging: pip install oaip"), the last commit before the
record formats moved. It is VENDORED rather than fetched with `git show` because
CI checks out at depth 1: a test that needs history is a test that does not run
in CI, which is the exact failure this repository's check runner exists to make
impossible. Its SHA-256 is asserted below, so the copy cannot drift into
something that is not the pre-change program, and when history IS available the
first case compares the two byte for byte.

A store built by hand in the old SHAPE would not have tested this: the point is
that the actual previous release wrote it, including its real signed warrant.

AND THE SIGNATURE IT WROTE IS PRE-v1 (2026-07-31, Warrant SPEC v0.4)
--------------------------------------------------------------------
Warrant SPEC v0.4 / package 0.6.0 replaced the signed message with
`"warrant-sig-v1:" || WarrantID_raw`. The pinned fixture verifies the BARE
WarrantID and cannot be edited (that is what pinning it is for), so against a
current Warrant CLI it refuses its own acceptance and can build no store at all.
The conclusion is forced and is not a testing artefact: **every store the
previous release could have written carries a pre-v1 signature.** So the store
here is built through `tests/fixtures/legacy_signer.py`, which is the real
Warrant CLI with the pre-0.6.0 signature construction put back — the honest
reconstruction of a ledger from before the flag day, which is precisely what an
existing user has.

That splits this file's subject in two, and the split is the finding:

  * the RECORD SHAPES still migrate (cases 1, 2, 4, 5). §6.4 legacy-read is a
    syntactic question — the same facts, differently spelled — and it is
    unaffected.
  * the ACCEPTANCE EDGE does NOT survive (case 3, inverted from what it used to
    assert). That is a cryptographic question, not a syntactic one, and the two
    constructions are disjoint by design with no dual-accept window. A pre-v1
    signature gets a diagnosis naming the construction and the remedy, and NO
    edge — then `warrant resign` restores it. Routing this through §6.4's
    legacy-read framing would have handed an operator a flag that widens what
    counts as a valid signature, which is the one thing SPEC §8.6 forbids.
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
sys.path.insert(0, str(ROOT / "impl"))
import oaip as O                                              # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "oaip_prechange.py"
LEGACY_SIGNER = ROOT / "tests" / "fixtures" / "legacy_signer.py"
PRECHANGE_COMMIT = "85298f0"
PRECHANGE_SHA256 = ("ad6e54b9131c52a7bf51e477fde182b5cb1401faf919852e7053a19b"
                    "da4b4da6")
ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def warrant_argv():
    cli = os.environ.get("WARRANT_CLI")
    if cli:
        return cli.split()
    return [sys.executable, str(Path.home() / "Projects/warrant/impl/warrant.py")]


def make_repo(tmp):
    work = Path(tmp) / "w"
    work.mkdir()
    subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "init"], cwd=work,
                   check=True)
    return work


def rows(db, table):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        out = [dict(r) for r in con.execute(f"SELECT * FROM {table}")]
    finally:
        con.close()
    return out


def main():
    if not FIXTURE.is_file():
        print(f"FAIL  the pre-change fixture {FIXTURE} is missing — this check "
              "cannot be skipped past: without it nothing tests that an "
              "existing ledger survives the format change")
        return 1
    raw = FIXTURE.read_bytes()
    case("the fixture is the pre-change program, by hash",
         hashlib.sha256(raw).hexdigest() == PRECHANGE_SHA256,
         hashlib.sha256(raw).hexdigest())

    # When history is present (a normal clone, not CI's depth-1 checkout) the
    # vendored copy is checked against the commit it claims to come from. When
    # it is not, this case says so instead of silently passing.
    g = subprocess.run(["git", "show", f"{PRECHANGE_COMMIT}:impl/oaip.py"],
                       cwd=ROOT, capture_output=True)
    if g.returncode == 0:
        case(f"the fixture is byte-identical to {PRECHANGE_COMMIT}:impl/oaip.py",
             g.stdout == raw)
    else:
        print(f"NOTE  git history for {PRECHANGE_COMMIT} is not available here "
              "(a shallow checkout); the fixture was verified by hash only")

    with tempfile.TemporaryDirectory() as tmp:
        work = make_repo(tmp)
        old = work / "prechange.py"
        shutil.copy(FIXTURE, old)
        env = dict(os.environ)
        real_cli = env.get("WARRANT_CLI") or " ".join(warrant_argv())
        env["WARRANT_CLI"] = real_cli

        # The previous release only ever ran against a pre-0.6.0 Warrant, so
        # that is what it is given here — the real CLI with the pre-v1 signature
        # construction put back (see tests/fixtures/legacy_signer.py). Only
        # `run_old` gets it; the CURRENT implementation, which is what is under
        # test, always talks to the real CLI.
        old_env = dict(env, LEGACY_WARRANT_REAL_CLI=real_cli,
                       WARRANT_CLI=f"{sys.executable} {LEGACY_SIGNER}")

        def run_old(*a):
            return subprocess.run([sys.executable, str(old), *a], cwd=work,
                                  capture_output=True, text=True, env=old_env)

        def run_new(*a):
            return subprocess.run(
                [sys.executable, str(ROOT / "impl" / "oaip.py"), *a], cwd=work,
                capture_output=True, text=True, env=env)

        # --- a real ledger, written by the previous release, with a real
        # signed acceptance.
        run_old("init")
        r = run_old("do", "--intent", "add a file", "--check", "test -f f.txt",
                    "--actor", "tester@local", "--", "sh", "-c",
                    "echo hi >> f.txt")
        if "ACCEPTED" not in r.stdout:
            print("FAIL  setup: the pre-change program did not file an "
                  "acceptance\n", r.stdout, r.stderr)
            return 1
        db = work / ".oaip" / "ledger.db"
        old_edges = rows(db, "warrants")
        case("setup: the pre-change store has an acceptance edge",
             len(old_edges) == 1, old_edges)
        arts = sorted((work / ".oaip" / "artifacts").glob("*"))
        legacy_tags = []
        for p in arts:
            try:
                d = json.loads(p.read_bytes())
            except Exception:
                continue
            if isinstance(d, dict) and isinstance(d.get("oaip_record"), str):
                legacy_tags.append(d["oaip_record"])
        case("setup: its canonical layer really is in the pre-0.1 shape",
             sorted(legacy_tags) == ["claim@v1", "execution@v1", "intent@v1"],
             legacy_tags)
        wrecs = sorted((work / ".oaip" / "warrants" / "records").glob("*.json"))
        accept = next((p for p in wrecs
                       if json.loads(p.read_text())["body"].get("decision")
                       == "accept"), None)
        acc_env = json.loads(accept.read_text()) if accept else {"sigs": []}
        case("setup: and its acceptance really is signed under the PRE-v1 "
             "construction — the only one that release could produce",
             any(O.legacy_signature(accept.stem, s) for s in acc_env["sigs"])
             and not any(O.signature_verifies(accept.stem, s)
                         for s in acc_env["sigs"]),
             acc_env["sigs"])

        # --- 1. the old PROJECTION under the new code: a sentence, not a
        # traceback, and it says what to do.
        log = run_new("log")
        out = log.stdout + log.stderr
        case("an old projection is diagnosed, not crashed into",
             log.returncode != 0 and "Traceback" not in out, out[-300:])
        case("...and the diagnosis says the projection is disposable and names "
             "the fix",
             "oaip rebuild" in out and "DISPOSABLE" in out, out[-400:])

        # --- 1b. THE SIGNATURE COMES FIRST, AND IT IS A DIFFERENT QUESTION FROM
        # THE RECORD SHAPE (Warrant SPEC v0.4, OAIP SPEC §8.6). Before any of the
        # §6.4 shape migration can be measured, this store has to get past the
        # signature gate — and it does not, because its acceptance was signed
        # over the bare WarrantID. The refusal must name the construction and the
        # remedy; it must NOT offer to read the record "in legacy mode".
        rb0 = run_new("rebuild")
        out0 = rb0.stdout + rb0.stderr
        case("a pre-v1 signature refuses the rebuild before any shape question "
             "is reached", rb0.returncode != 0, out0[-400:])
        case("...and the refusal names the construction and the remedy",
             O.LEGACY_SIG_MESSAGE in out0, out0[-800:])
        case("...and does NOT offer --allow-legacy-links: a pre-v1 SIGNATURE is "
             "not a pre-0.1 RECORD (SPEC §8.6)",
             "allow-legacy-links" not in out0 and "8.6" in out0, out0[-800:])
        case("...and derived no acceptance edge from it",
             not (work / ".oaip" / "ledger.db").is_file()
             or (work / ".oaip" / "projection.untrusted").is_file())

        # THE REMEDY, run exactly as the diagnosis prints it. This is what an
        # existing user does, once, before the record-shape migration below is
        # even a question.
        rs = subprocess.run(warrant_argv() + ["--store", ".oaip/warrants",
                                              "resign", "--key",
                                              ".oaip/dev.key"],
                            cwd=work, capture_output=True, text=True)
        case("`warrant resign --key .oaip/dev.key` migrates the store's "
             "signatures", rs.returncode == 0, (rs.stdout + rs.stderr)[-400:])
        after = json.loads(accept.read_text())
        case("...and the WarrantID did not move: the record is still at its own "
             "address (only `sigs` changed, and `sigs` is not hashed)",
             after["body"] == acc_env["body"]
             and any(O.signature_verifies(accept.stem, s)
                     for s in after["sigs"]))

        # --- 2. rebuild reads the legacy canonical layer rather than emptying
        # the ledger. THIS is the §6.4 question, and it is untouched by the
        # signature change: the same facts, differently spelled.
        rb = run_new("rebuild")
        rout = rb.stdout + rb.stderr
        case("rebuild of a pre-0.1 store succeeds", rb.returncode == 0,
             rout[-500:])
        case("...and says out loud that it read pre-0.1 records",
             "PRE-0.1" in rout and "6.4" in rout, rout[-500:])
        case("...and did not quietly write an empty projection",
             "legacy=4" in rout, rout[-300:])

        ints, exes, clms = (rows(db, "intents"), rows(db, "executions"),
                            rows(db, "claims"))
        case("the intent survived", len(ints) == 1 and ints[0]["objective"],
             ints)
        case("the execution survived",
             len(exes) == 1 and exes[0]["exit_code"] == 0, exes)
        case("the claim survived and its verdict was translated",
             len(clms) == 1 and clms[0]["verdict"] == "pass", clms)
        case("every legacy-derived row is MARKED as such (§6.4)",
             all(r["format"] == "oaip_record@v1"
                 for r in ints + exes + clms),
             [r["format"] for r in ints + exes + clms])
        case("a legacy execution's state columns are NOT presented as StateIDs",
             len(exes[0]["input_state"]) == 40 and exes[0]["status"] is None,
             exes[0])

        # --- 3. THE FACT THAT MATTERS: the acceptance edge, re-derived from a
        # legacy claim record and a warrant filed by the previous release.
        new_edges = rows(db, "warrants")
        case("the acceptance edge survived the format change",
             [(e["claim_id"], e["warrant_id"]) for e in new_edges]
             == [(e["claim_id"], e["warrant_id"]) for e in old_edges],
             f"before={old_edges} after={new_edges}")
        lg = run_new("log")
        case("`oaip log` still prints the WARRANT line",
             "WARRANT" in lg.stdout, lg.stdout)
        case("...and marks the legacy record rather than passing it off as 0.1",
             "legacy" in lg.stdout, lg.stdout)

        # --- 4. nothing was rewritten in place (§6.4: the address is cited by
        # the Warrant store).
        after_arts = sorted((work / ".oaip" / "artifacts").glob("*"))
        case("no legacy artifact was rewritten or removed",
             set(p.name for p in arts) <= set(p.name for p in after_arts),
             sorted(set(p.name for p in arts)
                    - set(p.name for p in after_arts)))

        # --- 5. and the ledger keeps working: a NEW action on the same store
        # is written in v0.1 shape (migration is read-side).
        r2 = run_new("do", "--intent", "add another", "--check", "test -f g.txt",
                     "--actor", "tester@local", "--", "sh", "-c",
                     "echo two >> g.txt")
        case("a new action on a migrated store still accepts",
             "ACCEPTED" in r2.stdout, (r2.stdout + r2.stderr)[-400:])
        ints2 = rows(db, "intents")
        case("the new records are v0.1 and the old ones are still legacy",
             sorted(r["format"] for r in ints2) == ["0.1", "oaip_record@v1"],
             [r["format"] for r in ints2])
        v = run_new("verify")
        case("verify passes over the mixed-format ledger", v.returncode == 0,
             (v.stdout + v.stderr)[-400:])
        case("a legacy execution's fingerprints are UNREPRODUCIBLE, and said so "
             "rather than left silent (§2.2.4 + §6.4)",
             "unreproducible" in (v.stdout + v.stderr)
             and "1 unreproducible" in v.stdout, v.stdout)
        case("...and reports the legacy records as legacy, not as corruption",
             "legacy" in (v.stdout + v.stderr)
             and "does not match its own address" not in v.stdout,
             (v.stdout + v.stderr)[-400:])

    print("\nLEGACY-STORE: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
