#!/usr/bin/env python3
"""Express an OAIP claim as an in-toto Statement v1 — and say what OAIP is not.

WHY THIS FILE EXISTS AT ALL
---------------------------
An external audit (2026-07-30) put it plainly: OAIP partly reinvents in-toto
Attestation, SLSA Provenance and OpenTelemetry span semantics while citing none of
them. Checked before accepting: `in-toto`, `SLSA`, `OpenTelemetry` and `Sigstore`
appear nowhere in this repository's SPEC or README. The finding is correct.

That is a strategic risk, not a bug. A parallel universe competes with the world's
existing habit and loses; a layer on top of it inherits the tooling. So the honest
map, record type by record type:

  Execution         ~ SLSA `runDetails` / an OpenTelemetry span
                      (invocation, environment, status, exit code, parent intent)
  Effect            ~ SLSA byproducts / materials
                      (before/after content hashes of what changed)
  Artifact, State   ~ in-toto ResourceDescriptor
                      (a citable blob; a workspace snapshot)
  ClaimCandidate    ~ in-toto Statement
                      (subject digest + a predicate + evidence)

Those four are duplication, and the right move is to be *expressible as* them
rather than to re-specify them.

WHAT IS ACTUALLY NEW HERE, AND WHERE NEITHER STANDARD REACHES
-------------------------------------------------------------
Two things, and they are the reason OAIP is not simply deleted in favour of
in-toto:

1. **The acceptance boundary (SPEC §4).** in-toto and SLSA attest what *happened*.
   Neither has a notion of a claim being *accepted*, nor of a refusal being a
   record rather than the absence of one. `exit_code = 0` earns nothing here; the
   validation check is separate from the execution, and acceptance is separate
   from both. An attestation ecosystem that cannot express "this ran, and was
   refused" is missing the case that matters for agent accountability.

2. **Attribution with declared uncertainty.** `confidence_ppm` as an integer, with
   `method` naming how the causal link was drawn. in-toto has no vocabulary for
   "probably this agent, by this inference, at this confidence" — and an honest
   0.8 beats a deterministic lie about who caused a change.

So the position this file implements: **OAIP's observations belong in the existing
ecosystem, and its `ClaimCandidate` is published as an in-toto predicateType** so
a reader with Sigstore, Rekor or any in-toto verifier can consume it. The
acceptance decision itself is not an attestation at all — it is a Warrant record,
which is a different object with a different trust model (SPEC §3).

LIMITS
------
Not signed here: DSSE wrapping and Rekor submission are separate steps with
separate trust, deliberately not hidden inside a converter. The predicateType is
under a URI this project controls, not a domain it does not own.

USAGE
    python3 tools/intoto.py wrap <claim-id>       # Statement on stdout
    python3 tools/intoto.py check <statement>     # does it bind to the ledger?
    python3 tools/intoto.py selftest
"""
import argparse
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

OAIP = Path(".oaip")
DB = OAIP / "ledger.db"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/s0fractal/oaip/claimcandidate/v0"


def _db():
    if not DB.is_file():
        sys.exit(f"no ledger at {DB} (run: oaip init)")
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def _descriptor(digest_hex, name=None, algo="sha256"):
    d = {"digest": {algo: digest_hex}}
    if name:
        d["name"] = name
    return d


def wrap(con, claim_id):
    c = con.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
    if not c:
        sys.exit(f"no claim {claim_id}")
    ex = con.execute("SELECT * FROM executions WHERE id=?",
                     (c["execution_id"],)).fetchone()
    effects = con.execute(
        "SELECT path,status,after_blob FROM effects WHERE execution_id=?",
        (c["execution_id"],)).fetchall()

    # in-toto matches subjects purely by digest, and the OAIP claim subject is
    # already a content-addressed blob of {predicate, execution, effects} — so it
    # maps across without inventing anything.
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [_descriptor(c["subject_hash"], name="oaip:claim-subject")],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "claimId": c["id"],
            "predicate": c["predicate"],
            # The distinction this whole protocol exists to keep. Two booleans,
            # never one: a check that ran and passed is not an accepted claim, and
            # an exit code of zero earns nothing (SPEC §4).
            "validation": {
                "check": c["check_cmd"],
                "exitCode": c["check_exit"],
                "supported": bool(c["supported"]),
                "transcript": _descriptor(c["transcript_hash"],
                                          name="check-transcript"),
            },
            "accepted": False,
            "acceptanceNote": "An OAIP claim is a CANDIDATE. Acceptance is a "
                              "Warrant record with its own signature and policy "
                              "(SPEC §3); it is not asserted by this attestation "
                              "and must not be inferred from `supported`.",
            # Field names follow the IMPLEMENTATION, not SPEC §2.4, because they
            # differ and reality is what a consumer will meet. §2.4 declares
            # `invocation`, `status`, `input_state`, `output_state`, `environment`;
            # impl/oaip.py stores `command`, `exit_code`, `before_tree`,
            # `after_tree`, `env_fp`. A third-party implementer following the
            # specification would emit artifacts incompatible with the reference,
            # which is a real divergence and is recorded in llms.txt rather than
            # quietly bridged over here. Aligning them is a format decision, not a
            # side effect of writing a converter.
            "execution": {
                "id": ex["id"] if ex else None,
                "invocation": ex["command"] if ex else None,
                "exitCode": ex["exit_code"] if ex else None,
                "inputState": ex["before_tree"] if ex else None,
                "outputState": ex["after_tree"] if ex else None,
                "environment": ex["env_fp"] if ex else None,
                "slsaAnalogue": "runDetails / OpenTelemetry span",
            },
            "effects": [
                {"target": e["path"], "kind": e["status"],
                 "after": e["after_blob"], "slsaAnalogue": "byproduct"}
                for e in effects
            ],
            "createdAt": c["created_at"],
        },
    }
    return statement


def check(con, st):
    """Recompute against the ledger. Shape validity is not binding."""
    errs = []
    if st.get("_type") != STATEMENT_TYPE:
        errs.append(f"_type is {st.get('_type')!r}, expected {STATEMENT_TYPE!r}")
    if st.get("predicateType") != PREDICATE_TYPE:
        errs.append(f"predicateType is {st.get('predicateType')!r}")
    subs = st.get("subject")
    if not isinstance(subs, list) or not subs:
        errs.append("subject must be a non-empty array")
    elif not isinstance(subs[0].get("digest"), dict):
        errs.append("every subject element MUST have digest set")

    p = st.get("predicate") or {}
    cid = p.get("claimId")
    if not isinstance(cid, str):
        errs.append("predicate.claimId missing")
        return errs
    c = con.execute("SELECT * FROM claims WHERE id=?", (cid,)).fetchone()
    if not c:
        errs.append(f"claim {cid} is not in this ledger")
        return errs

    if subs and subs[0].get("digest", {}).get("sha256") != c["subject_hash"]:
        errs.append("subject digest does not match the claim's subject_hash")
    if p.get("predicate") != c["predicate"]:
        errs.append("predicate text does not match the claim")
    v = p.get("validation") or {}
    if p.get("execution", {}).get("invocation") is not None:
        ex = con.execute("SELECT command FROM executions WHERE id=?",
                         (p["execution"].get("id"),)).fetchone()
        if ex is None or p["execution"]["invocation"] != ex["command"]:
            errs.append("predicate.execution.invocation does not match the ledger")
    if v.get("exitCode") != c["check_exit"]:
        errs.append("validation.exitCode does not match the claim")
    if bool(v.get("supported")) != bool(c["supported"]):
        errs.append("validation.supported does not match the claim")
    if (v.get("transcript") or {}).get("digest", {}).get("sha256") != c["transcript_hash"]:
        errs.append("validation.transcript digest does not match the claim")
    # §4 is a MUST, so a Statement asserting acceptance is malformed by
    # construction: this attestation type cannot carry that claim.
    if p.get("accepted") is not False:
        errs.append("predicate.accepted MUST be false — acceptance is a Warrant "
                    "record, not an OAIP attestation (SPEC §4)")
    return errs


def _throwaway_ledger():
    """Build a real ledger in a temp git repo and chdir into it.

    WHY: this selftest used to run against whatever ledger happened to be in the
    working directory, and printed `SKIP ... ledger has no claims` when there was
    none — exit 0, a pass earned by having nothing to check. In a clean checkout
    (and therefore in CI) that is the only outcome it could ever have produced.
    A selftest that depends on ambient state is not a selftest.

    Returns the TemporaryDirectory, which the caller must keep alive.
    """
    import subprocess
    import tempfile
    td = tempfile.TemporaryDirectory()
    work = Path(td.name) / "w"
    work.mkdir()
    shutil.copytree(Path(__file__).resolve().parents[1] / "impl", work / "impl")
    subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit",
                    "-q", "--allow-empty", "-m", "init"], cwd=work, check=True)
    run = lambda *a: subprocess.run([sys.executable, "impl/oaip.py", *a], cwd=work,
                                    capture_output=True, text=True)
    run("init")
    r = run("do", "--intent", "add a file", "--check", "test -f f.txt",
            "--actor", "selftest@local", "--", "sh", "-c", "echo hi >> f.txt")
    if "ACCEPTED" not in r.stdout:
        raise SystemExit(f"selftest setup failed: {r.stdout}{r.stderr}")
    os.chdir(work)
    return td


def selftest(con):
    row = con.execute("SELECT id FROM claims ORDER BY created_at LIMIT 1").fetchone()
    if not row:
        sys.exit("selftest needs a claim and the throwaway ledger produced none — "
                 "this is a setup failure, not something to skip past")
    ok = True

    def case(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL "), name)
        ok &= bool(cond)

    st = wrap(con, row["id"])
    case("wrap produces the required in-toto v1 shape",
         st["_type"] == STATEMENT_TYPE and st["predicateType"] == PREDICATE_TYPE
         and isinstance(st["subject"], list) and "digest" in st["subject"][0])
    case("check accepts a faithful Statement", check(con, st) == [])
    case("round-trips through JSON", check(con, json.loads(json.dumps(st))) == [])
    case("§4 is enforced: accepted is false",
         st["predicate"]["accepted"] is False)

    for mutate, label in (
        (lambda s: s["predicate"].update(accepted=True), "accepted=true (§4)"),
        (lambda s: s["predicate"].update(predicate="something else"), "predicate text"),
        (lambda s: s["predicate"]["validation"].update(exitCode=999), "exit code"),
        (lambda s: s["predicate"]["validation"].update(
            supported=not s["predicate"]["validation"]["supported"]), "supported"),
        (lambda s: s["subject"][0]["digest"].update(sha256="f" * 64), "subject digest"),
        (lambda s: s["predicate"]["validation"]["transcript"]["digest"].update(
            sha256="e" * 64), "transcript digest"),
        (lambda s: s["predicate"].update(claimId="nope"), "claimId"),
        (lambda s: s.update(_type="https://in-toto.io/Statement/v0"), "_type"),
    ):
        bad = json.loads(json.dumps(st))
        mutate(bad)
        case(f"check rejects a tampered {label}", check(con, bad) != [])

    print("\nOAIP-INTOTO: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["wrap", "check", "selftest"])
    ap.add_argument("arg", nargs="?")
    a = ap.parse_args()
    # selftest builds its own ledger; wrap/check operate on the caller's.
    keepalive = _throwaway_ledger() if a.cmd == "selftest" else None
    con = _db()
    if a.cmd == "wrap":
        if not a.arg:
            sys.exit("wrap needs a claim id")
        print(json.dumps(wrap(con, a.arg), indent=2, sort_keys=True))
        return 0
    if a.cmd == "check":
        if not a.arg:
            sys.exit("check needs a statement file")
        errs = check(con, json.loads(Path(a.arg).read_text()))
        for e in errs:
            print("ERR ", e)
        print("OAIP-INTOTO: " + ("BOUND — the Statement describes this claim"
                                 if not errs else f"{len(errs)} binding error(s)"))
        return 1 if errs else 0
    rc = selftest(con)
    del keepalive
    return rc


if __name__ == "__main__":
    sys.exit(main())
