#!/usr/bin/env python3
"""Does the signed record say what actually happened when the check ran?

THE DEFECT THIS FILE PINS (external audit by Codex, 2026-07-31, reproduced
locally before it was touched)
-------------------------------------------------------------------------
**A runtime tag that promised a profile OAIP never provided.** `oaip claim`
ran the validation check with `subprocess.run(check, shell=True)` — the host
shell, the caller's uid, the observed workspace, no isolation of any kind — and
then recorded `validation.runtime = "cmd@v1"`, which **Warrant SPEC §3 defines
as execution in an isolated container**. That tag was passed unchanged into the
signed Warrant record. The record was not wrong about a detail; it named an
execution profile that did not exist.

This is not shell injection — the check is user-supplied and running it is the
point. It is a provenance defect: the record promises something that did not
happen.

WHAT THE CASES BELOW ARE, AND ARE NOT
-------------------------------------
They pin the RECORD, not the sandbox. OAIP still runs the check on the host,
with everything that implies; nothing here is evidence of confinement. What is
pinned is that the record names the profile that actually ran, and that nothing
hands Warrant a tag whose meaning Warrant defines differently.
"""
import atexit
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

# The tag is a LITERAL here, not `O.HOST_SHELL_RUNTIME`. A test that asks the
# implementation what it calls itself agrees with the implementation by
# construction; SPEC §7.3 is the thing this file is measuring against.
HOST_SHELL = "oaip-host-shell@v1"

ok = True

# A throwaway trust root: a ledger's signing key lives outside the workspace
# (§8.4 profile B), so every ledger this file builds would otherwise leave a
# real Ed25519 key in the operator's own ~/.config.
if "XDG_CONFIG_HOME" not in os.environ:
    _XDG = tempfile.mkdtemp(prefix="oaip-runtime-xdg-")
    os.environ["XDG_CONFIG_HOME"] = _XDG
    atexit.register(lambda: shutil.rmtree(_XDG, ignore_errors=True))


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


class Ledger:
    """A real ledger in a throwaway git repo. No `do` in setup: every case
    below is about the claim step, which `do` would have already taken."""

    def __init__(self, tmp):
        self.dir = Path(tmp)
        self.dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOT / "impl", self.dir / "impl")
        subprocess.run(["git", "init", "-q", "."], cwd=self.dir, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "--allow-empty", "-m", "init"],
                       cwd=self.dir, check=True)
        self.run("init")

    def run(self, *a):
        return subprocess.run([sys.executable, "impl/oaip.py", *a],
                              cwd=self.dir, capture_output=True, text=True)

    def execution(self, *command):
        i = self.run("intent", "a benign execution").stdout.strip()
        r = self.run("run", "--intent", i, "--", *command)
        if "execution " not in r.stdout:
            raise SystemExit(f"setup: run failed:\n{r.stdout}{r.stderr}")
        return r.stdout.split()[1]

    def artifact(self, h):
        return (self.dir / ".oaip" / "artifacts" / h).read_bytes()

    def records(self, tag):
        """Every artifact that is a valid record of type `tag`."""
        out = []
        for p in sorted((self.dir / ".oaip" / "artifacts").glob("*")):
            try:
                d = json.loads(p.read_bytes())
            except Exception:
                continue
            if isinstance(d, dict) and tag in d:
                out.append(d)
        return out

    def warrants(self):
        recs = self.dir / ".oaip" / "warrants" / "records"
        return [json.loads(p.read_text()) for p in sorted(recs.glob("*.json"))
                ] if recs.is_dir() else []

    def claim_rows(self):
        db = self.dir / ".oaip" / "ledger.db"
        if not db.is_file():
            return []
        con = sqlite3.connect(db)
        rows = list(con.execute("SELECT id, runtime, verdict FROM claims"))
        con.close()
        return rows


def with_ledger(fn):
    with tempfile.TemporaryDirectory() as tmp:
        fn(Ledger(Path(tmp) / "w"))


def synthetic_claim(runtime):
    """A shape-valid §2.7 claim carrying `runtime`, for the §7.3 registry."""
    h = "a" * 64
    return {"claim": "0.1", "id": "x", "subject": h, "predicate": "p",
            "evidence": [], "proposed_by": "t@l", "ts": 1,
            "validation": {"runtime": runtime, "check": h, "verdict": "pass",
                           "transcript": h}}


# ---------------------------------------------------------------- A. the tag
def part_a():
    print("\n--- A. the runtime tag names what actually ran (§7.3, §3) ---")

    # A1/A2: the registry itself. `cmd@v1` MUST stay readable — §6 forbids a
    # change that invalidates a record valid under an earlier reading, and
    # every claim written before this fix carries it.
    case("§7.3: a claim recording oaip-host-shell@v1 is VALID",
         O.validate_record(synthetic_claim(HOST_SHELL))[0] == "valid",
         str(O.validate_record(synthetic_claim(HOST_SHELL))))
    case("§7.3: a claim recording cmd@v1 is still valid (§6: no record valid "
         "under an earlier reading becomes invalid)",
         O.validate_record(synthetic_claim("cmd@v1"))[0] == "valid")
    case("§7.3 stays closed: an unregistered runtime is invalid",
         O.validate_record(synthetic_claim("docker@v9"))[0] == "invalid")

    def cases(L):
        eid = L.execution("true")
        r = L.run("claim", "--execution", eid, "--predicate", "p",
                  "--check", "true")
        claims = L.records("claim")
        case("a claim written by this implementation records the HOST SHELL "
             "runtime, not cmd@v1",
             len(claims) == 1
             and claims[0]["validation"]["runtime"] == HOST_SHELL,
             json.dumps([c["validation"]["runtime"] for c in claims]))
        case("...and the projection row agrees with the record",
             [row[1] for row in L.claim_rows()] == [HOST_SHELL],
             str(L.claim_rows()))
        cid = (r.stdout.split() + ["", ""])[1]

        a = L.run("accept", "--claim", cid, "--actor", "tester@local")
        case("the acceptance is still filed", "ACCEPTED" in a.stdout,
             (a.stdout + a.stderr)[-300:])
        acc = [w for w in L.warrants()
               if w.get("body", {}).get("decision") == "accept"]
        body = acc[0]["body"] if acc else {"because": [], "evidence": []}
        checks = [x for x in body["because"] if x.get("kind") == "check"]
        case("the WARRANT carries no check reason claiming a runtime OAIP did "
             "not provide (Warrant §3: cmd@v1 means an isolated container)",
             checks == [], json.dumps(checks))
        prose = " ".join(x.get("text", "") for x in body["because"]
                         if x.get("kind") == "prose")
        case("...the warrant says instead, in prose, which runtime ran",
             HOST_SHELL in prose, prose[:200])
        claim = L.records("claim")[0]
        want = {claim["validation"]["check"], claim["validation"]["transcript"]}
        case("...and the check blob and transcript are still cited, as evidence",
             want <= set(body["evidence"]),
             json.dumps(sorted(body["evidence"])))
        blobs = self_blobs = {p.name for p in
                              (L.dir / ".oaip" / "warrants" / "blobs").glob("*")}
        case("...and those blobs RESOLVE in the warrant store",
             want <= blobs, json.dumps(sorted(want - self_blobs)))
        v = L.run("verify")
        case("the store still verifies", v.returncode == 0,
             (v.stdout + v.stderr)[-300:])
    with_ledger(cases)


def main():
    part_a()
    print("\nVALIDATION-RUNTIME: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
