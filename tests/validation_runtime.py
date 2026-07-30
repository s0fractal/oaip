#!/usr/bin/env python3
"""Does the signed record say what actually happened when the check ran?

THE TWO DEFECTS THIS FILE PINS (external audit by Codex, 2026-07-31; both
reproduced locally before either was touched)
--------------------------------------------------------------------------
1. **A runtime tag that promised a profile OAIP never provided.** `oaip claim`
   ran the validation check with `subprocess.run(check, shell=True)` — the host
   shell, the caller's uid, the observed workspace, no isolation of any kind —
   and then recorded `validation.runtime = "cmd@v1"`, which **Warrant SPEC §3
   defines as execution in an isolated container**. That tag was passed
   unchanged into the signed Warrant record. The record was not wrong about a
   detail; it named an execution profile that did not exist.

2. **The check's own side effects were outside the observation.** The
   Execution's output state is snapshotted when the observed command returns,
   so anything the check writes lands after the last observation. The
   reproduction: a check of `touch check-escaped-container` created that file in
   the observed workspace, and the signed decision recorded `effects=0`.

Neither is shell injection — the check is user-supplied and running it is the
point. Both are provenance defects: the record promises something that did not
happen.

WHAT THE CASES BELOW ARE, AND ARE NOT
-------------------------------------
They pin the RECORD, not a sandbox. OAIP still runs the check on the host, with
everything that implies. Case B4 asserts that the sentinel file really is on
disk after the refusal, so that no reader takes this file for evidence of
confinement. What is pinned is that the record names the profile that ran, that
nothing hands Warrant a tag whose meaning Warrant defines differently, and that
a check which mutates the workspace cannot produce a record that omits it.
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
SENTINEL = "check-escaped-container"

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


# --------------------------------------------------- B. the observation hole
def part_b():
    print("\n--- B. a check that mutates the workspace (the reproduction) ---")

    def refuses(L):
        eid = L.execution("true")
        r = L.run("claim", "--execution", eid, "--predicate",
                  "workspace.unchanged", "--check", f"touch {SENTINEL}")
        out = r.stdout + r.stderr
        case("B1: a check that mutates the observed workspace is REFUSED",
             r.returncode != 0, out[-400:])
        case("B2: the refusal names the path the check changed",
             SENTINEL in out, out[-400:])
        case("B3: and no claim record was written",
             L.records("claim") == [] and L.claim_rows() == [])
        # Stated as a case rather than a comment: this fix OBSERVES, it does
        # not confine. The file is really there.
        case("B4: the side effect itself was NOT prevented — the sentinel is "
             "on disk (this is detection, not confinement)",
             (L.dir / SENTINEL).exists())
    with_ledger(refuses)

    def records_them(L):
        eid = L.execution("true")
        r = L.run("claim", "--execution", eid, "--predicate",
                  "workspace.unchanged", "--check", f"touch {SENTINEL}",
                  "--allow-check-effects")
        case("B5: with --allow-check-effects the claim is filed",
             r.returncode == 0 and "claim " in r.stdout,
             (r.stdout + r.stderr)[-300:])
        claims = L.records("claim")
        cited = []
        for h in (claims[0]["evidence"] if claims else []):
            try:
                cited.append(json.loads(L.artifact(h)))
            except Exception:
                pass
        eff = [d for d in cited
               if isinstance(d, dict) and "check_effects" in d]
        case("B6: the claim CITES the check's own effects as evidence — no "
             "record of this run can read as effects=0",
             len(eff) == 1
             and [e["target"] for e in eff[0]["check_effects"]] == [SENTINEL]
             and [e["kind"] for e in eff[0]["check_effects"]] == ["file.create"],
             json.dumps(eff)[:300])
        # Defensive: a RED run must keep measuring the cases after this
        # one. A test that tracebacks where the implementation is broken
        # reports one failure and hides the rest.
        cid = (r.stdout.split() + ["", ""])[1]
        a = L.run("accept", "--claim", cid, "--actor", "tester@local")
        case("B7: the acceptance carries that evidence into the signed record",
             "ACCEPTED" in a.stdout
             and any(set(claims[0]["evidence"]) <= set(w["body"]["evidence"])
                     for w in L.warrants()
                     if w.get("body", {}).get("decision") == "accept"),
             (a.stdout + a.stderr)[-300:])
        # The trap this guards: §6.2 fails closed when a record CITES an
        # artifact this reader cannot read. A check-effects artifact shaped
        # like a record ("<tag>": "<version>") would classify as `unknown-type`
        # and every claim citing it would refuse to rebuild.
        case("B8: the check-effects artifact is not-a-record, so §6.2's "
             "fail-closed citation rule does not fire on it",
             len(eff) == 1        # never vacuous: `all([])` is True
             and all(O.classify_record(d)[0] == "not-a-record"
                     for d in eff))
        b = L.run("rebuild")
        case("B9: ...and the ledger still rebuilds, edge intact",
             b.returncode == 0 and "warrant-edge=1" in (b.stdout + b.stderr),
             (b.stdout + b.stderr)[-300:])
    with_ledger(records_them)

    def control(L):
        """The negative control. A check that changes nothing must not acquire
        an effects artifact, or B6 would pass on a ledger where nothing ran."""
        eid = L.execution("true")
        r = L.run("claim", "--execution", eid, "--predicate", "p",
                  "--check", "true")
        claims = L.records("claim")
        case("B10: a check that mutates nothing files a claim with no "
             "check-effects evidence",
             r.returncode == 0 and len(claims) == 1
             and claims[0]["evidence"] == sorted(claims[0]["evidence"])
             and not any("check_effects" in json.loads(L.artifact(h))
                         for h in claims[0]["evidence"]
                         if L.artifact(h)[:1] == b"{"),
             (r.stdout + r.stderr)[-300:])
    with_ledger(control)


def main():
    part_a()
    part_b()
    print("\nVALIDATION-RUNTIME: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
