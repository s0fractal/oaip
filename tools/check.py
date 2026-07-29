#!/usr/bin/env python3
"""Run every check this repository's claims rest on, in one command.

WHY THIS EXISTS
---------------
The same reason it exists in Warrant, plus a concrete failure that happened here.

`tools/intoto.py` shipped with a `selftest` covering twelve tamper cases, and that
selftest ran nowhere. A commit message claimed the CI wiring was fixed; it had
wired ONE step (the §5 projection rebuild) and left the bridge unwired, because
the workflow file was edited by hand for each new test. A test suite whose
membership is maintained by remembering to edit YAML will drift, silently, in the
direction of running less.

So: the list lives here, CI runs this one command, and a check that could not run
is UNRUN — a distinct outcome with its own exit status, never reported as passed.

WARRANT IS A NORMATIVE DEPENDENCY, NOT AN OPTIONAL EXTRA
--------------------------------------------------------
SPEC §3 makes the decision layer a real Warrant record, and SPEC §1 defines this
format's canonicalization as "exactly per Warrant SPEC §4". Several checks are
therefore meaningless without a Warrant checkout — and the honest report for those
is UNRUN, not a silent skip. Point `WARRANT_CLI` at your `warrant.py`, or keep a
checkout at ~/Projects/warrant.

USAGE
    python3 tools/check.py                 # everything; UNRUN is a failure
    python3 tools/check.py --allow-unrun   # tolerate a missing Warrant checkout
    python3 tools/check.py --list          # what would run, and what it needs
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WARRANT_IMPL = Path(os.environ.get("WARRANT_IMPL",
                                  Path.home() / "Projects/warrant/impl"))

# (name, argv, needs, expect) -- `expect` is a substring the run MUST print.
# It exists because the previous CI piped these demos through `grep -q` for a
# specific sentence, and moving the list here without it would have quietly
# weakened the suite: a demo that exits 0 without reaching its refusal would then
# pass. An exit code says the script ran; the string says it did the thing.
CHECKS = [
    ("canonicalization conformance (§1 vectors: byte-exact AND must-reject)",
     ["python3", "impl/oaip.py", "conformance", "examples/vectors.json"], None,
     "OAIP-CONFORMANCE: ALL PASS"),
    ("canonical layer integrity (forged artifacts, §5 truth)",
     ["python3", "tests/canonical_layer.py"], None,
     "CANONICAL-LAYER: ALL PASS"),
    ("projection is disposable (§5 MUST: delete, rebuild, identical graph)",
     ["python3", "tests/projection_rebuild.py"], None,
     "PROJECTION-REBUILD: ALL PASS"),
    ("I-JSON domain parity with Warrant (§1 'exactly per Warrant §4')",
     ["python3", "tests/ijson_parity.py"], "warrant-lib",
     "IJSON-PARITY: SAME DOMAIN"),
    # No `needs`: the selftest builds its own throwaway ledger. It used to depend
    # on one being present in the working directory, which is why it printed SKIP
    # and exited 0 in every clean checkout.
    ("in-toto bridge (Statement v1 shape + binding, tamper matrix)",
     ["python3", "tools/intoto.py", "selftest"], None,
     "OAIP-INTOTO: ALL PASS"),
    ("end-to-end: §4 refusal (execution success is not acceptance)",
     ["bash", "examples/auth-demo.sh"], "warrant-cli",
     "correctly refused: execution success is not acceptance"),
    ("graduation bridge (an unsigned decision → a signed Warrant)",
     ["bash", "examples/graduate-decision.sh"], "warrant-cli",
     "graduated -> signed Warrant"),
]


def _warrant_cli_ok():
    """A runnable Warrant CLI: either WARRANT_CLI, or the sibling checkout."""
    cli = os.environ.get("WARRANT_CLI")
    if cli:
        parts = cli.split()
        return bool(shutil.which(parts[0])) or Path(parts[0]).exists()
    return (WARRANT_IMPL / "warrant.py").is_file()


NEEDS = {
    "warrant-lib": (lambda: (WARRANT_IMPL / "warrant.py").is_file(),
                    f"no Warrant source at {WARRANT_IMPL}  ->  clone "
                    "https://github.com/s0fractal/warrant beside this repo, or "
                    "set WARRANT_IMPL. Parity with Warrant's I-JSON domain cannot "
                    "be measured without it."),
    "warrant-cli": (_warrant_cli_ok,
                    "no runnable Warrant CLI  ->  set WARRANT_CLI='python3 "
                    "/path/to/warrant/impl/warrant.py'. The decision layer is a "
                    "normative dependency (SPEC §3)."),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-unrun", action="store_true",
                    help="exit 0 when a check could not run; it is still named")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, argv, needs, expect in CHECKS:
            print(f"{name}\n    {' '.join(argv)}"
                  + (f"\n    needs: {needs}" if needs else "")
                  + (f"\n    must print: {expect}" if expect else ""))
        return 0

    env = dict(os.environ)
    if "WARRANT_CLI" not in env and (WARRANT_IMPL / "warrant.py").is_file():
        env["WARRANT_CLI"] = f"{sys.executable} {WARRANT_IMPL / 'warrant.py'}"

    failed, unrun, passed = [], [], 0
    for name, argv, needs, expect in CHECKS:
        if needs and not NEEDS[needs][0]():
            print(f"UNRUN  {name}\n         {NEEDS[needs][1]}")
            unrun.append(name)
            continue
        t0 = time.time()
        r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env=env)
        dt = time.time() - t0
        out = r.stdout + r.stderr
        missing = expect and expect not in out
        if r.returncode == 0 and not missing:
            print(f"ok     {name}  ({dt:.1f}s)")
            passed += 1
        else:
            print(f"FAIL   {name}  ({dt:.1f}s)"
                  + (f"\n         exited 0 but never printed: {expect!r}"
                     if missing and r.returncode == 0 else ""))
            for line in (r.stdout + r.stderr).strip().splitlines()[-3:]:
                print(f"         {line[:110]}")
            failed.append(name)

    print(f"\n{passed} passed, {len(failed)} failed, {len(unrun)} unrun")
    for n in failed:
        print(f"  FAILED  {n}")
    for n in unrun:
        print(f"  UNRUN   {n}")
    if unrun and not failed:
        print("\nNOT a clean run: something could not be checked. An unrun check "
              "is not a passed one, and this summary refuses to imply otherwise.")
    if failed:
        return 1
    if unrun:
        return 0 if args.allow_unrun else 2
    print("\nCHECK: ALL PASS — every claim in this repository was executed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
