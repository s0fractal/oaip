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

AND WHICH WARRANT: v0.4 / package >= 0.6.0, pinned in CI at 8508a4a.
--------------------------------------------------------------------
This is a HARD floor, not a recommendation. Warrant SPEC v0.4 replaced the §5
signed message with `"warrant-sig-v1:" || WarrantID_raw`, OAIP verifies Ed25519
in process and therefore carries its own copy of that construction, and the two
constructions are disjoint by design — there is no dual-accept window. Against a
pre-0.6.0 CLI, every check below that files a real acceptance fails, loudly, at
the signature; that is the intended behaviour and not a broken suite.
`tests/signature_gate.py` part A measures the installed CLI's construction
directly, so "the pin moved but the implementation did not" (or the reverse)
fails here rather than in someone's store.

USAGE
    python3 tools/check.py                 # everything; UNRUN is a failure
    python3 tools/check.py --allow-unrun   # tolerate a missing Warrant checkout
    python3 tools/check.py --list          # what would run, and what it needs
"""
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import tempfile
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
    # The other half of "conformance", and the half that did not exist until
    # 2026-07-30: the vectors above pin the SERIALIZER, these pin what a record
    # IS. While only the first existed, the reference implementation wrote a
    # different record from SPEC §2 for every type in the specification and
    # reported ALL PASS the whole time.
    ("record-shape conformance (§10 vectors: valid shapes AND must-reject)",
     ["python3", "impl/oaip.py", "records", "examples/record-vectors.json"],
     None, "OAIP-RECORDS: ALL PASS"),
    # Both checks above run `impl/oaip.py` with cwd = this checkout, which is
    # the one directory where a default of `examples/vectors.json` resolves.
    # 0.2.0 shipped to PyPI with exactly that default and traced back from
    # anywhere else. No `needs`: stdlib only, offline, no Warrant.
    ("the corpus verbs work from outside a checkout (the 0.2.0 PyPI defect)",
     ["python3", "tests/installed_vectors.py"], None,
     "INSTALLED-VECTORS: ALL PASS"),
    ("canonical layer integrity (forged artifacts, §5 truth)",
     ["python3", "tests/canonical_layer.py"], None,
     "CANONICAL-LAYER: ALL PASS"),
    ("projection is disposable (§5 MUST: delete, rebuild, identical graph)",
     ["python3", "tests/projection_rebuild.py"], None,
     "PROJECTION-REBUILD: ALL PASS"),
    # `needs` the CLI: the fixture is the PREVIOUS RELEASE of impl/oaip.py, and
    # it files a real signed warrant. What the check is for is that the
    # ACCEPTANCE EDGE survives the record-format change, and without a Warrant
    # CLI there is no acceptance to survive — an UNRUN here is honest; a
    # half-run that still printed its ALL PASS line would not be.
    ("pre-0.1 stores still read, pre-v1 SIGNATURES do not (§6.4 + §8.6, against "
     "the previous release)",
     ["python3", "tests/legacy_store.py"], "warrant-cli",
     "LEGACY-STORE: ALL PASS"),
    # No `needs`: the custody property is about git objects, not about Warrant —
    # the test plants a sentinel key when no Warrant CLI generated a real one.
    ("key custody (the snapshot must not embed .oaip / the signing key)",
     ["python3", "tests/key_custody.py"], None,
     "KEY-CUSTODY: ALL PASS"),
    # `needs` the CLI: every case files or re-verifies a real signed acceptance,
    # and a custody check that never reaches a signature is not a custody check.
    ("privilege separation (who can supply this ledger's own acceptance)",
     ["python3", "tests/privilege_separation.py"], "warrant-cli",
     "PRIVILEGE-SEPARATION: ALL PASS"),
    # `needs` the CLI: the end-to-end half files real signed records. The
    # verifier's own vectors would run anywhere, but a half-run check that still
    # printed its ALL PASS line would be the "passes by not looking" pattern this
    # repository keeps finding.
    ("signature gate (OAIP verifies Ed25519 itself; a stub CLI cannot forge)",
     ["python3", "tests/signature_gate.py"], "warrant-cli",
     "SIGNATURE-GATE: ALL PASS"),
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
    # The release gate lives here for the same reason everything else does: a
    # check whose membership is remembered rather than recorded runs less over
    # time. These two are the CHECKOUT half — the extractor's own selftest, and
    # every documented invocation measured against impl/oaip.py. The half that
    # measures the built WHEEL needs a wheel and a venv, so it runs in
    # .github/workflows/publish.yml, before the publish step it guards.
    ("release-surface extractor selftest (the gate is checked before it is used)",
     ["python3", "tools/check_release_surface.py", "--selftest"], None,
     "RELEASE-SURFACE-SELFTEST: ALL PASS"),
    ("documented CLI surface exists (README.md + llms.txt vs the real parser)",
     ["python3", "tools/check_release_surface.py"], None,
     "RELEASE SURFACE: ALL PASS"),
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
                    "normative dependency (SPEC §3), and it must be Warrant "
                    "SPEC v0.4 / package >= 0.6.0 (CI pins 8508a4a): an older "
                    "one signs a different message and OAIP will refuse every "
                    "acceptance it files."),
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
    # THE SUITE MUST NOT WRITE INTO THE OPERATOR'S OWN CONFIG. Since 2026-07-30
    # a ledger's signing key and keyring live in a TRUST ROOT outside the
    # workspace, defaulting to `$XDG_CONFIG_HOME/oaip/roots/<ledger>` — so every
    # throwaway ledger a check creates would otherwise leave a directory (and a
    # real Ed25519 key) in `~/.config/oaip`, named after a temporary path that no
    # longer exists. Measured: one full run left 44 of them. A throwaway
    # XDG_CONFIG_HOME per run keeps the suite hermetic; it is deliberately not
    # exported when the operator has already set one, since that is a deployment
    # choice and this tool does not overrule it.
    tmp_xdg = None
    if "XDG_CONFIG_HOME" not in env:
        tmp_xdg = tempfile.mkdtemp(prefix="oaip-check-xdg-")
        env["XDG_CONFIG_HOME"] = tmp_xdg
        atexit.register(lambda: shutil.rmtree(tmp_xdg, ignore_errors=True))

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
