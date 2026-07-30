#!/usr/bin/env python3
"""The two self-verifying verbs must work where the package is INSTALLED.

WHY THIS EXISTS
---------------
`oaip` 0.2.0 went to PyPI with this in its parser:

    pv.add_argument("vectors", nargs="?", default="examples/record-vectors.json")

A relative path as a default is a promise that holds in exactly one directory on
earth. Everywhere else:

    $ pip install oaip==0.2.0 && cd /tmp && oaip records
    FileNotFoundError: [Errno 2] No such file or directory:
        'examples/record-vectors.json'

A documented verb, a traceback, a fresh install. `oaip conformance` did the same.
Both were live for the whole life of 0.2.0.

Every check this repository owned ran `impl/oaip.py` with cwd set to the
checkout, and the release gate ran `oaip conformance <absolute path to the
checkout's vectors>` — so the one thing nobody ever exercised was the default.
That is the shape of the bug: not a wrong computation, an untested cwd.

WHAT THIS PINS
--------------
1. Both verbs resolve their corpus with the process standing somewhere that is
   NOT the checkout. This is the case that shipped broken; it fails on any tree
   where the default is a bare relative path.
2. The same two verbs resolve from an INSTALLED layout — `oaip.py` with an
   `oaip_vectors/` directory beside it and no checkout anywhere above — which is
   what the wheel unpacks to. Built here from the real files rather than from a
   wheel, so this stays stdlib-only and offline; the wheel itself is exercised
   by tools/check_release_surface.py, against the artifact, before publish.
3. pyproject.toml still declares that corpus as package data. (1) and (2) can
   both pass while the wheel ships nothing, and then the fix is only true in a
   checkout — which is the bug again, one layer down.
4. A corpus file MISSING from a checkout is a hard failure, not a quiet
   fall-through to whatever copy happens to be installed. A checkout that
   self-verifies against vectors it does not contain reports a fact about
   somebody else's files.
5. An explicit path that does not exist fails loudly, and is never silently
   replaced by the shipped corpus.

    python3 tests/installed_vectors.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPL = ROOT / "impl" / "oaip.py"
CORPORA = {"conformance": ("vectors.json", "OAIP-CONFORMANCE: ALL PASS"),
           "records": ("record-vectors.json", "OAIP-RECORDS: ALL PASS")}

results = []


def chk(name, cond, detail=""):
    results.append(bool(cond))
    print(("OK   " if cond else "FAIL "), name, "" if cond else f"\n       {detail}")


def run(argv, cwd):
    env = dict(os.environ)
    # The checkout must not reach the child on sys.path: it would supply the
    # very examples/ directory this test is trying to do without.
    env.pop("PYTHONPATH", None)
    p = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True,
                       text=True, timeout=180)
    return p.returncode, p.stdout + p.stderr


def outside():
    """A directory that is not the checkout and contains no examples/."""
    return tempfile.mkdtemp(prefix="oaip-notcheckout-")


# 1. The checkout's own script, run from somewhere else entirely.
for verb, (fname, tag) in CORPORA.items():
    rc, out = run([sys.executable, str(IMPL), verb], outside())
    last = (out.strip().splitlines() or [""])[-1]
    chk(f"`oaip {verb}` replays its corpus from outside the checkout",
        rc == 0 and tag in out,
        f"exited {rc} without {tag!r}; last line: {last!r}")

# 2. An installed layout: the module and its shipped corpus, no checkout above.
inst = Path(tempfile.mkdtemp(prefix="oaip-installed-"))
shutil.copy2(IMPL, inst / "oaip.py")
(inst / "oaip_vectors").mkdir()
for fname, _tag in CORPORA.values():
    shutil.copy2(ROOT / "examples" / fname, inst / "oaip_vectors" / fname)
chk("the simulated install has no examples/ dir above the module",
    not (inst.parent / "examples").exists())
for verb, (fname, tag) in CORPORA.items():
    rc, out = run([sys.executable, str(inst / "oaip.py"), verb], outside())
    last = (out.strip().splitlines() or [""])[-1]
    chk(f"`oaip {verb}` replays the SHIPPED corpus from an installed layout",
        rc == 0 and tag in out,
        f"exited {rc} without {tag!r}; last line: {last!r}")

# 3. …and the build is actually told to ship it, so (2) describes a real wheel.
pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
chk("pyproject maps the vector corpus into the distribution",
    re.search(r'(?m)^\s*packages\s*=.*"oaip_vectors"', pyproject)
    and re.search(r'"oaip_vectors"\s*=\s*"examples"', pyproject),
    "pyproject.toml no longer declares the `oaip_vectors` package mapped onto "
    "examples/ — the wheel would ship the verbs without the vectors they replay")
for fname, _tag in CORPORA.values():
    chk(f"pyproject ships {fname} as package data",
        re.search(r'(?m)^\s*oaip_vectors\s*=\s*\[[^\]]*%s' % re.escape(fname),
                  pyproject, re.S),
        f"{fname} is not listed in [tool.setuptools.package-data]")

# 4. A checkout missing a corpus file is a hard failure, not a fallback.
fake = Path(tempfile.mkdtemp(prefix="oaip-gapped-"))
(fake / "impl").mkdir()
(fake / "examples").mkdir()
shutil.copy2(IMPL, fake / "impl" / "oaip.py")
shutil.copy2(ROOT / "examples" / "vectors.json", fake / "examples" / "vectors.json")
rc, out = run([sys.executable, str(fake / "impl" / "oaip.py"), "records"], outside())
chk("a corpus file missing from a checkout fails loudly",
    rc != 0 and "OAIP-RECORDS: ALL PASS" not in out and "record-vectors.json" in out,
    f"exited {rc}: {out.strip()[:200]!r}")
chk("…and says so in a sentence, not a traceback",
    "Traceback (most recent call last)" not in out, out.strip()[:200])
# the file that IS present still replays, so the failure was about the gap only
rc, out = run([sys.executable, str(fake / "impl" / "oaip.py"), "conformance"],
              outside())
chk("…while the corpus that IS present still replays",
    rc == 0 and "OAIP-CONFORMANCE: ALL PASS" in out, out.strip()[:200])

# 5. An explicit argument is never silently replaced by the shipped corpus.
rc, out = run([sys.executable, str(inst / "oaip.py"), "records",
               str(inst / "nope.json")], outside())
chk("an explicit path that does not exist is refused, not substituted",
    rc != 0 and "OAIP-RECORDS: ALL PASS" not in out,
    f"exited {rc}: {out.strip()[:200]!r}")

for d in (inst, fake):
    shutil.rmtree(d, ignore_errors=True)

ok, total = sum(results), len(results)
print(f"\nINSTALLED-VECTORS: {'ALL PASS' if ok == total else 'FAILURES'} "
      f"({ok}/{total})")
sys.exit(0 if ok == total else 1)
