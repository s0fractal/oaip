#!/usr/bin/env python3
"""Fail when the docs promise a CLI surface the built wheel does not have.

WHY THIS EXISTS
---------------
This repository has never published anything. Every check it owns —
`tools/check.py` and the whole CI job — runs against `impl/oaip.py` in a
checkout. The wheel is a different artifact: one module, no `examples/`, no
`tests/`, on a machine that has never seen this repo. Nothing here has ever
exercised that, and the sibling project learned the cost of the gap the
expensive way: `warrant-verify` 0.4.0 shipped while its README documented
`verify --store-mode --json`, so `pip install` + the README produced
`unrecognized arguments` for anyone who followed the instructions.

So this runs in the release workflow BEFORE the irreversible publish step, and
it asks one question: can the wheel do what the documentation tells a stranger
to do?

WHAT IT CHECKS
--------------
1. The WHEEL, read as a zip before anything from it runs: distribution name and
   version against `pyproject.toml`, `oaip.py` present, and the `oaip` console
   script declared in `entry_points.txt`.
2. The installed package: `import oaip` resolves inside the venv's
   site-packages (not a checkout that happens to be on `sys.path`), and the
   `oaip` console script exists.
3. `oaip --help` runs from a directory that is NOT the checkout. That cwd is
   load-bearing: an installed CLI that only works next to its own repo is the
   defect this whole file is about.
4. Every subcommand the documentation names exists in the CLI's `--help`, and
   `oaip <sub> --help` works for each.
5. Every flag a documented invocation passes is a real option OF THAT
   SUBCOMMAND, taken from the subparser's own help.
6. One real computation from outside the checkout: `oaip conformance` replays
   the SPEC §1 canonicalization vectors and must print `OAIP-CONFORMANCE: ALL
   PASS`. Parsing proves the surface exists; this proves the installed module
   still computes.

WHAT IT DOES NOT CHECK, AND WHY — read this before trusting a green run
----------------------------------------------------------------------
* **The acceptance path is not exercised.** `oaip init`, `do`, `accept`,
  `bind`, `rebuild` and `verify` all shell out to a **Warrant CLI**
  (`$WARRANT_CLI`, or a sibling checkout) — a normative dependency that is NOT
  a Python dependency of this package and is not present in a fresh venv. This
  gate therefore proves those subcommands EXIST and accept their documented
  flags; it does not prove they accept anything. The end-to-end acceptance and
  refusal behaviour is covered by `tools/check.py`, from a checkout, with
  Warrant installed. A green release-surface run is not a claim about §4.
* **Flag checking reads argparse's own option list, not argv semantics.** A
  documented flag must appear as an option of the subparser that documents it,
  which catches a removed or misplaced flag. It does not catch a documented
  form that argparse would reject anyway (`--flag=value` for a store_true, a
  flag combination barred after parsing). Validating those needs a parser-only
  entry point, which `impl/oaip.py` does not have — its `main()` parses and
  dispatches in one call, and running `oaip do …` for real would execute an
  arbitrary command. Naming the gap is the honest option; pretending the check
  is stronger than it is would be the same defect in a different place.

    python3 tools/check_release_surface.py                        # this checkout
    python3 tools/check_release_surface.py --wheel W --bin V/bin   # the artifact
    python3 tools/check_release_surface.py --selftest              # the extractor

Exit 0 = every documented subcommand and flag exists in the artifact under test.
"""
import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIST_NAME = "oaip"
CONSOLE_SCRIPT = "oaip"

# Docs a stranger is expected to follow. README.md is the front door; llms.txt
# is the same promise made to a model, and it quotes far more invocations —
# leaving it out would mean the most-quoted surface in the repo went unchecked.
DOCS = ("README.md", "llms.txt", "PUBLISHING.md")

# Bare one-word code spans that are NOT subcommands. Over-collecting and then
# justifying each exception here is deliberate: the alternative (only counting
# words that happen to be subcommands already) can never report a verb the docs
# name and the CLI lost, which is the entire failure this check exists for.
# A new word in the docs fails loudly until someone classifies it.
NOT_SUBCOMMANDS = {
    "decision": "a mind-os node type in the 'graduating decisions' section",
    "oaip": "the program itself",
    "warrant": "the sibling CLI",
    "command": "a FIELD of the execution record (llms.txt §record shape), not a verb",
    "environment": "a field of the execution record, same",
    "key": "a field of the binding record (`oaip bind --key` writes it)",
}

# Argparse's vocabulary for "this argv is not valid".
ARGPARSE_ERRORS = ("unrecognized arguments", "invalid choice",
                   "expected one argument", "the following arguments are required")

CONFORMANCE_TAG = "OAIP-CONFORMANCE: ALL PASS"

# `oaip …` in prose stands for "some subcommand", not for a subcommand called
# `…`. A placeholder in argv[0] means the line names no verb, so there is
# nothing to check and nothing to accuse.
PLACEHOLDER = re.compile(r"^(…|\.\.\.|<.*>|\$\{?\w+\}?)$")


# --------------------------------------------------------------------------
# ONE place that turns documented shell into ordered argv. The --selftest mode
# drives this same function.
# --------------------------------------------------------------------------
def logical_lines(text):
    """(lineno, logical line) for fenced shell blocks, joining `\\` continuations.

    The README documents `oaip do` across five physical lines. A reader that
    took one line at a time would check `--intent` and silently skip
    `--predicate`, `--check` and `--actor` — three quarters of the invocation
    that matters most.
    """
    out, buf, start, in_fence = [], "", None, False
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("```"):
            if buf:
                out.append((start, buf))
            buf, in_fence = "", not in_fence
            continue
        if not in_fence:
            continue
        line = raw.strip()
        if not buf:
            start = n
        cont = line.endswith("\\")
        buf = (buf + " " + (line[:-1] if cont else line)).strip()
        if cont:
            continue
        if buf:
            out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def inline_commands(text):
    """(lineno, code span) for inline `…` spans, outside fenced blocks."""
    out, in_fence = [], False
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for span in re.findall(r"`([^`\n]+)`", raw):
            out.append((n, span))
    return out


def _tokens(line):
    try:
        return shlex.split(line, comments=True)
    except ValueError:
        return None                      # unbalanced quotes: caller reports it


def invocations(line):
    """Every `oaip …` command in one logical line, as argv without argv[0].

    Recognises both the installed form (`oaip verify`) and the checkout form the
    README uses (`python3 $oaip verify`, after `oaip=…/impl/oaip.py`).
    """
    toks = _tokens(line)
    if toks is None:
        return None
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        # a shell assignment (`oaip=~/…/impl/oaip.py`) is not an invocation
        if "=" in t and not t.startswith("-"):
            i += 1
            continue
        argv = None
        if t in ("oaip", "./oaip") or t.endswith("/oaip") or t.endswith("oaip.py"):
            argv = toks[i + 1:]
        elif t in ("python", "python3") and i + 1 < len(toks):
            nxt = toks[i + 1]
            if nxt in ("$oaip", "${oaip}") or nxt.endswith("oaip.py"):
                argv = toks[i + 2:]
        if argv is not None:
            # stop at a shell operator; everything after `--` belongs to the
            # user's own command, not to oaip's parser
            cut = len(argv)
            for j, a in enumerate(argv):
                if a in ("|", "||", "&&", ";", ">", ">>", "&"):
                    cut = j
                    break
                if a == "--":
                    cut = j
                    break
            out.append(argv[:cut])
            i += 1 + cut
            continue
        i += 1
    return [a for a in out
            if a and not a[0].startswith("-") and not PLACEHOLDER.match(a[0])]


# A bare word in backticks is a subcommand claim only when the prose says it is.
# The first version of this check harvested every one-word code span and asked
# for an exclusion with a reason for each — a rule that reads `flock`, `fcntl`,
# `cryptography` and `ts` as lost verbs and produced 23 false accusations on
# llms.txt alone. A gate that cries wolf gets switched off, so the rule is now
# narrow and stated: the LINE must call the thing a verb/command/subcommand.
SUBCOMMAND_MARKER = re.compile(r"\b(verbs?|subcommands?|commands?)\b", re.I)


def bare_words(text):
    """(lineno, word) for one-word code spans on lines that call them verbs."""
    lines = text.splitlines()
    out = []
    for n, span in inline_commands(text):
        line = lines[n - 1] if n - 1 < len(lines) else ""
        if not SUBCOMMAND_MARKER.search(line):
            continue
        if re.fullmatch(r"[a-z][a-z0-9-]*", span):
            out.append((n, span))
    return out


# --------------------------------------------------------------------------
# The CLI's own answer to "what exists".
# --------------------------------------------------------------------------
def run(argv, cwd, timeout=120):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)          # the checkout must not leak in
    p = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def subcommands(help_text):
    m = re.search(r"\{([a-z0-9_,-]+)\}", help_text)
    return set(m.group(1).split(",")) if m else set()


def options_of(help_text):
    """Every option string argparse lists for a (sub)parser."""
    opts = set()
    for m in re.finditer(r"(?m)^\s{2,}(-[^\s,]+)", help_text):
        opts.add(m.group(1).split("=")[0])
    for m in re.finditer(r"(--[A-Za-z][A-Za-z0-9-]*)", help_text):
        opts.add(m.group(1))
    return opts


# --------------------------------------------------------------------------
def selftest():
    ok = []

    def chk(name, cond, detail=""):
        ok.append(cond)
        print(("OK  " if cond else "FAIL"), name, "" if cond else detail)

    readme_do = ('python3 $oaip do --intent "make login reject expired tokens" \\\n'
                 '        --predicate auth.rejects-expired \\\n'
                 '        --check "python3 tests/test_auth.py" \\\n'
                 '        --actor you@host \\\n'
                 '        -- your-agent-command')
    lines = logical_lines("```bash\n" + readme_do + "\n```\n")
    chk("continuations joined into one logical line", len(lines) == 1)
    argv = invocations(lines[0][1])[0]
    chk("multi-line invocation read whole",
        argv == ["do", "--intent", "make login reject expired tokens",
                 "--predicate", "auth.rejects-expired", "--check",
                 "python3 tests/test_auth.py", "--actor", "you@host"],
        f"got {argv}")
    chk("the user's own command after `--` is not read as oaip flags",
        "your-agent-command" not in argv)

    chk("shell assignment is not an invocation",
        invocations("oaip=~/x/impl/oaip.py") == [])
    chk("installed form recognised",
        invocations("oaip verify") == [["verify"]])
    chk("checkout form recognised",
        invocations("python3 impl/oaip.py log") == [["log"]])
    chk("bare script path recognised too",
        invocations("./impl/oaip.py verify") == [["verify"]])
    chk("pipeline stops at the operator",
        invocations("oaip log | grep WARRANT") == [["log"]])
    chk("a flag-only span is not a subcommand claim",
        invocations("oaip --help") == [])
    chk("`oaip …` in prose names no verb, so it accuses nobody",
        invocations("oaip …") == [] and invocations("oaip <cmd>") == [])

    help_text = ("usage: oaip [-h] {init,intent,run,claim,accept,bind,do,log,"
                 "rebuild,verify,conformance} ...")
    chk("subcommand set parsed from --help",
        subcommands(help_text) == {"init", "intent", "run", "claim", "accept",
                                   "bind", "do", "log", "rebuild", "verify",
                                   "conformance"})
    sub_help = ("usage: oaip do [-h] --intent INTENT --check CHECK\n\n"
                "options:\n  -h, --help  show this\n  --intent INTENT\n"
                "  --check CHECK\n")
    o = options_of(sub_help)
    chk("options parsed from a subparser help", {"--intent", "--check"} <= o)
    chk("a flag that is not there is not invented", "--store-mode" not in o)

    fenced = "```bash\noaip verify\n```\nthe verbs `accept` and `decision`\n"
    chk("bare-word harvest ignores fenced blocks",
        {w for _, w in bare_words(fenced)} == {"accept", "decision"},
        f"got {[w for _, w in bare_words(fenced)]}")
    words = {w for _, w in bare_words("verbs `intent` / `accept` and `decision`")}
    chk("bare-word harvest is complete where the prose says 'verbs'",
        words == {"intent", "accept", "decision"}, f"got {words}")
    chk("a code span in prose that never says verb/command is not a claim",
        bare_words("the `flock` call and the `ts` field") == [],
        f"got {bare_words('the `flock` call and the `ts` field')}")

    print("\nRELEASE-SURFACE-SELFTEST: " + ("ALL PASS" if all(ok) else "FAILURES")
          + f" ({sum(ok)}/{len(ok)})")
    return 0 if all(ok) else 1


# --------------------------------------------------------------------------
def inspect_wheel(wheel):
    problems = []
    if not wheel.is_file():
        return None, [f"no such wheel: {wheel}"]
    with zipfile.ZipFile(wheel) as z:
        names = set(z.namelist())
        meta = [n for n in names if n.endswith(".dist-info/METADATA")]
        if not meta:
            return None, [f"{wheel.name}: no dist-info/METADATA"]
        text = z.read(meta[0]).decode()
        eps = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
        ep_text = z.read(eps[0]).decode() if eps else ""
    info = {"name": None, "version": None, "files": names}
    for line in text.splitlines():
        if line.startswith("Name: "):
            info["name"] = line[6:].strip()
        elif line.startswith("Version: "):
            info["version"] = line[9:].strip()

    if "oaip.py" not in names:
        problems.append(f"{wheel.name}: does not contain oaip.py")
    if not re.search(r"(?m)^%s\s*=\s*oaip:main\s*$" % re.escape(CONSOLE_SCRIPT),
                     ep_text):
        problems.append(f"{wheel.name}: no `{CONSOLE_SCRIPT} = oaip:main` console "
                        f"script — the docs tell a stranger to type `oaip`")

    pyproject = (ROOT / "pyproject.toml").read_text()
    pv = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    if pv and info["version"] != pv.group(1):
        problems.append(f"{wheel.name}: wheel version {info['version']} != "
                        f"pyproject version {pv.group(1)}")
    dn = re.search(r'(?m)^name\s*=\s*"([^"]+)"', pyproject)
    if dn and (info["name"] or "").replace("_", "-") != dn.group(1):
        problems.append(f"{wheel.name}: wheel name {info['name']} != pyproject "
                        f"name {dn.group(1)}")
    return info, problems


def site_packages(binroot):
    hits = (sorted(binroot.parent.glob("lib/python*/site-packages")) or
            sorted(binroot.parent.glob("Lib/site-packages")))
    return hits[0] if hits else None


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--wheel", help="the built wheel: the provenance root")
    ap.add_argument("--bin", help="bin/ of a venv the wheel is installed into")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    problems = []

    if args.bin and not args.wheel:
        print("RELEASE SURFACE: REFUSING — --bin without --wheel.\n\n"
              "  An installation cannot vouch for itself. Pass the wheel that\n"
              "  will be published; it is the root of what is being checked.",
              file=sys.stderr)
        return 2

    if args.wheel:
        info, wproblems = inspect_wheel(Path(args.wheel).resolve())
        problems += wproblems
        if info is None:
            print("RELEASE SURFACE: FAIL\n")
            for p in problems:
                print(f"  {p}")
            return 1
        target = f"{info['name']} {info['version']} from {Path(args.wheel).name}"
    else:
        target = "this checkout"

    if args.bin:
        binroot = Path(args.bin).resolve()
        cli = binroot / CONSOLE_SCRIPT
        python = binroot / "python"
        if not python.exists():
            python = binroot / "python3"
        if not cli.exists():
            print(f"RELEASE SURFACE: FAIL — no `{CONSOLE_SCRIPT}` in {binroot}. "
                  f"The docs tell a stranger to type it.")
            return 1
        base = [str(cli)]
        # A directory that is NOT the checkout, on purpose: an installed CLI that
        # only works next to its own repo is exactly the bug this gate is for.
        workdir = tempfile.mkdtemp(prefix="oaip-release-")
        site = site_packages(binroot)
        rc, out, err = run([str(python), "-c", "import oaip;print(oaip.__file__)"],
                           workdir)
        if rc != 0:
            problems.append(f"import oaip failed from the installed wheel: "
                            f"{(err.strip().splitlines() or [''])[-1]}")
        elif site is not None:
            origin = Path(out.strip()).resolve()
            if site.resolve() not in origin.parents:
                problems.append(f"oaip imported from {origin}, not from the "
                                f"installed package under {site} — this run "
                                f"would be testing a checkout, not the artifact")
    else:
        base = [sys.executable, str(ROOT / "impl" / "oaip.py")]
        workdir = tempfile.mkdtemp(prefix="oaip-release-")

    # 3. --help, from outside the checkout.
    rc, out, err = run(base + ["--help"], workdir)
    if rc != 0:
        problems.append(f"`oaip --help` exited {rc} from {workdir}: "
                        f"{(err.strip().splitlines() or [''])[-1]}")
        print(f"RELEASE SURFACE: FAIL — {target} cannot even print its help:\n")
        for p in problems:
            print(f"  {p}")
        return 1
    have = subcommands(out)
    if not have:
        problems.append("`oaip --help` lists no subcommands")

    # 4/5. What the docs name, against what exists.
    sub_help, documented, checked = {}, set(), 0

    def sub_options(name):
        if name not in sub_help:
            sub_help[name] = run(base + [name, "--help"], workdir)
        return sub_help[name]

    for doc in DOCS:
        text = (ROOT / doc).read_text()
        spans = ([(n, ln) for n, ln in logical_lines(text)] +
                 [(n, s) for n, s in inline_commands(text)])
        for lineno, line in spans:
            inv = invocations(line)
            if inv is None:
                # Fenced blocks are not all shell — README.md's lede is an ASCII
                # arrow diagram whose quotes do not balance. A line that cannot
                # be tokenised and does not mention `oaip` is prose, not a
                # broken command; one that DOES mention it is reported, because
                # then the unparseable thing is a documented invocation.
                if "oaip" in line:
                    problems.append(f"{doc}:{lineno}: unparseable shell: {line!r}")
                continue
            for argv in inv:
                name, flags = argv[0], [a for a in argv[1:] if a.startswith("--")]
                documented.add(name)
                checked += 1
                if name not in have:
                    problems.append(f"{doc}:{lineno}: `oaip {name}` is documented "
                                    f"but the CLI has no such subcommand "
                                    f"(has: {', '.join(sorted(have))})")
                    continue
                src, sout, serr = sub_options(name)
                if src != 0:
                    problems.append(f"`oaip {name} --help` exited {src}")
                    continue
                opts = options_of(sout + serr)
                for f in flags:
                    if f.split("=")[0] not in opts:
                        problems.append(f"{doc}:{lineno}: `oaip {name} {f}` is "
                                        f"documented but {f} is not an option of "
                                        f"`{name}`")

    for doc in DOCS:
        for lineno, w in bare_words((ROOT / doc).read_text()):
            if w in have:
                documented.add(w)
                continue
            if w in NOT_SUBCOMMANDS:
                continue
            problems.append(
                f"{doc}:{lineno}: `{w}` reads as a subcommand name but the CLI "
                f"has none. Either it is a verb the artifact lost, or it is "
                f"prose — say which by adding it to NOT_SUBCOMMANDS with a "
                f"reason")

    # 6. One real computation, from outside the checkout.
    vectors = ROOT / "examples" / "vectors.json"
    if vectors.is_file():
        rc, out, err = run(base + ["conformance", str(vectors)], workdir)
        if rc != 0 or CONFORMANCE_TAG not in out:
            tail = (out.strip().splitlines() or [""])[-1]
            problems.append(f"`oaip conformance` from {workdir} exited {rc} "
                            f"without {CONFORMANCE_TAG!r} (last line: {tail!r}) "
                            f"— the installed module parses but does not compute")
    else:
        problems.append(f"missing {vectors}: the one check that proves the "
                        f"installed module still computes cannot run")

    if problems:
        print(f"RELEASE SURFACE: FAIL — the documentation promises "
              f"{len(problems)} thing(s) {target} does not offer:\n")
        for p in problems:
            print(f"  {p}")
        print("\nEither ship the surface or stop documenting it. A stranger who "
              "follows the README\nmust not hit `unrecognized arguments`.")
        return 1

    # Say what was NOT covered, every time, so a green line cannot be misread.
    warrant_verbs = sorted(v for v in ("init", "do", "accept", "bind", "rebuild",
                                       "verify") if v in documented)
    print(f"RELEASE SURFACE: ALL PASS ({checked} documented invocations across "
          f"{len(DOCS)} docs accepted by {target}; conformance vectors replay "
          f"from outside the checkout)")
    print(f"note: {', '.join(warrant_verbs)} are checked for EXISTENCE only — "
          f"they shell out to a Warrant CLI, which a fresh venv does not have. "
          f"Acceptance behaviour is gated by tools/check.py, not here.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
