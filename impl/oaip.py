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
    `before_state`/`after_state`, unlike HEAD."""
    tmp_index = OAIP / "tmp.index"
    env = dict(os.environ, GIT_INDEX_FILE=str(tmp_index.resolve()))
    # seed the throwaway index from HEAD if it exists, else empty, then add all
    subprocess.run(["git", "read-tree", "HEAD"], env=env, capture_output=True)
    subprocess.run(["git", "add", "-A"], env=env, capture_output=True)
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
    print(f"initialized .oaip (ledger + warrant store + dev key)")


def cmd_intent(a):
    i = kid()
    con = db()
    con.execute("INSERT INTO intents(id, description, parent_id, created_at) VALUES (?,?,?,?)",
                (i, a.description, a.parent, int(time.time())))
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
    con.execute("""INSERT INTO executions(id,intent_id,command,exit_code,before_tree,after_tree,
                   env_fp,stdout_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (eid, a.intent, " ".join(a.command), proc.returncode, before, after,
                 env_fp, stdout_hash, int(time.time())))
    n = 0
    for e in effects_between(before, after):
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


def cmd_verify(_):
    r = subprocess.run(WARRANT + ["--store", str(WSTORE), "verify"], capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(empty store)")
    sys.exit(r.returncode)


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
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    pf = sub.add_parser("conformance"); pf.add_argument("vectors", nargs="?", default="examples/vectors.json"); pf.set_defaults(fn=cmd_conformance)
    a = ap.parse_args()
    if a.cmd in ("run", "do") and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    a.fn(a)


if __name__ == "__main__":
    main()
