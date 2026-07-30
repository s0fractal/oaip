#!/usr/bin/env python3
"""The Warrant CLI as it behaved BEFORE the flag day — a signer, never a verifier.

WHY THIS EXISTS
---------------
`tests/legacy_store.py` proves that a ledger written by the PREVIOUS RELEASE of
`impl/oaip.py` still reads under the current one (SPEC §6.4). Its fixture,
`oaip_prechange.py`, is a byte copy of that release, pinned by SHA-256 — it
cannot be edited, and that is the point: a test that adjusts its own "previous
version" is testing nothing.

That release verifies signatures in process, over the BARE 32-byte WarrantID
(Warrant SPEC v0.3). Warrant SPEC v0.4 / package 0.6.0 changed the signed
message to `"warrant-sig-v1:" || WarrantID_raw`. So against a current Warrant
CLI the pinned fixture refuses its own acceptance and cannot build a store at
all — not because anything is broken, but because **the previous release could
only ever have produced a pre-v1 store.** Reconstructing one truthfully means
reconstructing the signer it had.

This shim is that signer. It forwards every argument to the real Warrant CLI —
so the store, the body, the WarrantID, the blob layout and the CLI's own output
are all genuinely Warrant's — and then, for records the supplied `--key` signed,
replaces the signature with the same key's signature over the bare WarrantID.
The result is byte-for-byte what a pre-0.6.0 Warrant would have written.

WHAT IT MAY TOUCH, AND WHY THAT BOUND MATTERS
---------------------------------------------
Exactly one field: the `sig` hex of an entry whose `key` is the public half of
`--key` and whose signature currently verifies under the v0.4 construction.
`body` is never read for anything but its address (taken from the FILENAME, so
this file has no opinion about canonicalization), `actor` and `key` are never
written, and the WarrantID cannot move because the envelope is not hashed.

IT IS A SIGNER, NOT A VERIFIER. Nothing here decides whether a signature is
acceptable, and no code under `impl/` imports it. Pointing `$WARRANT_CLI` at it
downgrades what SIGNS; the thing that decides is `impl/oaip.py`'s own in-process
Ed25519 check, which is exactly what `legacy_store.py` then measures.

USAGE
    LEGACY_WARRANT_REAL_CLI="python3 /path/to/warrant.py" \
        WARRANT_CLI="python3 tests/fixtures/legacy_signer.py" ...
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "impl"))
import oaip as O                                              # noqa: E402


def ed25519_sign(seed, msg):
    """(public key, signature) — RFC 8032, over the implementation's own point
    arithmetic, so this file adds no dependency and no second curve."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h[:32], "little")

    def compress(P):
        inv = pow(P[2], O._ED_P - 2, O._ED_P)
        x, y = P[0] * inv % O._ED_P, P[1] * inv % O._ED_P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    pub = compress(O._ed_mul(a, O._ED_G))
    r = int.from_bytes(hashlib.sha512(bytes(h[32:]) + msg).digest(),
                       "little") % O._ED_L
    R = compress(O._ed_mul(r, O._ED_G))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(),
                       "little") % O._ED_L
    return pub, R + ((r + k * a) % O._ED_L).to_bytes(32, "little")


def opt(argv, name):
    """The value of `--name V`, or None. Warrant takes `--store` before the
    subcommand and `--key` after it; scanning the whole argv covers both without
    this file having to model Warrant's parser."""
    for i, tok in enumerate(argv):
        if tok == name and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith(name + "="):
            return tok.split("=", 1)[1]
    return None


def downgrade(store, key_path):
    """Re-sign this store's records the way a pre-0.6.0 Warrant would have."""
    try:
        seed = bytes.fromhex(Path(key_path).read_text().strip())
    except (OSError, ValueError):
        return                      # no readable key: nothing this key signed
    if len(seed) != 32:
        return
    pub, _ = ed25519_sign(seed, b"")
    pub_hex = pub.hex()
    records = Path(store) / "records"
    if not records.is_dir():
        return
    for p in sorted(records.glob("*.json")):
        # The address IS the WarrantID (the store is content-addressed on the
        # canonical body), so nothing here re-canonicalizes anything.
        wid = p.stem
        if not O.HEX64.match(wid):
            continue
        try:
            env = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if not (isinstance(env, dict) and isinstance(env.get("sigs"), list)):
            continue
        changed = False
        for s in env["sigs"]:
            if not (isinstance(s, dict) and s.get("key") == pub_hex):
                continue
            if not O.signature_verifies(wid, s):
                continue            # not a current signature by this key
            _, sig = ed25519_sign(seed, bytes.fromhex(wid))
            s["sig"] = sig.hex()
            changed = True
        if changed:
            p.write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")


def main():
    real = os.environ.get("LEGACY_WARRANT_REAL_CLI")
    if not real:
        print("legacy_signer: set LEGACY_WARRANT_REAL_CLI to the real Warrant "
              "CLI argv (e.g. 'python3 /path/to/impl/warrant.py')",
              file=sys.stderr)
        return 2
    argv = sys.argv[1:]
    r = subprocess.run(real.split() + argv, capture_output=True, text=True)
    # Forwarded verbatim: the caller reads the WarrantID off stdout.
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    store, key = opt(argv, "--store"), opt(argv, "--key")
    if r.returncode == 0 and store and key:
        downgrade(store, key)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
