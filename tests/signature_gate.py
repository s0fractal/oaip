#!/usr/bin/env python3
"""Who decided? OAIP must answer that itself, from bytes, in process.

THE DEFECT (2026-07-30, THIRD adversarial round, C2-F1a)
-------------------------------------------------------
Cryptographic signature validity was decided in exactly ONE place: a subprocess
named by `$WARRANT_CLI` — or, with no environment variable set at all, an
unpinned sibling checkout at `$HOME/Projects/warrant/impl/warrant.py`. OAIP's own
rule (`unbound_signers`) only asked which key a signature entry NAMED; whether
that key had signed anything was the subprocess's business. And the gate on the
subprocess (`store_report`) checked the SHAPE of the JSON it printed, not the
identity of the program — a commit on this branch called that "the CLI identity
probe", which it never was.

So four lines defeated the whole acceptance path:

    # fakewarrant.py
    import json
    print(json.dumps({"report": "warrant.verify-report@v0", "grade":
                      "settlement", "ok": True, "records": 2, "errors": 0,
                      "warnings": 0, "findings": []}))

with a forged accept whose `sigs[0]` names this ledger's REAL public key and
carries `"sig": "abab…"` — garbage, no secret needed. Measured before the fix:
the real Warrant CLI refused (rc=1), and
`WARRANT_CLI="python3 fakewarrant.py" oaip rebuild` exited 0, derived the
acceptance edge, `oaip log` printed "(signed decision)", `oaip verify` printed
0 errors. Reproduced with NO environment variable by planting the same stub at
the unpinned default path (case B2 below does this against a fake $HOME; it must
never touch the operator's real checkout).

THE FIX: OAIP VERIFIES ED25519 ITSELF (`impl/oaip.py: ed25519_verify`)
----------------------------------------------------------------------
Verification needs no secret and no dependency — ~60 lines of integer arithmetic
over stdlib `hashlib` — so the central check is no longer delegated. Warrant
remains the normative decision layer and is still consulted; a stub can still
make OAIP REFUSE (that direction is safe), and can no longer make it believe.
Part A pins the verifier against RFC 8032 §7.1 and against forgery classes;
Part B pins the end-to-end behaviour through both routes to the stub.

AND: A REFUSAL MUST NOT LEAVE A KNOWN-BAD PROJECTION READABLE (same finding)
---------------------------------------------------------------------------
The forgery was also STICKY. Once a projection asserted it, every honest rebuild
afterwards refused (rc=1) and left that projection in place — so `oaip log` went
on printing "(signed decision)" indefinitely, and the refusal protected nothing.
A refused rebuild now marks the projection untrusted (case B3): the bytes stay,
the authority goes, and a successful rebuild restores it.

CO-SIGNATURES (C2-F1b)
----------------------
Warrant SPEC §5 lets anyone with store write access append a co-signature, and
deliberately will not let one invalidate an otherwise-good record. OAIP demanded
that EVERY signature be bound, so one appended, cryptographically VALID co-sig by
a second endorser silently DELETED the acceptance edge and `oaip rebuild` still
exited 0. Part C pins the opposite: the claimed actor's signature must be valid
and bound, extra signatures are reported, and the edge survives.
"""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "impl"))
import oaip as O                                              # noqa: E402

ok = True

STUB = ("import json\n"
        'print(json.dumps({"report":"warrant.verify-report@v0",'
        '"grade":"settlement","ok":True,"records":2,"errors":0,'
        '"warnings":0,"findings":[]}))\n')


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def wcli():
    return (os.environ.get("WARRANT_CLI")
            or f"{sys.executable} "
               f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()


def make_repo(tmp, name="w"):
    work = Path(tmp) / name
    work.mkdir()
    shutil.copytree(ROOT / "impl", work / "impl")
    subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "init"],
                   cwd=work, check=True)

    def run(*a, env=None):
        return subprocess.run([sys.executable, "impl/oaip.py", *a], cwd=work,
                              capture_output=True, text=True,
                              env=dict(os.environ, **(env or {})))
    run("init")
    return work, run


def edges(work):
    db = work / ".oaip" / "ledger.db"
    if not db.is_file():
        return []
    con = sqlite3.connect(db)
    rows = list(con.execute("SELECT claim_id, warrant_id FROM warrants"))
    con.close()
    return rows


def real_accept(work):
    """(path, envelope) of the accept `oaip do` filed."""
    for p in sorted((work / ".oaip" / "warrants" / "records").glob("*.json")):
        env = json.loads(p.read_text())
        if env["body"].get("decision") == "accept":
            return p, env
    raise SystemExit("setup: no accept record in the store")


def part_a():
    # --- A. the verifier itself. RFC 8032 §7.1 first: a verifier that cannot
    # agree with the standard's own vectors is not evidence about anything below.
    vectors = [
        # (secret-derived public key, message, signature) — RFC 8032 §7.1
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
         "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
         "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
         "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]
    for pub, msg, sig in vectors:
        case(f"RFC 8032 §7.1 vector (msg={msg or '<empty>'}) verifies",
             O.ed25519_verify(bytes.fromhex(pub), bytes.fromhex(msg),
                              bytes.fromhex(sig)))
    pub, msg, sig = (bytes.fromhex(vectors[1][0]), bytes.fromhex(vectors[1][1]),
                     bytes.fromhex(vectors[1][2]))
    case("a flipped message byte does not verify",
         not O.ed25519_verify(pub, bytes([msg[0] ^ 1]), sig))
    case("a flipped signature byte does not verify",
         not O.ed25519_verify(pub, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
    case("another key does not verify the same signature",
         not O.ed25519_verify(bytes.fromhex(vectors[0][0]), msg, sig))
    case("`sig` of the wrong length does not verify",
         not O.ed25519_verify(pub, msg, sig[:-1]))
    # Malleability: S + L is the same scalar mod L, and an unreduced S must be
    # refused rather than accepted as a second valid signature.
    s_plus_l = int.from_bytes(sig[32:], "little") + O._ED_L
    if s_plus_l < (1 << 256):
        case("a non-reduced S (S + L) does not verify",
             not O.ed25519_verify(pub, msg,
                                  sig[:32] + s_plus_l.to_bytes(32, "little")))
    # A small-order key makes an all-zero signature verify for many messages in a
    # lenient verifier: that is a forgery without a secret (Warrant SPEC §5).
    case("a small-order public key is refused outright",
         all(not O.ed25519_verify(k, b"anything", b"\x00" * 64)
             for k in list(O._ED_SMALL_ORDER)[:4]))
    case("`signature_verifies` refuses non-hex and non-object entries",
         not O.signature_verifies("aa" * 32, {"key": "zz", "sig": "zz"})
         and not O.signature_verifies("aa" * 32, "not an object")
         and not O.signature_verifies("aa" * 32, {"key": "aa" * 32}))

    # A REAL Warrant signature, produced by the reference CLI (which uses
    # `cryptography`), must verify here. Parity in the accepting direction is
    # what makes the refusals above meaningful rather than a broken verifier.
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "parity")
        r = run("do", "--intent", "sign something real", "--check", "true",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(A): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        p, env = real_accept(work)
        s = env["sigs"][0]
        case("a REAL warrant signature verifies under OAIP's own Ed25519 check",
             O.signature_verifies(p.stem, s), f"{p.stem[:12]} {s}")
        case("the signed message is the WarrantID OAIP recomputes itself",
             p.stem == sha256(canon(env["body"])))
        bad = dict(s, sig="ab" * 64)
        case("the same entry with garbage `sig` does NOT verify",
             not O.signature_verifies(p.stem, bad))


def forge(work, key_hex, actor="tester@local", sig="ab" * 64):
    """A NEW accept record at its own valid address, naming a real bound key,
    signed with bytes no key produced. This is the whole forgery kit."""
    _, env = real_accept(work)
    body = dict(env["body"])
    body["ts"] = body["ts"] + 1
    wid = sha256(canon(body))
    (work / ".oaip" / "warrants" / "records" / f"{wid}.json").write_text(
        json.dumps({"body": body,
                    "sigs": [{"actor": actor, "key": key_hex, "sig": sig}]}))
    return wid


def part_b():
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "stub")
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(B): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        honest = edges(work)
        pub = (work / ".oaip" / "dev.key.pub").read_text().strip()
        fwid = forge(work, pub)

        # The negative control, both halves. The forgery satisfies EVERY gate
        # that does not do cryptography: it hashes to its own address, and it
        # names a key this ledger's own keyring binds to the actor it claims.
        case("negative control: the forgery satisfies address-matching",
             (work / ".oaip" / "warrants" / "records"
              / f"{fwid}.json").is_file())
        trust = json.loads((work / ".oaip" / "trust.json").read_text())
        case("negative control: the forgery NAMES a bound key of the real actor",
             pub in trust["actors"].get("tester@local", []), trust)

        # And the real CLI refuses it, which is why an attacker wants another one.
        r = run("rebuild")
        case("with the REAL Warrant CLI, rebuild refuses this store",
             r.returncode != 0, (r.stdout + r.stderr)[-300:])

        # --- B1: the stub named by $WARRANT_CLI.
        stub = work / "fakewarrant.py"
        stub.write_text(STUB)
        r = run("rebuild", env={"WARRANT_CLI": f"{sys.executable} {stub}"})
        out = r.stdout + r.stderr
        case("stub CLI via $WARRANT_CLI: no acceptance edge is derived from the "
             "forgery", all(w != fwid for _, w in edges(work)),
             f"{edges(work)} {out[-300:]}")
        case("stub CLI via $WARRANT_CLI: the refusal names the SIGNATURE, not "
             "the exit code", "does NOT verify" in out, out[-400:])
        case("stub CLI via $WARRANT_CLI: the honest edge is untouched",
             edges(work) == honest, f"{edges(work)} vs {honest}")
        log = run("log", env={"WARRANT_CLI": f"{sys.executable} {stub}"})
        case("stub CLI via $WARRANT_CLI: `oaip log` prints no forged "
             "(signed decision)", fwid[:16] not in log.stdout, log.stdout)
        v = run("verify", env={"WARRANT_CLI": f"{sys.executable} {stub}"})
        case("stub CLI via $WARRANT_CLI: `oaip verify` FAILS on the forgery",
             v.returncode != 0 and fwid[:12] in (v.stdout + v.stderr),
             (v.stdout + v.stderr)[-400:])

        # --- B2: NO environment variable at all. The default path is unpinned
        # (`$HOME/Projects/warrant/impl/warrant.py`), so planting the stub there
        # is the same attack with nothing to notice. Run against a FAKE $HOME:
        # this test must never write into the operator's real checkout.
        fake_home = work / "fakehome"
        (fake_home / "Projects" / "warrant" / "impl").mkdir(parents=True)
        (fake_home / "Projects" / "warrant" / "impl" / "warrant.py").write_text(STUB)
        env = {k: v for k, v in os.environ.items() if k != "WARRANT_CLI"}
        env["HOME"] = str(fake_home)
        r = subprocess.run([sys.executable, "impl/oaip.py", "rebuild"], cwd=work,
                           capture_output=True, text=True, env=env)
        out = r.stdout + r.stderr
        case("stub planted at the UNPINNED DEFAULT PATH (no env var): no edge "
             "from the forgery", all(w != fwid for _, w in edges(work)),
             f"{edges(work)} {out[-300:]}")
        case("stub at the default path: the refusal names the signature",
             "does NOT verify" in out, out[-400:])

        # --- B3: STICKINESS. A refusal must not leave a projection that keeps
        # asserting what the canonical layer no longer supports.
        r = run("rebuild")
        case("the honest CLI still refuses the poisoned store", r.returncode != 0,
             (r.stdout + r.stderr)[-200:])
        case("a refused rebuild leaves the projection bytes in place "
             "(fail-closed is not destroy-first)",
             (work / ".oaip" / "ledger.db").is_file() and edges(work) == honest,
             edges(work))
        log = run("log")
        case("after a refused rebuild `oaip log` REFUSES to report the "
             "projection", log.returncode != 0 and "WARRANT" not in log.stdout,
             (log.stdout + log.stderr)[-300:])
        case("and it says why, naming the marker",
             "UNTRUSTED" in (log.stdout + log.stderr).upper()
             and "rebuild" in (log.stdout + log.stderr),
             (log.stdout + log.stderr)[-300:])
        v = run("verify")
        case("`oaip verify` reports the projection as untrusted, and fails",
             v.returncode != 0 and "MARKED UNTRUSTED" in (v.stdout + v.stderr),
             (v.stdout + v.stderr)[-400:])

        # Remove the forgery: the store is honest again, so a rebuild succeeds
        # and the projection's authority comes back with it.
        (work / ".oaip" / "warrants" / "records" / f"{fwid}.json").unlink()
        r = run("rebuild")
        case("with the forgery removed, rebuild succeeds again",
             r.returncode == 0, (r.stdout + r.stderr)[-300:])
        log = run("log")
        case("a successful rebuild restores the projection's authority",
             log.returncode == 0 and "WARRANT" in log.stdout,
             (log.stdout + log.stderr)[-300:])
        case("and the honest edge is exactly what it was", edges(work) == honest,
             f"{edges(work)} vs {honest}")


def ed25519_sign(seed, msg):
    """(public key, signature) — RFC 8032, reusing the implementation's own point
    arithmetic. A test that only ever produces JUNK signatures cannot show that a
    VALID one is handled correctly, and C2-F1b is entirely about a valid one."""
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


def part_c():
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "cosign")
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(C): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        honest = edges(work)
        case("setup(C): there is an acceptance edge to lose", len(honest) == 1,
             honest)
        p, env = real_accept(work)
        wid = p.stem

        # A SECOND ENDORSER. Warrant SPEC §5 permits appending a co-signature to a
        # filed record — the envelope is not hashed, only the body is — and
        # deliberately will not let one invalidate a good record.
        pub, sig = ed25519_sign(bytes.fromhex("11" * 32), bytes.fromhex(wid))
        env["sigs"].append({"actor": "cosigner@other", "key": pub.hex(),
                            "sig": sig.hex()})
        p.write_text(json.dumps(env))
        vr = subprocess.run(wcli() + ["--store", ".oaip/warrants", "verify"],
                            cwd=work, capture_output=True, text=True)
        case("negative control: `warrant verify` still reports 0 errors "
             "(§5: an appended co-sig cannot invalidate a good record)",
             vr.returncode == 0, (vr.stdout + vr.stderr)[-300:])
        case("negative control: the co-signature really is VALID under OAIP's "
             "own check", O.signature_verifies(wid, env["sigs"][-1]))
        case("negative control: the record's own actor is still signed for",
             O.signature_verifies(wid, env["sigs"][0]))

        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an appended VALID co-signature does NOT delete the acceptance edge",
             edges(work) == honest, f"{edges(work)} vs {honest} | {out[-400:]}")
        case("and the rebuild that keeps it exits 0", r.returncode == 0,
             out[-300:])
        case("the co-signature is REPORTED as a note, not acted on as a refusal",
             "NOTE" in out and "co-signature" in out, out[-400:])
        log = run("log")
        case("`oaip log` still shows the WARRANT line", "WARRANT" in log.stdout,
             log.stdout)
        v = run("verify")
        case("`oaip verify` passes a co-signed acceptance", v.returncode == 0,
             (v.stdout + v.stderr)[-400:])

        # A JUNK co-signature must not delete it either — same §5 reasoning, and
        # this is the case Warrant reports as "excluded" rather than passing over.
        env["sigs"].append({"actor": "griefer@other", "key": "cd" * 32,
                            "sig": "ef" * 64})
        p.write_text(json.dumps(env))
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an appended JUNK co-signature does not delete the edge either",
             edges(work) == honest and r.returncode == 0,
             f"{edges(work)} | {out[-400:]}")
        case("the junk entry is named as excluded",
             "EXCLUDED" in out or "excluded" in out, out[-400:])

        # THE OTHER HALF OF C2-F1b: when an edge really is dropped, say so and
        # do not exit 0. Removing the accept record from the store is the
        # simplest honest way to lose one.
        p.unlink()
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("an edge that vanishes from the canonical layer is a LOUD failure, "
             "not a silent success", r.returncode != 0, out[-400:])
        case("the loud failure names the lost edge and the reason",
             "LOST an acceptance edge" in out and wid[:12] in out, out[-500:])
        case("and the new projection no longer asserts it", edges(work) == [],
             edges(work))


def part_d():
    # `oaip accept` cannot avoid delegating the SIGNING — it does not hold an
    # Ed25519 signer and asks the Warrant CLI to sign — but it can decline to
    # take the result on trust. Until it did, a hostile $WARRANT_CLI could make
    # the LIVE projection assert an acceptance nothing had signed; only a later
    # rebuild or verify would have caught it.
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "acceptcheck")
        # A wrapper that is the REAL Warrant CLI in every respect except that it
        # corrupts the signature of the record it has just filed.
        wrapper = work / "sabotage.py"
        wrapper.write_text(
            "import json, subprocess, sys\n"
            "from pathlib import Path\n"
            f"REAL = {wcli()!r}\n"
            "r = subprocess.run(REAL + sys.argv[1:], capture_output=True, text=True)\n"
            "sys.stderr.write(r.stderr)\n"
            "if 'accept' in sys.argv and r.returncode == 0 and '--store' in sys.argv:\n"
            "    wid = (r.stdout.strip().splitlines() or [''])[-1]\n"
            "    p = (Path(sys.argv[sys.argv.index('--store') + 1]) / 'records'\n"
            "         / (wid + '.json'))\n"
            "    if p.is_file():\n"
            "        env = json.loads(p.read_text())\n"
            "        env['sigs'][0]['sig'] = 'ab' * 64\n"
            "        p.write_text(json.dumps(env))\n"
            "sys.stdout.write(r.stdout)\n"
            "sys.exit(r.returncode)\n")
        env = {"WARRANT_CLI": f"{sys.executable} {wrapper}"}
        iid = run("intent", "sabotaged", env=env).stdout.strip()
        eid = run("run", "--intent", iid, "--", "sh", "-c", "echo hi > f.txt",
                  env=env).stdout.split()[1]
        cid = run("claim", "--execution", eid, "--predicate", "p",
                  "--check", "true", env=env).stdout.split()[1]
        r = run("accept", "--claim", cid, "--actor", "tester@local", env=env)
        out = r.stdout + r.stderr
        case("a CLI that files an unsigned record: accept REFUSES",
             r.returncode != 0 and "ACCEPTED" not in r.stdout, out[-400:])
        case("the refusal names OAIP's own check, not the CLI's exit status",
             "does NOT verify" in out, out[-400:])
        case("and no acceptance edge reached the live projection",
             all(c != cid for c, _ in edges(work)), edges(work))


def flood_entries(env, n):
    """`n` appended signature entries, each crafted to cost the verifier as much
    as possible: a REAL point as `R` (so decompression succeeds) and a reduced
    `S` (so the scalar multiplication actually runs). Junk entries that fail an
    early check are cheap, and a test that used them would measure nothing."""
    real = env["sigs"][0]
    return [{"actor": f"griefer{i % 7}@other", "key": real["key"],
             "sig": real["sig"][:64] + (i + 1).to_bytes(32, "little").hex()}
            for i in range(n)]


def part_e():
    """F1/F2 (2026-07-30, FOURTH round): `sigs` is outside the hashed body, so
    appending to it is free and unbounded, and OAIP verified every entry.

    Measured before the caps, with 5,000 appended entries on ONE honest accept:
    `oaip rebuild` 8.54 s against 0.35 s for the same store without them (and
    0.28 s for `warrant verify` over the same file), the same again for
    `oaip verify`, and 10,000 NOTE lines on stderr / 10,003 on stdout for that
    one record — the ERR and `decision layer:` summary buried as the first and
    last line of the dump.

    The two properties this pins are in tension, which is why they are asserted
    together: the work must be bounded, AND the appended junk must still not
    un-decide the edge (C2-F1b)."""
    n = 5000
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "flood")
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(E): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        honest = edges(work)
        p, env = real_accept(work)
        wid = p.stem

        # A REAL second endorser, kept across the flood: the bounded path must not
        # be "stop looking", it must be "stop verifying what cannot decide".
        pub, sig = ed25519_sign(bytes.fromhex("11" * 32), bytes.fromhex(wid))
        env["sigs"].append({"actor": "cosigner@other", "key": pub.hex(),
                            "sig": sig.hex()})
        p.write_text(json.dumps(env))
        t0 = time.time()
        base = run("rebuild")
        base_dt = time.time() - t0
        case("baseline(E): the co-signed honest record rebuilds",
             base.returncode == 0 and edges(work) == honest,
             (base.stdout + base.stderr)[-300:])

        env["sigs"] += flood_entries(env, n)
        p.write_text(json.dumps(env))
        case(f"setup(E): {n} entries appended and the record still matches its "
             "own address (the flood is free, which is the whole problem)",
             sha256(canon(env["body"])) == wid)

        t0 = time.time()
        r = run("rebuild")
        dt = time.time() - t0
        out = r.stdout + r.stderr
        # A RELATIVE bound, so the check means the same thing on a slow machine:
        # the flood must not multiply the work of the same store without it.
        budget = max(base_dt * 3, base_dt + 3.0)
        case(f"{n} appended signatures do not multiply rebuild's work "
             f"({dt:.2f}s vs {base_dt:.2f}s baseline, budget {budget:.2f}s)",
             dt < budget, f"took {dt:.2f}s")
        case("the flooded record's acceptance edge SURVIVES (C2-F1b: appending "
             "must not un-decide)", edges(work) == honest,
             f"{edges(work)} vs {honest} | {out[-300:]}")
        case("and the rebuild that keeps it exits 0", r.returncode == 0,
             out[-300:])
        case("the notes are COLLAPSED, not dumped: a human can still read the "
             f"report ({len(out.splitlines())} lines)",
             len(out.splitlines()) < 40, f"{len(out.splitlines())} lines")
        case("and the collapse says how many entries and how many actors",
             "further signature entries excluded" in out
             and "distinct actor" in out, out[-500:])

        t0 = time.time()
        v = run("verify")
        vdt = time.time() - t0
        vout = v.stdout + v.stderr
        case(f"`oaip verify` is bounded too ({vdt:.2f}s, budget {budget:.2f}s)",
             vdt < budget, f"took {vdt:.2f}s")
        case("`oaip verify` still passes the flooded-but-honest record",
             v.returncode == 0, vout[-400:])
        case(f"`oaip verify` prints a report, not a dump "
             f"({len(vout.splitlines())} lines)", len(vout.splitlines()) < 40,
             f"{len(vout.splitlines())} lines")

        # The other end of the same lever: bytes, not entries. A record padded
        # past the size limit is refused BY NAME, before it is parsed.
        big = dict(env)
        big["sigs"] = env["sigs"] + [{"actor": "pad@other", "key": "cd" * 32,
                                      "sig": "ef" * 64, "pad": "A" * (5 << 20)}]
        p.write_text(json.dumps(big))
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("a store record padded past the size limit is refused in a sentence",
             r.returncode != 0 and "over the" in out and "byte limit" in out,
             out[-400:])
        case("and that refusal marks the projection untrusted",
             (work / ".oaip" / "projection.untrusted").is_file())


def file_accept(work, body, seed, actor):
    """An accept record at its own valid address, signed with a REAL Ed25519 key
    that this ledger does not bind — the case `warrant verify` reports as a
    WARNING by specification (§5, §5.1), so the store still verifies at 0 errors
    and the record reaches OAIP's own gate."""
    wid = sha256(canon(body))
    pub, sig = ed25519_sign(seed, bytes.fromhex(wid))
    (work / ".oaip" / "warrants" / "records" / f"{wid}.json").write_text(
        json.dumps({"body": body, "sigs": [{"actor": actor, "key": pub.hex(),
                                            "sig": sig.hex()}]}))
    return wid


def part_f():
    """F6 (2026-07-30, FOURTH round): `verify` and `rebuild` audited different
    sets of accepts.

    `_rebuild` ran `assess_signer` on EVERY accept; `cmd_verify` ran it only on
    accepts whose note starts with `oaip-claim:`. They agreed on edges — nothing
    was derived unverified — and disagreed on REPORTING, which is the half a
    human acts on. Measured before the fix, with a note-less accept carrying a
    real claim's subject hash and a valid signature by an UNBOUND key:
    `oaip rebuild` printed "WARN accept <id> … key … is not bound to actor
    'tester@local'", and `oaip verify` printed nothing about it and exited 0.
    Under --allow-legacy-links that same class of record can produce an edge."""
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "auditset")
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(F): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        _, env = real_accept(work)

        # (1) A NOTE-LESS accept about the same claim's subject, signed by a key
        # nobody vouches for. This is the record --allow-legacy-links derives
        # from, and the one `verify` never looked at.
        body = json.loads(json.dumps(env["body"]))
        body["ts"] = body["ts"] + 1
        body["subject"].pop("note", None)
        wid = file_accept(work, body, bytes.fromhex("22" * 32), "tester@local")

        r = run("rebuild", "--allow-legacy-links")
        out = r.stdout + r.stderr
        case("negative control(F): rebuild already reports the note-less accept",
             wid[:12] in out and "not bound" in out, out[-500:])
        case("negative control(F): and derives no edge from it",
             all(w != wid for _, w in edges(work)), edges(work))
        v = run("verify")
        vout = v.stdout + v.stderr
        case("`oaip verify` audits the note-less accept rebuild warns about",
             wid[:12] in vout, vout[-600:])
        case("and reports it as an ERROR, so the exit status carries it",
             v.returncode != 0 and "ERR" in vout and "not bound" in vout,
             vout[-600:])

    # (2) The other direction, which the same change must not break: a decision
    # in the store that is NOT about an OAIP claim (root adoption, key rotation,
    # another ledger's business — F14). `rebuild` warns and derives nothing;
    # `verify` must not turn that into an accusation or a failing exit status.
    with tempfile.TemporaryDirectory() as tmp:
        work, run = make_repo(tmp, "foreign")
        r = run("do", "--intent", "real work", "--check", "test -f f.txt",
                "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
        if "ACCEPTED" not in r.stdout:
            case("setup(F2): the one-shot flow accepted", False, r.stdout + r.stderr)
            return
        honest = edges(work)
        _, env = real_accept(work)
        body = json.loads(json.dumps(env["body"]))
        body["ts"] = body["ts"] + 2
        body["actor"] = {"id": "root@other-ledger"}
        body["subject"] = {"hash": "ab" * 32}      # no OAIP claim has this subject
        fwid = file_accept(work, body, bytes.fromhex("33" * 32),
                           "root@other-ledger")
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("a foreign decision in the store: rebuild still succeeds",
             r.returncode == 0 and edges(work) == honest, out[-400:])
        v = run("verify")
        vout = v.stdout + v.stderr
        case("`oaip verify` passes a store holding another ledger's decision "
             "(no false accusation, F14)", v.returncode == 0, vout[-600:])
        case("and it is reported as a WARN, matching what rebuild says",
             fwid[:12] in vout and "WARN" in vout, vout[-600:])


def main():
    part_a()
    part_b()
    part_c()
    part_d()
    part_e()
    part_f()
    print("\nSIGNATURE-GATE: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
