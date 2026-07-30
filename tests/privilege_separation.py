#!/usr/bin/env python3
"""Can the party this protocol exists to gate supply its own acceptance?

WHAT FIVE ROUNDS OF REVIEW LEFT OPEN (O4, 2026-07-30)
-----------------------------------------------------
Rounds one to five hardened WHAT OAIP believes: the address, the signature, the
key↔actor binding, the claim link, the cost of checking them. Each fix narrowed
the forger's requirements by one step, and the last step is written down in
`llms.txt` as the residual boundary:

    anyone who can write `.oaip/` can write the keyring AND the signing key.

This file is the executable half of the threat model, organised by ATTACKER
CAPABILITY rather than by code path. It starts with the cheapest capability and
the one nothing checked at all:

  Part A  a party with a SHARED-HOST ACCOUNT. `warrant keygen` chmods the key
          0600 and OAIP took that on trust — so a key widened afterwards by an
          umask of 0002, a restore from a tarball, a copy off a mode-less
          filesystem, or a plain `chmod -R` was used to sign acceptances without
          a word, and a keyring at 0666 vouched for whatever anyone wrote into
          it. This is the control every ssh client has enforced for thirty
          years, and its absence was not written down anywhere.

WHAT PART A DOES NOT CLOSE, said here rather than in a footnote: mode bits say
nothing about a process running as the SAME UID, which is exactly the observed
agent's position. The workspace-write capability is a separate commit and a
separate part of this file; until it lands, the boundary in `llms.txt` stands
unchanged and this file must not be read as narrowing it.

Every case carries its negative control in the file, for the reason this
repository has now recorded three times: a detector that cannot see the defect
is not evidence about the defect.
"""
import atexit
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every ledger this test creates keeps its key material under a THROWAWAY
# XDG_CONFIG_HOME. Set in the environment (not passed per-run) so every
# subprocess inherits it — including ones that rebuild the environment from
# scratch — and so no test run ever writes into the operator's own ~/.config.
_XDG = tempfile.mkdtemp(prefix="oaip-privsep-xdg-")
os.environ["XDG_CONFIG_HOME"] = _XDG
atexit.register(lambda: shutil.rmtree(_XDG, ignore_errors=True))

ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def make_repo(tmp, name="w", init_args=()):
    work = Path(tmp) / name
    work.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "."], cwd=work, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "init"],
                   cwd=work, check=True)

    def run(*a, env=None, cwd=None):
        return subprocess.run([sys.executable, str(ROOT / "impl" / "oaip.py"), *a],
                              cwd=cwd or work, capture_output=True, text=True,
                              env=dict(os.environ, **(env or {})))

    r = run("init", *init_args)
    if r.returncode != 0:
        raise SystemExit(f"setup: oaip init failed: {r.stdout}{r.stderr}")
    return work, run


def edges(work):
    db = work / ".oaip" / "ledger.db"
    if not db.is_file():
        return []
    con = sqlite3.connect(db)
    rows = list(con.execute("SELECT claim_id, warrant_id FROM warrants"))
    con.close()
    return rows


def accepted_ledger(tmp, name, init_args=()):
    """A ledger with one real, accepted claim — the state every attack starts
    from. Returns (work, run, edges-before)."""
    work, run = make_repo(tmp, name, init_args)
    r = run("do", "--intent", "real work", "--check", "test -f f.txt",
            "--actor", "tester@local", "--", "sh", "-c", "echo hi > f.txt")
    if "ACCEPTED" not in r.stdout:
        raise SystemExit(f"setup({name}): the one-shot flow did not accept:\n"
                         f"{r.stdout}{r.stderr}")
    return work, run, edges(work)


# ---------------------------------------------------------------- Part A
def part_a():
    """A shared-host account: mode bits on the signing key and the keyring."""
    if os.name != "posix":
        print("SKIP  Part A: POSIX mode bits do not decide access here")
        return
    with tempfile.TemporaryDirectory() as tmp:
        work, run, before = accepted_ledger(tmp, "perms")
        key = work / ".oaip" / "dev.key"
        trust = work / ".oaip" / "trust.json"
        case("the key `init` created is not group/world accessible",
             key.is_file() and (key.stat().st_mode & 0o077) == 0,
             f"{key} mode {key.stat().st_mode & 0o777:04o}" if key.is_file()
             else f"no key at {key}")

        # The negative control FIRST: with honest modes, everything below passes.
        v = run("verify")
        case("negative control: a 0600 key verifies clean", v.returncode == 0,
             (v.stdout + v.stderr)[-400:])

        key.chmod(0o644)
        v = run("verify")
        out = v.stdout + v.stderr
        case("a world-READABLE signing key: `oaip verify` FAILS",
             v.returncode != 0, out[-400:])
        case("...and names the file, the mode and the chmod that fixes it",
             "dev.key" in out and "0644" in out and "chmod 600" in out,
             out[-400:])
        r = run("rebuild")
        case("...and `oaip rebuild` REFUSES rather than deriving edges",
             r.returncode != 0 and "custody" in (r.stdout + r.stderr),
             (r.stdout + r.stderr)[-400:])

        # Signing is the direction that matters most: a signature made with a key
        # other accounts can read is not evidence that this actor decided.
        iid = run("intent", "second").stdout.strip()
        eid = run("run", "--intent", iid, "--", "sh", "-c",
                  "echo two > g.txt").stdout.split()[1]
        cid = run("claim", "--execution", eid, "--predicate", "q",
                  "--check", "true").stdout.split()[1]
        r = run("accept", "--claim", cid, "--actor", "tester@local")
        out = r.stdout + r.stderr
        case("a world-readable key REFUSES to sign a new acceptance",
             r.returncode != 0 and "Traceback" not in r.stderr, out[-400:])
        case("...and the refusal explains what a readable key costs",
             "sign as this actor" in out, out[-400:])

        key.chmod(0o600)
        r = run("rebuild")
        case("with the mode restored the same ledger rebuilds again",
             r.returncode == 0, (r.stdout + r.stderr)[-300:])
        case("...and the honest acceptance edge is still there",
             edges(work) == before, f"{edges(work)} vs {before}")

        # The keyring is a decision INPUT, not a secret: what matters there is
        # who can WRITE it.
        trust.chmod(0o666)
        v = run("verify")
        out = v.stdout + v.stderr
        case("a world-WRITABLE keyring is refused too", v.returncode != 0
             and "trust.json" in out and "vouch for their own key" in out,
             out[-400:])
        trust.chmod(0o600)

        os.chmod(work / ".oaip", 0o777)
        v = run("verify")
        out = v.stdout + v.stderr
        case("a world-writable trust root DIRECTORY is refused (the files "
             "inside it can be replaced whatever their own modes say)",
             v.returncode != 0 and "chmod 700" in out, out[-400:])
        os.chmod(work / ".oaip", 0o700)
        v = run("verify")
        case("...and restoring the directory mode clears it", v.returncode == 0,
             (v.stdout + v.stderr)[-300:])


def main():
    part_a()
    print("\nPRIVILEGE-SEPARATION: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
