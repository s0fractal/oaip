#!/usr/bin/env python3
"""Can the party this protocol exists to gate supply its own acceptance?

WHAT FIVE ROUNDS OF REVIEW LEFT OPEN (O4, 2026-07-30)
-----------------------------------------------------
Rounds one to five hardened WHAT OAIP believes: the address, the signature, the
key↔actor binding, the claim link, the cost of checking them. Each fix narrowed
the forger's requirements by one step, and the last step was written down in
`llms.txt` as the residual boundary:

    anyone who can write `.oaip/` can write the keyring AND the signing key.

That is precisely the observed agent. `oaip run` executes the wrapped command
with the workspace as its cwd, and the workspace contained `.oaip/dev.key`
(the key every acceptance is signed with) and `.oaip/trust.json` (the file that
says which key may sign as which actor). An agent with ordinary write access to
the repository it is working in could therefore mint its own acceptance —
without breaking a single one of the five rounds' checks, because every one of
them was satisfied honestly by a key the agent legitimately held.

This file is the executable half of the threat model in SPEC §8. It is organised
by ATTACKER CAPABILITY, not by code path:

  Part A  a party with a shared-host account (mode bits): the key and keyring
          must not be group/world accessible, and OAIP must refuse rather than
          sign with one that is.
  Part B  the observed agent (workspace write): with the trust root relocated
          out of the workspace, a hostile `.oaip/trust.json` must be IGNORED,
          and the workspace must contain no copy of the signing key.
  Part C  the same agent trying to DOWNGRADE the arrangement: deleting the
          ledger's own metadata must not silently return OAIP to reading the
          keyring the agent can write.
  Part D  migration: an existing in-workspace ledger keeps working, and
          `oaip trust-root --migrate` moves it across without losing an edge.

EVERY PART CARRIES ITS NEGATIVE CONTROL, in the file, for the reason this
repository has now recorded three times: a detector that cannot see the defect
is not evidence about the defect. Part B's control is the legacy (in-workspace)
trust root, where the same forgery DOES produce an acceptance edge — that is the
measured pre-fix behaviour, kept executable so the fix cannot quietly rot.

WHAT THIS FILE DOES NOT ESTABLISH, SAID HERE RATHER THAN IN A FOOTNOTE
----------------------------------------------------------------------
Relocating the trust root separates it from the WORKSPACE, not from the USER.
A process running as the same uid as the observer can read `$XDG_CONFIG_HOME`
just as easily as `.oaip/`, and nothing in this file claims otherwise: Part B
asserts that workspace write is no longer enough, and Part A asserts that a
shared-host account is not enough either. Same-uid separation needs a second
uid or a separate process holding the key — SPEC §8.4 profiles C and D, which
are documented and NOT implemented.
"""
import atexit
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every ledger this test creates gets its trust root under a THROWAWAY
# XDG_CONFIG_HOME. Set in the environment (not passed per-run) so that every
# subprocess — including the ones that rebuild the environment from scratch —
# inherits it, and so that no test run ever writes into the operator's own
# ~/.config/oaip.
_XDG = tempfile.mkdtemp(prefix="oaip-privsep-xdg-")
os.environ["XDG_CONFIG_HOME"] = _XDG
atexit.register(lambda: shutil.rmtree(_XDG, ignore_errors=True))

ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def wcli():
    return (os.environ.get("WARRANT_CLI")
            or f"{sys.executable} "
               f"{Path.home() / 'Projects/warrant/impl/warrant.py'}").split()


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

    # `--trust-root` is a GLOBAL option: it decides where the key is for every
    # verb, so it precedes the subcommand.
    r = run(*init_args, "init")
    if r.returncode != 0:
        raise SystemExit(f"setup: oaip init failed: {r.stdout}{r.stderr}")
    return work, run


def trust_root(run):
    return Path(run("trust-root", "--path").stdout.strip())


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
    """A shared-host account: mode bits on the key and the keyring.

    Nothing checked these until O4. `warrant keygen` chmods 0600 and OAIP took
    that on trust — so a key widened afterwards by an umask, a restore from a
    tarball, a copy off a mode-less filesystem, or a plain `chmod -R` was used to
    sign acceptances without a word. This is the cheapest real control in the
    whole design and it was the one that was missing."""
    if os.name != "posix":
        print("SKIP  Part A: POSIX mode bits do not decide access here")
        return
    with tempfile.TemporaryDirectory() as tmp:
        work, run, before = accepted_ledger(tmp, "perms")
        root = trust_root(run)
        key = root / "dev.key"
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
        (root / "trust.json").chmod(0o666)
        v = run("verify")
        out = v.stdout + v.stderr
        case("a world-WRITABLE keyring is refused too", v.returncode != 0
             and "trust.json" in out and "vouch for their own key" in out,
             out[-400:])
        (root / "trust.json").chmod(0o600)

        root.chmod(0o777)
        v = run("verify")
        out = v.stdout + v.stderr
        case("a world-writable trust root DIRECTORY is refused (the files "
             "inside it can be replaced whatever their own modes say)",
             v.returncode != 0 and "chmod 700" in out, out[-400:])
        root.chmod(0o700)
        v = run("verify")
        case("...and restoring the directory mode clears it", v.returncode == 0,
             (v.stdout + v.stderr)[-300:])


# ---------------------------------------------------------------- Part B
def forge_acceptance(work, run, actor="tester@local", keyring=None):
    """The observed agent's forgery, executed with nothing but workspace write.

    It generates its own key, files a real, cryptographically valid `accept` into
    the workspace's Warrant store naming a real supported claim, and vouches for
    its own key in `keyring` (the file OAIP consults). Every step is something a
    process with the workspace as its cwd can do. Returns (warrant id, claim id).
    """
    con = sqlite3.connect(work / ".oaip" / "ledger.db")
    cid, subj = con.execute("SELECT id, subject_hash FROM claims "
                            "WHERE supported=1").fetchone()
    con.close()
    attacker = work / "attacker.key"
    kg = subprocess.run(wcli() + ["keygen", "--out", str(attacker)],
                        cwd=work, capture_output=True, text=True)
    pub = kg.stdout.split()[-1]
    rr = subprocess.run(
        wcli() + ["--store", ".oaip/warrants", "accept", "--subject", subj,
                  "--under", ".oaip/policy.txt", "--reason", "self-accepted",
                  "--note", f"oaip-claim:{cid}", "--actor", actor,
                  "--key", str(attacker)],
        cwd=work, capture_output=True, text=True)
    wid = (rr.stdout.strip().splitlines() or [""])[-1]
    if len(wid) != 64:
        raise SystemExit(f"setup: the forged accept did not file: "
                         f"{rr.stdout}{rr.stderr}")
    # …and vouches for its own key, in the file OAIP reads.
    keyring = Path(keyring)
    doc = json.loads(keyring.read_text()) if keyring.is_file() else {"actors": {}}
    doc["actors"].setdefault(actor, []).append(pub)
    keyring.write_text(json.dumps(doc, sort_keys=True) + "\n")
    return wid, cid


def part_b():
    """The observed agent, holding exactly what `oaip run` hands it: write
    access to the workspace it is being observed in."""
    with tempfile.TemporaryDirectory() as tmp:
        # --- THE NEGATIVE CONTROL, and the measured pre-O4 behaviour: with the
        # trust root INSIDE the workspace (`--trust-root .oaip`, which is where
        # every ledger before this change kept it), the forgery works. If this
        # ever stops working, the case below proves nothing.
        work, run, before = accepted_ledger(tmp, "legacy",
                                            ("--trust-root", ".oaip"))
        case("negative control: the legacy layout puts the trust root in the "
             "observed workspace", trust_root(run) == (work / ".oaip").resolve(),
             str(trust_root(run)))
        wid, cid = forge_acceptance(work, run,
                                    keyring=work / ".oaip" / "trust.json")
        r = run("rebuild")
        case("negative control: with an in-workspace keyring the agent's OWN "
             "key mints an acceptance edge",
             any(w == wid for _, w in edges(work)),
             f"rc={r.returncode} {edges(work)} {(r.stdout + r.stderr)[-300:]}")
        case("negative control: and `oaip log` prints it as a signed decision",
             wid[:16] in run("log").stdout, run("log").stdout[-300:])

    with tempfile.TemporaryDirectory() as tmp:
        # --- THE CASE ITSELF: the same agent, the same forgery, the default
        # layout — the trust root outside the workspace.
        work, run, before = accepted_ledger(tmp, "relocated")
        root = trust_root(run)
        case("by default the trust root is OUTSIDE the observed workspace",
             not str(root).startswith(str(work.resolve())), f"{root} vs {work}")
        case("the workspace holds no signing key",
             not (work / ".oaip" / "dev.key").exists())

        # Stronger than "the filename is absent": the key's BYTES are nowhere the
        # agent can read by walking the workspace. (The pre-O4 leak this repo
        # already fixed was about git objects; this is about the worktree.)
        secret = (root / "dev.key").read_text().strip()
        found = []
        for p in work.rglob("*"):
            if p.is_file() and not p.is_symlink():
                try:
                    if secret and secret in p.read_text(errors="ignore"):
                        found.append(str(p.relative_to(work)))
                except OSError:
                    pass
        case("the signing key's BYTES appear in no file under the workspace",
             found == [], found)

        wid, cid = forge_acceptance(work, run,
                                    keyring=work / ".oaip" / "trust.json")
        case("negative control: the agent really did write a keyring into the "
             "workspace naming its own key",
             (work / ".oaip" / "trust.json").is_file())
        r = run("rebuild")
        out = r.stdout + r.stderr
        case("the in-workspace keyring is IGNORED: no acceptance edge from the "
             "agent's own key", all(w != wid for _, w in edges(work)),
             f"rc={r.returncode} {edges(work)} {out[-400:]}")
        case("...and the refusal names the binding, in the RELOCATED keyring "
             "(not the one the agent wrote)",
             "not bound to" in out.lower() and root.name in out
             and str(work / ".oaip" / "trust.json") not in out, out[-500:])
        case("...and the honest edge is untouched", edges(work) == before,
             f"{edges(work)} vs {before}")
        case("...and `oaip log` prints no forged signed decision",
             wid[:16] not in run("log").stdout, run("log").stdout[-300:])
        v = run("verify")
        case("`oaip verify` FAILS on the forged acceptance",
             v.returncode != 0 and wid[:12] in (v.stdout + v.stderr),
             (v.stdout + v.stderr)[-400:])

        # The other half of the same capability: `oaip bind` is the verb that
        # vouches, and in the deployment relocation is FOR — the trust root
        # belongs to someone else — running it must fail as a permission error
        # and be reported as a refusal, not a traceback. The mode bits here stand
        # in for that ownership; they are not themselves the separation (a
        # same-uid process can chmod them back, which is why SPEC §8.4's profiles
        # C and D exist and this one does not claim to be them).
        os.chmod(root / "trust.json", 0o400)
        os.chmod(root, 0o500)
        try:
            r = run("bind", "--actor", "tester@local", "--key", "aa" * 32,
                    "--foreign-key")
            out = r.stdout + r.stderr
            case("a trust root the agent cannot WRITE: `bind` refuses in words "
                 "rather than a traceback",
                 r.returncode != 0 and "Traceback" not in r.stderr, out[-400:])
            case("...and says nothing was bound",
                 "Nothing was bound" in out, out[-400:])
            keyring = json.loads((root / "trust.json").read_text())
            case("...and the keyring really is unchanged",
                 "aa" * 32 not in json.dumps(keyring), keyring)
        finally:
            os.chmod(root, 0o700)
            os.chmod(root / "trust.json", 0o600)


# ---------------------------------------------------------------- Part C
def part_c():
    """The downgrade: can the agent make OAIP look at the keyring it CAN write?

    The trust root is found by three routes — an explicit `--trust-root`, the
    `OAIP_TRUST_ROOT` environment variable, and a default location derived from
    the workspace's own path. The third is what makes the default deployment
    survive this attack: it is computed, not read out of a file the agent can
    edit. This part deletes and rewrites every workspace-side pointer there is
    and asserts the answer does not move."""
    with tempfile.TemporaryDirectory() as tmp:
        work, run, before = accepted_ledger(tmp, "downgrade")
        root = trust_root(run)
        meta = work / ".oaip" / "store.json"

        # 1. delete the ledger's own metadata, then plant a keyring where the
        #    pre-O4 code would have looked.
        wid, cid = forge_acceptance(work, run,
                                    keyring=work / ".oaip" / "trust.json")
        meta.unlink()
        case("the resolved trust root does not move when store.json is deleted",
             trust_root(run) == root, f"{trust_root(run)} vs {root}")
        r = run("rebuild")
        case("...and no edge is derived from the planted in-workspace keyring",
             all(w != wid for _, w in edges(work)),
             f"rc={r.returncode} {edges(work)} {(r.stdout + r.stderr)[-300:]}")

        # 2. rewrite the pointer to a trust root the agent DOES control, inside
        #    the workspace. A workspace-side pointer must never be able to
        #    redirect the trust root; it may only make OAIP refuse.
        (work / "evil").mkdir()
        shutil.copy(work / ".oaip" / "trust.json", work / "evil" / "trust.json")
        meta.write_text(json.dumps(
            {"oaip_store": "oaip-store@v1", "note_convention_since": 1,
             "trust_root": {"mode": "external",
                            "path": str(work / "evil")}}, sort_keys=True) + "\n")
        tr = run("trust-root", "--path")
        out = tr.stdout + tr.stderr
        case("a rewritten pointer cannot redirect the trust root: OAIP REFUSES "
             "rather than choosing", tr.returncode != 0
             and str(work / "evil") not in tr.stdout, f"rc={tr.returncode} {out}")
        case("...and the refusal names both candidates, so a human can tell "
             "which one is theirs",
             str(root) in out and str(work / "evil") in out, out[-400:])
        r = run("rebuild")
        case("...and still derives no edge from the agent's keyring",
             all(w != wid for _, w in edges(work)),
             f"rc={r.returncode} {edges(work)} {(r.stdout + r.stderr)[-300:]}")
        # The refusal is a denial the agent can cause at will — it can already
        # delete a store record, which is equally loud and equally destructive
        # (llms.txt records that trade-off for the signature caps). What it must
        # not be able to do is make OAIP BELIEVE the keyring it wrote.
        meta.unlink()

        # 3. the honest side of the same rule: a pointer that names a root which
        #    is not there must FAIL CLOSED, not fall back to the workspace.
        elsewhere = Path(tmp) / "moved-away"
        meta.write_text(json.dumps(
            {"oaip_store": "oaip-store@v1", "note_convention_since": 1,
             "trust_root": {"mode": "external", "path": str(elsewhere)}},
            sort_keys=True) + "\n")
        shutil.move(str(root), str(Path(tmp) / "stash"))
        try:
            r = run("rebuild")
            out = r.stdout + r.stderr
            case("a missing trust root refuses instead of falling back to the "
                 "workspace", r.returncode != 0 and "Traceback" not in r.stderr,
                 out[-400:])
            case("...and the refusal names the path it expected",
                 str(elsewhere) in out, out[-500:])
        finally:
            shutil.move(str(Path(tmp) / "stash"), str(root))


# ---------------------------------------------------------------- Part D
def part_d():
    """Migration: an existing in-workspace ledger, and the one command that
    moves it. A hardening step that loses the acceptance edges it was protecting
    has not protected them."""
    with tempfile.TemporaryDirectory() as tmp:
        work, run, before = accepted_ledger(tmp, "migrate",
                                            ("--trust-root", ".oaip"))
        case("negative control: a legacy ledger still works as it did",
             before and run("verify").returncode == 0, before)
        v = run("verify")
        case("...and says plainly that its trust root is inside the workspace",
             "IN THE OBSERVED WORKSPACE" in (v.stdout + v.stderr),
             (v.stdout + v.stderr)[-500:])

        r = run("trust-root", "--migrate")
        out = r.stdout + r.stderr
        case("`oaip trust-root --migrate` succeeds", r.returncode == 0, out[-400:])
        new_root = trust_root(run)
        case("...and the key is now outside the workspace",
             not str(new_root).startswith(str(work.resolve()))
             and (new_root / "dev.key").is_file(), f"{new_root}")
        case("...and is gone from the workspace",
             not (work / ".oaip" / "dev.key").exists()
             and not (work / ".oaip" / "trust.json").exists())
        r = run("rebuild")
        case("...and the acceptance edge filed BEFORE the migration survives it",
             r.returncode == 0 and edges(work) == before,
             f"rc={r.returncode} {edges(work)} vs {before} "
             f"{(r.stdout + r.stderr)[-300:]}")
        case("...and a second migration is refused rather than repeated",
             run("trust-root", "--migrate").returncode != 0)

        # And the forgery from Part B now fails on the SAME ledger it worked on.
        wid, cid = forge_acceptance(work, run,
                                    keyring=work / ".oaip" / "trust.json")
        run("rebuild")
        case("the migrated ledger now ignores an in-workspace keyring",
             all(w != wid for _, w in edges(work)), edges(work))


def main():
    part_a()
    part_b()
    part_c()
    part_d()
    print("\nPRIVILEGE-SEPARATION: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
