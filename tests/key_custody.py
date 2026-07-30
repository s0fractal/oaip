#!/usr/bin/env python3
"""Does the observer exfiltrate its own signing key into the repo it observes?

THE DEFECT (found and fixed 2026-07-30)
---------------------------------------
`workspace_snapshot()` built the before/after tree with `git add -A` into a
throwaway index. A throwaway INDEX is not throwaway OBJECTS: `git add` writes
every added file as a loose blob into `.git/objects`, so in any repo whose
.gitignore did not already exclude `.oaip/` — including every repo created by
`git init` + `oaip init`, which wrote no .gitignore — the snapshot embedded
`.oaip/dev.key`, the Ed25519 SIGNING KEY behind every warrant this ledger
files. Demonstrated before the fix: `git ls-tree -r <after_tree>` listed
`.oaip/dev.key` and `git cat-file blob <hash-of-key>` printed the key hex from
the object database. From there the key travels with any clone, push, bundle
or backup of `.git` — the custody of the decision layer, exfiltrated by the
observation layer.

The fix is two independent walls, and this test checks each one ALONE:

  1. `workspace_snapshot()` excludes `.oaip` by PATHSPEC — it must hold even
     when no .gitignore exists, so case 2 deletes .gitignore first.
  2. `oaip init` appends `.oaip/` to the repo's .gitignore (creating it if
     missing, never duplicating the line), so the USER's own `git add -A`
     does not commit the key either.

THE FIRST PATHSPEC WAS ITSELF DEFECTIVE (2026-07-30 adversarial review)
-----------------------------------------------------------------------
`-- . ':(exclude).oaip'` passed every case above and still leaked, two ways,
both reproduced by a fresh-context Claude-family reviewer:

  * `:(exclude).oaip` anchors at the pathspec root, so a NESTED ledger
    (`sub/.oaip/dev.key`, from `oaip init` run in a subdirectory) was added
    like any other file — the identical key leak, one directory down.
  * Both pathspecs were cwd-RELATIVE. Run from `sub/`: `git rm --cached --
    .oaip` meant `sub/.oaip`, so a HEAD-tracked root `.oaip` survived into
    every snapshot; and `-- .` silently narrowed the "FULL worktree" snapshot
    to the cwd subtree, so a wrapped command mutating anything outside cwd
    produced effects=0 — an observer that observed less the deeper you stood.

Cases 5–7 below pin all three properties: nested exclusion, repo-rooted
removal from a subdirectory, and full-worktree reach from a subdirectory.

AND IT WAS DEFECTIVE A THIRD TIME: THE LETTER CASE (second adversarial round)
----------------------------------------------------------------------------
`:(top,exclude,glob)` matches case-SENSITIVELY. This project is developed on
macOS/APFS, which is case-INSENSITIVE: `Path(".oaip").mkdir(exist_ok=True)`
succeeds into a pre-existing `.OAIP`, every `.oaip/...` write lands there, and
git reports the real on-disk name — so the exclusion matched nothing and the
key leaked as `.OAIP/dev.key`, tracked (4a) or untracked with a DIRECTORY named
.gitignore removing wall 2 (4b). This FILE could not see it either: the
detector was `".oaip" in p.split("/")`, case-sensitive in exactly the same way.
Both are fixed; the detector is case-insensitive and cases 4a/4b are the repros.

AND A FOURTH TIME: A SYMLINK (case 4c, same round)
--------------------------------------------------
`ln -s ledgerstore .oaip` gives the ledger a second name, and every exclusion
here works by NAME, so `git add -A` added the real path: `ledgerstore/dev.key`
in the tree and the key's blob in `.git/objects`. `oaip init` followed the
symlink without a word. `init` now refuses, and the snapshot excludes the
symlink's target as well and says loudly that the arrangement is wrong.

WHY THE NEGATIVE CONTROL IS IN THE FILE
---------------------------------------
Case 1 re-runs the PRE-FIX snapshot procedure (read-tree, `git add -A` with no
pathspec, write-tree — byte-for-byte the old code path) and asserts the key IS
in that tree and the key's blob IS in the object database. If that ever stops
holding, the detection below proves nothing — a leak check that cannot see a
deliberate leak is noise. It is also this repo's record that the leak was
real, in the same file as the proof that it is gone.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ok = True

# THE TRUST ROOT IS NO LONGER IN THE WORKSPACE (O4, 2026-07-30), so every ledger
# this file creates keeps its key and keyring under a THROWAWAY
# XDG_CONFIG_HOME. Set in the environment rather than passed per-run, so that
# every subprocess inherits it — including the ones that rebuild the environment
# from scratch — and so no test run writes into the operator's own ~/.config.
import atexit as _atexit                                          # noqa: E402
import shutil as _shutil                                          # noqa: E402
import tempfile as _tempfile                                      # noqa: E402
_XDG = _tempfile.mkdtemp(prefix="oaip-test-xdg-")
os.environ["XDG_CONFIG_HOME"] = _XDG
_atexit.register(lambda: _shutil.rmtree(_XDG, ignore_errors=True))


def trust_root(work):
    """Where this ledger's key and keyring actually live — asked of the tool,
    not recomputed here, so the test cannot disagree with the implementation
    about the one path the whole property is about."""
    r = subprocess.run([sys.executable, str(ROOT / "impl" / "oaip.py"),
                        "trust-root", "--path"], cwd=work,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot resolve the trust root in {work}: "
                         f"{r.stdout}{r.stderr}")
    return Path(r.stdout.strip())


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


class Repo:
    """A throwaway git repo WITHOUT a .gitignore — the vulnerable configuration."""

    def __init__(self, tmp, pre=None):
        self.dir = Path(tmp)
        self.dir.mkdir()
        self.git("init", "-q", ".")
        self.git("-c", "user.email=t@t", "-c", "user.name=t",
                 "commit", "-q", "--allow-empty", "-m", "init")
        if pre:
            pre(self)               # arrange the repo BEFORE `oaip init` runs
        self.run("init")
        # The property under test is about the KEY BYTES, not about Warrant:
        # if no Warrant CLI generated a key, plant a sentinel secret so the
        # test still measures custody (and never depends on the neighbour).
        key = self.dir / ".oaip" / "dev.key"
        if not key.exists():
            key.write_text("0" * 63 + "1\n")

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.dir,
                              capture_output=True, text=True)

    def run(self, *a, sub=None):
        """Run oaip; `sub` runs it from a SUBDIRECTORY of the repo (the cwd the
        cwd-relative pathspecs leaked from)."""
        cwd = self.dir / sub if sub else self.dir
        return subprocess.run([sys.executable, str(ROOT / "impl" / "oaip.py"), *a],
                              cwd=cwd, capture_output=True, text=True)

    def snapshot_tree(self, sub=None, cmd="echo hi > f.txt"):
        """One real snapshot, extracted from a real `oaip run`."""
        r = self.run("run", "--intent", "x", "--", "sh", "-c", cmd, sub=sub)
        for tok in r.stdout.split():
            if tok.startswith("after_tree="):
                return tok.split("=", 1)[1]
        raise SystemExit(f"setup failed: no after_tree= in {r.stdout!r} {r.stderr!r}")

    def key_blob(self, key=".oaip/dev.key"):
        """The git blob id the key WOULD have — without writing it anywhere."""
        r = subprocess.run(["git", "hash-object", key], cwd=self.dir,
                           capture_output=True, text=True)
        return r.stdout.strip()

    def key_in_odb(self, key=".oaip/dev.key"):
        return self.git("cat-file", "-e", self.key_blob(key)).returncode == 0

    def tree_paths(self, tree):
        return self.git("ls-tree", "-r", "--name-only", "--full-tree",
                        tree).stdout.splitlines()

    def oaip_paths_in(self, tree):
        # ANY path component named .oaip, at ANY depth, in ANY LETTER CASE.
        # `startswith(".oaip")` was how this file failed to see the nested-ledger
        # leak; `".oaip" in p.split("/")` was how it failed to see the leak as
        # `.OAIP/dev.key` on the case-insensitive filesystem this project is
        # developed on (2026-07-30, second adversarial round). A detector that
        # cannot see the leak is not evidence about the leak.
        return [p for p in self.tree_paths(tree)
                if ".oaip" in [c.lower() for c in p.split("/")]]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # --- 1. the negative control: the pre-fix procedure DOES leak, and this
        # test's detectors see it. Run first; every case below is meaningless
        # without it.
        L = Repo(Path(tmp) / "control")
        (L.dir / ".gitignore").unlink(missing_ok=True)   # isolate from wall 2
        env_index = L.dir / "old.index"
        env = dict(os.environ, GIT_INDEX_FILE=str(env_index.resolve()))
        subprocess.run(["git", "read-tree", "HEAD"], cwd=L.dir, env=env,
                       capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=L.dir, env=env,
                       capture_output=True)               # the old code, verbatim
        old_tree = subprocess.run(["git", "write-tree"], cwd=L.dir, env=env,
                                  capture_output=True, text=True).stdout.strip()
        case("negative control: the pre-fix snapshot embeds .oaip in its tree",
             f".oaip/dev.key" in "\n".join(L.oaip_paths_in(old_tree)),
             f"tree={old_tree} paths={L.oaip_paths_in(old_tree)}")
        case("negative control: the key's bytes reached .git/objects",
             L.key_in_odb())

    with tempfile.TemporaryDirectory() as tmp:
        # --- 2. wall 1 alone: NO .gitignore anywhere, only the pathspec
        # exclusion stands between the key and the object database.
        L = Repo(Path(tmp) / "w")
        (L.dir / ".gitignore").unlink(missing_ok=True)
        tree = L.snapshot_tree()
        case("snapshot tree carries no .oaip path (with .gitignore DELETED)",
             L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")
        case("the signing key's bytes never entered .git/objects",
             not L.key_in_odb())
        case("the snapshot still saw the actual work",
             "f.txt" in L.git("ls-tree", "-r", "--name-only", tree).stdout)

    with tempfile.TemporaryDirectory() as tmp:
        # --- 3. a user who committed .oaip BEFORE the fix: HEAD tracks the key,
        # so read-tree seeds it into the throwaway index. The blob is already in
        # the odb (that damage predates the snapshot), but no NEW tree this
        # observer writes may keep asserting it.
        L = Repo(Path(tmp) / "h")
        (L.dir / ".gitignore").unlink(missing_ok=True)
        L.git("add", "-f", ".oaip")
        L.git("-c", "user.email=t@t", "-c", "user.name=t",
              "commit", "-q", "-m", "user committed the ledger")
        tree = L.snapshot_tree()
        case("HEAD tracks .oaip: the snapshot tree still refuses to carry it",
             L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")

    with tempfile.TemporaryDirectory() as tmp:
        # --- 4a. THE LETTER CASE (second adversarial round, 2026-07-30).
        # `:(top,exclude,glob)` matches case-SENSITIVELY. On the
        # case-INSENSITIVE filesystem this project is developed on (macOS/APFS)
        # `OAIP.mkdir(exist_ok=True)` resolves into an existing `.OAIP`, the key
        # is written there, and git reports the real name — so `**/.oaip/**`
        # excluded nothing. Measured on macOS before the fix, this exact case:
        # tree listed `.OAIP/dev.key`, and `git cat-file -e` found the key blob.
        #
        # On a case-SENSITIVE filesystem the same arrangement is a user
        # directory that merely LOOKS like a ledger; the assertion is the same
        # either way, because a snapshot must not carry `.oaip` in any casing.
        def plant_upper(L):
            (L.dir / ".OAIP").mkdir()
            (L.dir / ".OAIP" / "dev.key").write_text("3" * 63 + "1\n")
            L.git("add", "-f", ".OAIP")
            L.git("-c", "user.email=t@t", "-c", "user.name=t",
                  "commit", "-q", "-m", "user committed .OAIP")

        L = Repo(Path(tmp) / "case-tracked", pre=plant_upper)
        (L.dir / ".gitignore").unlink(missing_ok=True)
        tree = L.snapshot_tree()
        case("HEAD-tracked .OAIP: snapshot carries no .oaip path in ANY case",
             L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")

    with tempfile.TemporaryDirectory() as tmp:
        # --- 4b. the UNTRACKED half of the same finding, with wall 2 removed the
        # way this branch's own directory-`.gitignore` fix removes it: a
        # DIRECTORY named .gitignore makes `oaip init` warn and move on, so
        # nothing is ignored and the pathspec is the only wall left. Measured on
        # macOS before the fix: the tree gained `.OAIP/dev.key`,
        # `.OAIP/ledger.db`, `.OAIP/tmp.index` and `.OAIP/tmp.index.lock`.
        def plant_upper_untracked(L):
            (L.dir / ".OAIP").mkdir()
            (L.dir / ".gitignore").mkdir()      # wall 2 cannot be written

        L = Repo(Path(tmp) / "case-untracked", pre=plant_upper_untracked)
        # On a case-sensitive filesystem `oaip init` made its own `.oaip`; plant
        # a sentinel in `.OAIP` too so the case there is a real leak candidate.
        upper_key = L.dir / ".OAIP" / "dev.key"
        if not upper_key.exists():
            upper_key.write_text("4" * 63 + "1\n")
        tree = L.snapshot_tree()
        case("untracked .OAIP with no writable .gitignore: nothing .oaip-ish "
             "in the tree", L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")
        case("the .OAIP signing key's bytes never entered .git/objects",
             not L.key_in_odb(".OAIP/dev.key"))

    with tempfile.TemporaryDirectory() as tmp:
        # --- 4c. A SYMLINKED LEDGER (F6, second adversarial round). The exclusion
        # is by NAME, and a symlink gives the same directory a second name:
        # `ln -s ledgerstore .oaip` and `git add -A` adds the REAL path, which
        # `**/.oaip/**` does not match. Measured before the fix, this exact case:
        # the tree carried `ledgerstore/dev.key`, `ledgerstore/ledger.db`,
        # `ledgerstore/trust.json`, `ledgerstore/tmp.index`, and `git cat-file -e`
        # found the key blob. `init` followed the symlink without a word.
        d = Path(tmp) / "sym"
        d.mkdir()
        subprocess.run(["git", "init", "-q", "."], cwd=d, capture_output=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "--allow-empty", "-m", "init"],
                       cwd=d, capture_output=True)
        (d / "ledgerstore").mkdir()
        (d / ".oaip").symlink_to("ledgerstore")
        oaip = lambda *a: subprocess.run(
            [sys.executable, str(ROOT / "impl" / "oaip.py"), *a], cwd=d,
            capture_output=True, text=True)
        r = oaip("init")
        case("init REFUSES a symlinked .oaip instead of following it",
             r.returncode != 0 and "symlink" in (r.stdout + r.stderr)
             and "Traceback" not in r.stderr, f"rc={r.returncode} {r.stderr[:200]}")

        # A symlink can also be made AFTER a legitimate init, so the snapshot must
        # not depend on init having refused. Build that state directly.
        (d / ".oaip").unlink()
        r = oaip("init")
        (d / ".gitignore").unlink(missing_ok=True)
        os.rename(d / ".oaip", d / "ledgerstore2")
        (d / ".oaip").symlink_to("ledgerstore2")
        key = d / "ledgerstore2" / "dev.key"
        if not key.exists():
            key.write_text("5" * 63 + "1\n")
        r = oaip("run", "--intent", "x", "--", "sh", "-c", "echo hi > f.txt")
        tree = next((t.split("=", 1)[1] for t in r.stdout.split()
                     if t.startswith("after_tree=")), "")
        paths = subprocess.run(["git", "ls-tree", "-r", "--name-only",
                                "--full-tree", tree], cwd=d,
                               capture_output=True, text=True).stdout.splitlines()
        case("symlinked ledger: the snapshot excludes the SYMLINK'S TARGET too",
             tree and not any(p.startswith("ledgerstore2/") for p in paths),
             f"tree={tree} paths={paths}")
        blob = subprocess.run(["git", "hash-object", "ledgerstore2/dev.key"],
                              cwd=d, capture_output=True, text=True).stdout.strip()
        case("symlinked ledger: the key's bytes never entered .git/objects",
             subprocess.run(["git", "cat-file", "-e", blob], cwd=d,
                            capture_output=True).returncode != 0)
        case("symlinked ledger: the snapshot says so, loudly",
             "SYMLINK" in r.stderr, r.stderr[:300])

    with tempfile.TemporaryDirectory() as tmp:
        # --- 5. a NESTED ledger: `oaip init` run in a subdirectory. The first
        # pathspec (':(exclude).oaip') anchored at the root and leaked
        # sub/.oaip/dev.key into the object database exactly as the original
        # bug leaked ./.oaip/dev.key (2026-07-30 adversarial review).
        L = Repo(Path(tmp) / "n")
        (L.dir / ".gitignore").unlink(missing_ok=True)
        (L.dir / "sub").mkdir()
        L.run("init", sub="sub")
        (L.dir / "sub" / ".gitignore").unlink(missing_ok=True)
        subkey = L.dir / "sub" / ".oaip" / "dev.key"
        if not subkey.exists():                     # no Warrant CLI: sentinel
            subkey.parent.mkdir(parents=True, exist_ok=True)
            subkey.write_text("2" * 63 + "1\n")
        tree = L.snapshot_tree()
        case("nested ledger: snapshot tree carries no sub/.oaip path",
             L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")
        case("the nested signing key's bytes never entered .git/objects",
             not L.key_in_odb("sub/.oaip/dev.key"))

    with tempfile.TemporaryDirectory() as tmp:
        # --- 6. run from a SUBDIRECTORY with a HEAD-tracked root .oaip: the
        # cwd-relative `git rm --cached -- .oaip` meant sub/.oaip, so the
        # root key survived into every tree the observer wrote.
        L = Repo(Path(tmp) / "s")
        (L.dir / ".gitignore").unlink(missing_ok=True)
        L.git("add", "-f", ".oaip")
        L.git("-c", "user.email=t@t", "-c", "user.name=t",
              "commit", "-q", "-m", "user committed the root ledger")
        (L.dir / "sub").mkdir()
        L.run("init", sub="sub")                    # the cwd's own ledger
        (L.dir / "sub" / ".gitignore").unlink(missing_ok=True)
        tree = L.snapshot_tree(sub="sub")
        case("run from sub/: the HEAD-tracked root .oaip is still purged",
             L.oaip_paths_in(tree) == [],
             f"tree={tree} leaked={L.oaip_paths_in(tree)}")

        # --- 7. the REGRESSION half of the same finding: `-- .` narrowed the
        # snapshot to the cwd subtree, so a wrapped command mutating a file
        # OUTSIDE the cwd was unobserved (effects=0, before==after). The
        # docstring promises the FULL worktree; hold it to that.
        r = L.run("run", "--intent", "x", "--", "sh", "-c",
                  "echo escaped > ../outside.txt", sub="sub")
        after = next((t.split("=", 1)[1] for t in r.stdout.split()
                      if t.startswith("after_tree=")), "")
        case("a mutation OUTSIDE the cwd is still observed (effects != 0)",
             "effects=0" not in r.stdout and "effects=" in r.stdout, r.stdout)
        case("the snapshot tree is the full worktree, not the cwd subtree",
             "outside.txt" in L.tree_paths(after),
             f"tree={after} paths={L.tree_paths(after)}")

    with tempfile.TemporaryDirectory() as tmp:
        # --- 8. wall 2: init owns the .gitignore line.
        L = Repo(Path(tmp) / "g")
        gi = L.dir / ".gitignore"
        text = gi.read_text() if gi.is_file() else ""     # a clean FAIL, no crash
        case("init created .gitignore in a repo that had none", gi.is_file())
        case("init's .gitignore excludes .oaip/",
             ".oaip/" in [l.strip() for l in text.splitlines()], text or "<missing>")
        L.run("init")
        text = gi.read_text() if gi.is_file() else ""
        case("a second init does not duplicate the line",
             [l.strip() for l in text.splitlines()].count(".oaip/") == 1, text)
        gi.write_text("*.pyc")                            # no trailing newline
        L.run("init")
        lines = gi.read_text().splitlines()
        case("an existing .gitignore is appended to, not clobbered",
             lines[0] == "*.pyc" and ".oaip/" in [l.strip() for l in lines],
             gi.read_text())
        case("appending respected the missing trailing newline",
             "*.pyc.oaip/" not in gi.read_text(), gi.read_text())
        # A bare `.oaip` line already excludes the directory (gitignore matches
        # it at any depth); appending `.oaip/` next to it is noise.
        gi.write_text(".oaip\n")
        L.run("init")
        case("a bare `.oaip` line is recognized; no redundant `.oaip/` appended",
             gi.read_text() == ".oaip\n", gi.read_text())
        # A DIRECTORY named .gitignore is not writable config. init used to die
        # with an uncaught IsADirectoryError; a warning is a decision, a
        # traceback is an accident (2026-07-30 adversarial review, P3).
        gi.unlink()
        gi.mkdir()
        r = L.run("init")
        case("init with a directory .gitignore warns instead of crashing",
             r.returncode == 0 and "Traceback" not in r.stderr
             and "warning" in r.stderr, f"rc={r.returncode} {r.stderr[:200]}")

    with tempfile.TemporaryDirectory() as tmp:
        # --- 4e (C1-F1, third adversarial round): `icase` is key-safe and it is
        # an UNANNOUNCED OBSERVATION HOLE. The exclusion drops any path whose
        # component case-folds to `.oaip`, at any depth, on any filesystem — so
        # `src/.Oaip/config.yml`, a user's own file with nothing to do with this
        # ledger, vanished from every snapshot with no warning, in the tool whose
        # entire job is to observe. The exclusion stays (leaving things out is
        # the safe direction for a signing key); the silence does not.
        L = Repo(Path(tmp) / "icase")
        (L.dir / "src" / ".Oaip").mkdir(parents=True)
        (L.dir / "src" / ".Oaip" / "config.yml").write_text("x: 1\n")
        (L.dir / "src" / "kept.txt").write_text("observed\n")
        r = L.run("run", "--intent", "x", "--", "sh", "-c", "echo hi > f.txt")
        tree = next((t.split("=", 1)[1] for t in r.stdout.split()
                     if t.startswith("after_tree=")), "")
        paths = L.tree_paths(tree)
        case("a user path that merely case-folds to .oaip is still excluded",
             "src/.Oaip/config.yml" not in paths, paths)
        case("the negative control: its sibling IS observed",
             "src/kept.txt" in paths, paths)
        case("the exclusion no longer does it silently: the path is NAMED",
             "src/.Oaip/config.yml" in r.stderr, r.stderr[-400:])
        case("...and the warning says what it costs",
             "UNOBSERVED" in r.stderr, r.stderr[-400:])
        # A NESTED ledger is not this ledger and is still a ledger: reporting
        # `sub/.oaip/dev.key` as a lost user file would be false, and "rename it
        # if it should be observed" is bad advice about a signing key.
        (L.dir / "sub").mkdir()
        L.run("init", sub="sub")
        subkey = L.dir / "sub" / ".oaip" / "dev.key"
        if not subkey.exists():
            subkey.parent.mkdir(parents=True, exist_ok=True)
            subkey.write_text("7" * 63 + "1\n")
        r = L.run("run", "--intent", "x", "--", "sh", "-c", "echo hi > g.txt")
        case("a NESTED ledger is not announced as a lost user file",
             "sub/.oaip" not in r.stderr, r.stderr[-400:])

    with tempfile.TemporaryDirectory() as tmp:
        # --- 4d (C1-F2, third adversarial round): a plain FILE at the ledger
        # path. The DIRECTORY case (a real `.oaip`) and the SYMLINK case were
        # both handled; the file case was missed, so `OAIP.mkdir(exist_ok=True)`
        # raised a bare FileExistsError traceback. A refusal is a decision.
        d = Path(tmp) / "filepath"
        d.mkdir()
        subprocess.run(["git", "init", "-q", "."], cwd=d, capture_output=True)
        oaip = lambda *a, **kw: subprocess.run(
            [sys.executable, str(ROOT / "impl" / "oaip.py"), *a], cwd=d,
            capture_output=True, text=True, **kw)
        (d / ".oaip").write_text("not a ledger\n")
        r = oaip("init")
        out = r.stdout + r.stderr
        case("a FILE at .oaip: init refuses instead of tracebacking",
             r.returncode != 0 and "Traceback" not in r.stderr
             and "not a directory" in out, f"rc={r.returncode} {out[-200:]}")
        case("the refusal says what lives there, so it is not deleted lightly",
             "SIGNING KEY" in out, out[-300:])
        r = oaip("log")
        case("...and a read command diagnoses it too, without a traceback",
             r.returncode != 0 and "Traceback" not in r.stderr,
             (r.stdout + r.stderr)[-200:])
        (d / ".oaip").unlink()
        # An uninitialised ledger was the same defect class: sqlite3 raised
        # `unable to open database file` and the traceback was the answer to
        # "there is no ledger here".
        r = oaip("log")
        case("no ledger at all: `log` says so instead of raising sqlite3",
             r.returncode != 0 and "Traceback" not in r.stderr
             and "oaip init" in (r.stdout + r.stderr),
             (r.stdout + r.stderr)[-200:])
        # A FILE named `.OAIP` is the same path on a case-insensitive filesystem
        # (this project's own development platform), and a different one
        # elsewhere; assert only where it is the same path.
        (d / ".OAIP").write_text("not a ledger either\n")
        if (d / ".oaip").exists():          # the filesystem folds case
            r = oaip("init")
            case("a FILE at .OAIP on a case-insensitive filesystem: refused too",
                 r.returncode != 0 and "Traceback" not in r.stderr,
                 (r.stdout + r.stderr)[-200:])
        (d / ".OAIP").unlink()

    with tempfile.TemporaryDirectory() as tmp:
        # --- 10 (third adversarial round): a READ-ONLY ledger directory made
        # `oaip bind` die with a PermissionError traceback. The keyring is what
        # OAIP consults before deriving any acceptance edge, so a keyring it
        # cannot update is a refusal that must be readable as one.
        L = Repo(Path(tmp) / "ro")
        # The keyring lives in the TRUST ROOT, which since O4 is outside the
        # workspace by default; the case is the same one — a directory OAIP
        # cannot write — asked of the directory that now holds the keyring.
        root = trust_root(L.dir)
        trust = root / "trust.json"
        trust.unlink(missing_ok=True)
        os.chmod(root, 0o500)
        try:
            r = L.run("bind", "--actor", "someone@local")
            out = r.stdout + r.stderr
            case("a read-only ledger: bind diagnoses instead of tracebacking",
                 r.returncode != 0 and "Traceback" not in r.stderr
                 and "trust.json" in out, f"rc={r.returncode} {out[-250:]}")
            case("the diagnosis says nothing was bound",
                 "Nothing was bound" in out, out[-250:])
        finally:
            os.chmod(root, 0o700)

    with tempfile.TemporaryDirectory() as tmp:
        # --- 9 (third adversarial round): `oaip bind` is the one command whose
        # whole purpose is to say WHICH key may sign as an actor, and it was the
        # least careful place in the codebase about it: any hex64 was accepted
        # with no cross-check against `.oaip/dev.key.pub`, no warning, and `oaip
        # verify` clean afterwards — while `cmd_accept` refuses an acceptance
        # signed by a key that is not this ledger's. Binding a foreign key is a
        # legitimate act (a store filed by another ledger), but it is a different
        # act, and it now has to be said out loud.
        L = Repo(Path(tmp) / "bind")
        root = trust_root(L.dir)        # not the workspace, since O4
        pub = root / "dev.key.pub"
        if not pub.is_file():           # no Warrant CLI: a sentinel own-key
            pub.write_text("b" * 63 + "1\n")
        own = pub.read_text().strip()
        trust = root / "trust.json"
        foreign = "a" * 64

        r = L.run("bind", "--actor", "someone@else", "--key", foreign)
        out = r.stdout + r.stderr
        case("bind REFUSES a key that is not this ledger's own",
             r.returncode != 0 and "Traceback" not in r.stderr, out[-200:])
        case("the refusal names both keys and the flag that would allow it",
             foreign[:12] in out and own[:12] in out and "--foreign-key" in out,
             out[-300:])
        case("the refused bind wrote nothing into the keyring",
             foreign not in trust.read_text(), trust.read_text())

        r = L.run("bind", "--actor", "someone@else", "--key", foreign,
                  "--foreign-key")
        out = r.stdout + r.stderr
        case("with --foreign-key it binds", r.returncode == 0, out[-200:])
        case("...and says loudly that OAIP does not hold that key",
             "FOREIGN" in r.stderr and "revoke" in r.stderr, r.stderr[-300:])
        case("...and the keyring records it", foreign in trust.read_text(),
             trust.read_text())

        r = L.run("bind", "--actor", "tester@local", "--key", own)
        case("binding this ledger's OWN key needs no flag and no warning",
             r.returncode == 0 and "FOREIGN" not in r.stderr,
             (r.stdout + r.stderr)[-200:])

    print("\nKEY-CUSTODY: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
