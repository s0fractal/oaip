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


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


class Repo:
    """A throwaway git repo WITHOUT a .gitignore — the vulnerable configuration."""

    def __init__(self, tmp):
        self.dir = Path(tmp)
        self.dir.mkdir()
        self.git("init", "-q", ".")
        self.git("-c", "user.email=t@t", "-c", "user.name=t",
                 "commit", "-q", "--allow-empty", "-m", "init")
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
            if tok.startswith("after="):
                return tok.split("=", 1)[1]
        raise SystemExit(f"setup failed: no after= in {r.stdout!r} {r.stderr!r}")

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
        # ANY path component named .oaip, at ANY depth — `startswith(".oaip")`
        # was how this file failed to see the nested-ledger leak.
        return [p for p in self.tree_paths(tree) if ".oaip" in p.split("/")]


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
                      if t.startswith("after=")), "")
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

    print("\nKEY-CUSTODY: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
