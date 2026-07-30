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

    def run(self, *a):
        return subprocess.run([sys.executable, str(ROOT / "impl" / "oaip.py"), *a],
                              cwd=self.dir, capture_output=True, text=True)

    def snapshot_tree(self):
        """One real snapshot, extracted from a real `oaip run`."""
        r = self.run("run", "--intent", "x", "--", "sh", "-c", "echo hi > f.txt")
        for tok in r.stdout.split():
            if tok.startswith("after="):
                return tok.split("=", 1)[1]
        raise SystemExit(f"setup failed: no after= in {r.stdout!r} {r.stderr!r}")

    def key_blob(self):
        """The git blob id the key WOULD have — without writing it anywhere."""
        r = subprocess.run(["git", "hash-object", ".oaip/dev.key"], cwd=self.dir,
                           capture_output=True, text=True)
        return r.stdout.strip()

    def key_in_odb(self):
        return self.git("cat-file", "-e", self.key_blob()).returncode == 0

    def oaip_paths_in(self, tree):
        out = self.git("ls-tree", "-r", "--name-only", tree).stdout
        return [p for p in out.splitlines() if p.startswith(".oaip")]


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
        # --- 4. wall 2: init owns the .gitignore line.
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

    print("\nKEY-CUSTODY: " + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
