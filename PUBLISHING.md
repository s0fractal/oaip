# Publishing `oaip` to PyPI

Publishing is automated with **Trusted Publishing (OIDC)** — no API tokens are
stored anywhere. Cutting a GitHub Release builds, validates, and publishes the
package (`.github/workflows/publish.yml`). You do a **one-time** setup on PyPI,
then every release publishes itself.

- **Distribution name:** `oaip` — claimed, and held by this repository's Trusted
  Publisher: <https://pypi.org/project/oaip/>.
- **Import module & CLI command:** `oaip` (the flat `impl/oaip.py`, unchanged).
- **What ships:** one stdlib-only module and the `oaip` console script. Nothing
  else — no `examples/`, no `tests/`, no Warrant.
- **Released so far:** **0.1.0**, **0.2.0** and **0.2.1** (all 2026-07-30) and
  **0.3.0** (2026-07-31, current). Tags `v0.1.0` … `v0.3.0`. Every one went out
  through the workflow below; none was uploaded by hand.
- **One of the four shipped broken.** 0.2.0 passed the release gate as it then
  stood and `pip install oaip==0.2.0 && cd /tmp && oaip records` raised
  `FileNotFoundError` for the entire life of that release; 0.2.1 exists to fix
  it, and the gate was rewritten to measure the artifact instead of the
  checkout (step 3 below). A publish path that runs is not a publish path that
  catches things.
- **What has been checked about the published artifact:** the maintainer
  installed 0.3.0 from PyPI into a clean venv and ran `oaip records` to
  `OAIP-RECORDS: ALL PASS (117/117)`. Nobody else is known to have installed
  any release. If this file and PyPI ever disagree, PyPI is right.

## Warrant is NOT installed with this package, and that matters

SPEC §1 and §3 make Warrant a **normative dependency**: acceptance is a signed
Warrant record and canonicalization is "exactly per Warrant SPEC §4". But Warrant
is invoked as an **external CLI** (`$WARRANT_CLI`, or a sibling checkout), not
imported, so `pip install oaip` gives you a working `oaip` with **no decision
layer**. `init`, `do`, `accept`, `bind`, `rebuild` and `verify` will tell you so.

Say this on the release notes rather than letting a stranger find it: the wheel
is the observer, not the whole stack.

## One-time setup (you, on the web — I can't do this part)

> **Already done.** The publisher exists and has minted tokens for four
> releases. Kept for the next project, and for re-establishing the publisher if
> it is ever lost — but the project now exists on PyPI, so re-establishing it is
> an ordinary publisher, not a *pending* one.

### 1. Add a "pending publisher" on PyPI

Before the first publish the project did not exist on PyPI, so this was a
*pending* publisher: it creates the project on the first publish. Go to
<https://pypi.org/manage/account/publishing/> → "Add a pending publisher" and
enter **exactly**:

| Field | Value |
|---|---|
| PyPI Project Name | `oaip` |
| Owner | `s0fractal` |
| Repository name | `oaip` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Repeat on <https://test.pypi.org/manage/account/publishing/> with Environment
`testpypi` if you want the dry run below (recommended for a first release).

### 2. Create the GitHub Environments

In the repo → Settings → Environments, create `pypi` (and optionally `testpypi`).
Add protection to `pypi` if you want a manual approval gate before each publish
(recommended: "Required reviewers" = you). The name is already claimed; the gate
is now about not shipping a bad artifact — which has happened once — and a
version number on PyPI cannot be reused even after a delete.

## Releasing (every version, automated)

1. Bump `version` in `pyproject.toml` and merge to `main` through the normal
   branch + review path.
2. Cut a GitHub Release with tag **`v0.3.1`** — the `v` plus the exact pyproject
   version (which is `0.3.0` right now, so it must be bumped first). The
   workflow fails the build if they disagree:

   ```bash
   gh release create v0.3.1 --generate-notes
   ```
3. The `publish` workflow builds, runs `twine check`, installs the wheel into a
   fresh venv, and runs `tools/check_release_surface.py` against that install.
   The gate fails the build if any subcommand or flag the docs name is missing
   from the wheel — and, since 0.2.1, if any verb that CAN be executed offline
   does not actually run: `conformance`, `records` and `trust-root` are invoked
   with no arguments **from a fresh directory that is not the checkout**, and
   must exit 0, print what they promise, and leave that directory empty. The
   other ten verbs write, or need a Warrant CLI, or need an initialised ledger;
   the gate names each one and its reason on every run, so "checked for
   existence only" is stated rather than assumed.

   That distinction is not theoretical. 0.2.0 passed the old gate and shipped:
   it ran `oaip conformance <path into the checkout>`, so the default argument —
   the relative path `examples/vectors.json`, which the wheel did not contain —
   was never exercised, and `pip install oaip==0.2.0 && cd /tmp && oaip records`
   raised `FileNotFoundError`. Finding a verb in `--help` is not finding that it
   runs.

   Only after the gate passes does the workflow publish via OIDC. Watch it:

   ```bash
   gh run watch
   ```
4. Confirm the public install:

   ```bash
   pipx install oaip        # or: pip install oaip
   oaip --help
   ```

## Dry run on TestPyPI (never actually performed)

All four real releases went straight to PyPI; the `testpypi` job has never
executed, so this is a documented plan and not a tested procedure — and 0.2.0 is
what it would have been for. After the TestPyPI pending publisher + `testpypi`
environment exist, trigger the workflow manually to publish to TestPyPI only:

```bash
gh workflow run publish.yml
gh run watch
python3 -m venv /tmp/tv && /tmp/tv/bin/pip install -i https://test.pypi.org/simple/ oaip
/tmp/tv/bin/oaip --help
```

## What the release gate does and does not prove

`tools/check_release_surface.py` reads the built wheel as a zip, checks the
installed copy comes from site-packages, and then checks every `oaip …`
invocation quoted in `README.md` and `llms.txt` against the CLI's own parser
output. It also replays the §1 canonicalization vectors from a directory that is
not the checkout, so the wheel is proved to *compute*, not merely to parse.

It does **not** exercise acceptance. Every verb that files or reads a Warrant
record needs a Warrant CLI, which a fresh venv does not have; those verbs are
checked for existence and for accepting their documented flags, nothing more.
The §4 rule (`execution success ≠ validation ≠ acceptance`) is gated by
`tools/check.py` in `ci.yml`, from a checkout, with Warrant pinned. A green
publish run is not a claim about §4.

Run it yourself before tagging:

```bash
python3 tools/check_release_surface.py --selftest      # the extractor
python3 tools/check_release_surface.py                 # this checkout
python3 -m build && python3 -m venv /tmp/ov && /tmp/ov/bin/pip install dist/*.whl
python3 tools/check_release_surface.py --wheel dist/*.whl --bin /tmp/ov/bin
```

## After the first publish — done

- `README.md` carries the installed form (`pipx install oaip`) beside the
  checkout form (`python3 $oaip …`). The release-surface gate reads both, so
  those lines have been checked against the real parser since the moment they
  were written.
- The published versions are recorded at the top of this file.

## Manual fallback (if you ever bypass CI)

```bash
python3 -m build && twine check dist/*
twine upload dist/*                    # needs your PyPI token in ~/.pypirc
```

Bypassing CI also bypasses the release gate. If you do it, run
`tools/check_release_surface.py --wheel … --bin …` by hand first, or you are
publishing something nobody has checked against its own documentation.
