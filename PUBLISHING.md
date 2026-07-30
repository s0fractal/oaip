# Publishing `oaip` to PyPI

Publishing is automated with **Trusted Publishing (OIDC)** — no API tokens are
stored anywhere. Cutting a GitHub Release builds, validates, and publishes the
package (`.github/workflows/publish.yml`). You do a **one-time** setup on PyPI,
then every release publishes itself.

- **Distribution name:** `oaip` (checked 2026-07-30:
  <https://pypi.org/simple/oaip/> returns **404**, i.e. the name is free — but
  PyPI is first-come, and this is only true until someone else takes it).
- **Import module & CLI command:** `oaip` (the flat `impl/oaip.py`, unchanged).
- **What ships:** one stdlib-only module and the `oaip` console script. Nothing
  else — no `examples/`, no `tests/`, no Warrant.
- **Nothing has ever been published from this repository.** There are no tags
  and no releases. Everything below is the first time.

## Warrant is NOT installed with this package, and that matters

SPEC §1 and §3 make Warrant a **normative dependency**: acceptance is a signed
Warrant record and canonicalization is "exactly per Warrant SPEC §4". But Warrant
is invoked as an **external CLI** (`$WARRANT_CLI`, or a sibling checkout), not
imported, so `pip install oaip` gives you a working `oaip` with **no decision
layer**. `init`, `do`, `accept`, `bind`, `rebuild` and `verify` will tell you so.

Say this on the release notes rather than letting a stranger find it: the wheel
is the observer, not the whole stack.

## One-time setup (you, on the web — I can't do this part)

### 1. Add a "pending publisher" on PyPI

The project does not exist on PyPI yet, so this is a *pending* publisher: it
creates the project on the first publish. Go to
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
(recommended: "Required reviewers" = you). The first publish is the one that
claims the name; a gate there is cheap.

## Releasing (every version, automated)

1. Bump `version` in `pyproject.toml` and merge to `main` through the normal
   branch + review path.
2. Cut a GitHub Release with tag **`v0.1.0`** — the `v` plus the exact pyproject
   version. The workflow fails the build if they disagree:

   ```bash
   gh release create v0.1.0 --generate-notes
   ```
3. The `publish` workflow builds, runs `twine check`, installs the wheel into a
   fresh venv, runs `oaip --help` and the §1 conformance vectors **from /tmp**
   (not from the checkout), and then runs `tools/check_release_surface.py`, which
   fails the build if any subcommand or flag the docs name is missing from the
   wheel. Only then does it publish via OIDC. Watch it:

   ```bash
   gh run watch
   ```
4. Confirm the public install:

   ```bash
   pipx install oaip        # or: pip install oaip
   oaip --help
   ```

## Dry run before the first real release (recommended)

After the TestPyPI pending publisher + `testpypi` environment exist, trigger the
workflow manually to publish to TestPyPI only:

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

## After the first publish

- Add the one-liner (`pipx install oaip`) to `README.md`, which currently only
  documents the checkout form (`python3 $oaip …`). The release-surface gate reads
  both forms, so the new lines are checked from the moment they are written.
- Record the published version here, and remember that if this file and PyPI ever
  disagree, PyPI is right.

## Manual fallback (if you ever bypass CI)

```bash
python3 -m build && twine check dist/*
twine upload dist/*                    # needs your PyPI token in ~/.pypirc
```

Bypassing CI also bypasses the release gate. If you do it, run
`tools/check_release_surface.py --wheel … --bin …` by hand first, or you are
publishing something nobody has checked against its own documentation.
