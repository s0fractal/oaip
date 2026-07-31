# OAIP — Observed Action & Intent Protocol

**An agent reports that it fixed the thing. The pipeline exits 0. Who checked, and
who decided that what they checked was the thing?**

That is one question, not two, and the second half is where it goes wrong. Almost
every tool in this area takes an agent's own account of its work as the record of
that work: it wrote "fixed auth", so the dashboard says auth is fixed. Even when a
check runs, the party being checked usually supplied the check, chose its scope,
and reported the result. OAIP is built so that the account of what happened is
**observed** rather than reported, and so that accepting it is a separate act by a
separate key: *what* changed and *from which* workspace state are measured, not
narrated; *why* and *by whom* are recorded with honest uncertainty; and the
acceptance is a signed record citing a validation that anyone can re-run.

Git remembers **what** changed. OAIP remembers the rest: *why* (intent), *by whom*, *from which workspace state*, *on what observed evidence*, *what was validated*, and — the part that matters for agents — that a change was **accepted**, not just that a command exited 0.

```
intent  →  execution  →  effects  →  claim  →  ACCEPT
"reject   "ran the      "src/auth.py  "auth       a signed Warrant, citing the
 expired   change"       modified,      rejects     provenance as evidence and the
 tokens"                 test added"    expired"    validation as a re-runnable check
```

The accepted decision is a real, signed, hash-addressed [Warrant](https://github.com/s0fractal/warrant) record — not a line in `console.log`.

## Why not just a trace log / agent-observability tool?

Because those treat **an agent's own JSON as fact**: it wrote "fixed auth", so the dashboard says auth is fixed. OAIP's cardinal rule (SPEC §4):

> **execution success ≠ validation success ≠ acceptance.**
> A zero exit code earns *execution success only*. A claim is acceptable only if a **separate** validation check passes, and acceptance is a **signed Warrant** filed under policy.

So the bridge **refuses** to accept a claim whose check failed — even if the command returned 0. That refusal is the whole product.

## Install

```bash
pipx install oaip
pipx install warrant-verify
```

`oaip` 0.3.0 is the current release on PyPI. The second line is not optional
scenery: SPEC §1 and §3 make [Warrant](https://github.com/s0fractal/warrant) a
**normative dependency**, invoked as an external CLI (`$WARRANT_CLI`, or a
sibling checkout) rather than imported, so a venv holding only the first one has
no decision layer and can accept nothing. It must be Warrant SPEC v0.4 / package
≥ 0.6.0; older versions sign a different message and every acceptance is
refused.

Everything below is written in the checkout form (`python3 $oaip …`) because
that is what a contributor runs; with the wheel installed, `oaip …` is the same
program.

## Ten seconds

```bash
cd your-git-repo
oaip=~/…/oaip/impl/oaip.py
python3 $oaip init         # ledger + a local Warrant store, and a signing key
                           # in a TRUST ROOT *outside* this repo (see below)

# one-shot: intent → run the agent action → validate → accept ONLY if the check passes
python3 $oaip do --intent "make login reject expired tokens" \
        --predicate auth.rejects-expired \
        --check "python3 tests/test_auth.py" \
        --allow-check-effects \
        --actor you@host \
        -- your-agent-command

python3 $oaip log        # intent → execution → effects → claim → warrant
python3 $oaip verify     # artifacts match their addresses; the store verifies;
                         # every OAIP acceptance was signed by a key bound to the
                         # actor it claims; and the key custody is reported
                         # (see llms.txt for what that does and does not establish)
python3 $oaip trust-root # where the key and keyring live, and what that stops
```

If the validation check passes, `do` files a signed Warrant. If the command
exits 0 but the check **fails**, `do` refuses and files nothing — that refusal
is the whole point (SPEC §4). The four verbs (`intent` / `run` / `claim` /
`accept`) are also available separately when you want to inspect each step;
`examples/auth-demo.sh` walks them, including the refusal case.

`--allow-check-effects` is there because the check above really does write to
your repository: `python3 tests/test_auth.py` leaves `__pycache__/`. The
execution's after-state was snapshotted **before** the check ran, so without the
flag OAIP refuses the claim rather than sign a decision whose effect list omits
those writes; with it, the claim cites what the check changed as evidence. Drop
the flag if your check is read-only — and read SPEC §8.5 SA-13 before reading
either behaviour as confinement: the check runs unconfined on your host
(`oaip-host-shell@v1`, §7.3), and this observes what it did rather than
preventing it.

## What it gets right by construction

- **`before_state = HEAD` lies.** The observer snapshots the *full workspace*
  (tracked + staged + untracked + env/toolchain fingerprint) into a throwaway git
  index — content-addressed, no commits added to your history. (SPEC §2.2)
- **Canonical vs projection.** The truth is the content-addressed artifacts + the
  Warrant store. The SQLite ledger is a *projection* you can delete and rebuild.
  (SPEC §5)
- **Causality is honest.** Attribution carries a confidence in parts-per-million
  integers (no floats); an honest "probably the agent" beats a deterministic lie.
  (SPEC §2.6)
- **It reuses, doesn't reinvent.** Warrant SPEC §4 canonicalization *verbatim*;
  accepted claims are Warrant records; Σ-GLYPH `ski@v1` is the forward path for
  portable checks. OAIP adds exactly one layer: a clean input to the decision layer.
- **The record formats are pinned by vectors, not by the implementation.**
  `examples/vectors.json` pins how a record serializes and
  `examples/record-vectors.json` pins what a record *is* — positive shapes and,
  more usefully, the shapes that MUST be refused. Until 2026-07-30 only the first
  existed, and the reference implementation wrote a different record from SPEC §2
  for every type in it while reporting conformance; `llms.txt` tells that story.
  (SPEC §10)
- **It says what it is not.** SPEC §9 maps every record onto W3C PROV and onto
  in-toto/SLSA, states where IETF SCITT begins and OAIP stops, and names the two
  things OAIP actually adds — the acceptance boundary and uncertain attribution.
  If those two are not what you need, §9 says so and points elsewhere.

## Where it fits

```
Reactions        (budget-bounded; not in v0.1)
Policies         (execution / decision / reaction)
Warrant          signed decisions + causal DAG        ← github.com/s0fractal/warrant
Claims           formalized assertions about states
── OAIP ──────── observed causality: intent/execution/effect/attribution
Σ-GLYPH          deterministic portable checks         ← github.com/s0fractal/sigma-glyph
Git / CAS        content-addressed bytes
```

## The bridge generalizes: graduating decisions

The `accept` bridge isn't code-specific. The same *subject + evidence + reason →
signed Warrant* move graduates **any** decision that is attributed and
tamper-evident but not yet **signed** — for instance a `decision` node in a
[mind-os / workos](https://github.com/s0fractal/mind-os) thought-graph, whose own
README calls per-author cryptographic signatures *"the deliberate next tier."*
This bridge **is** that tier: it reads the decision's public projection and files
a Warrant that ratifies it, citing the source as evidence — without the source
taking a hard dependency on Warrant. See
[`examples/graduate-decision.sh`](examples/graduate-decision.sh). So the four
repos compose into one stack: Σ-GLYPH computes checks, OAIP observes doing,
mind-os records reasoning, and Warrant is the signed-decision tier both provenance
halves graduate into.

## Who can forge an acceptance here

The point of the §4 gate is that the party being gated cannot supply its own
acceptance. That is a property of **where the signing key is**, so OAIP keeps the
key and the keyring in a **trust root outside the observed workspace** —
`$XDG_CONFIG_HOME/oaip/roots/<ledger>` by default, or wherever `--trust-root` /
`$OAIP_TRUST_ROOT` says. `oaip run` hands the observed command a workspace; it no
longer hands it the key that signs the verdict on that command's work.

Stated as precisely as it can be (the full matrix is [SPEC §8](SPEC.md), and it
is executed by `tests/privilege_separation.py`):

- **An agent with write access to the workspace** can no longer mint an
  acceptance: a keyring it writes at `.oaip/trust.json` is never read, deleting
  or rewriting `.oaip/store.json` does not move the answer, and the key is not
  there to read. It can still make OAIP **refuse** — it can delete store records
  — and every such loss is reported non-zero.
- **The same agent running unconfined as the observer's own uid** can read the
  trust root wherever it is. Relocation buys nothing there; that needs a second
  uid or a separate signing process (SPEC §8.4 profiles C and D — documented,
  **not implemented**). Relocation is decisive when the agent's write access is
  confined to the workspace: a container mount, a CI checkout, a sandboxed tool.
- **Anyone who can write the trust root, or control the environment,** can forge
  freely. Nothing stops them, and SPEC §8.2 says so rather than describing a
  control that does not exist.
- **The check the claim is judged by still runs against post-agent state.** An
  agent that rewrites its own test passes honestly. That hole is open and is
  stated as a boundary of the threat model, not a to-do (SPEC §8.5, SA-1).

Existing ledgers with an in-workspace key keep working, say so on every accept,
and move with one command: `oaip trust-root --migrate`.

## Status

`v0.1` DRAFT — see [`SPEC.md`](SPEC.md). Reference implementation in
[`impl/oaip.py`](impl/oaip.py) (stdlib + the Warrant CLI), which as of
2026-07-30 emits the records SPEC §2 declares; ledgers written before that are
read under §6.4 legacy mode and marked, never rewritten.

**Requires Warrant SPEC v0.4 / package ≥ 0.6.0** (CI pins commit `8508a4a`).
Warrant v0.4 changed the bytes an Ed25519 signature covers to
`"warrant-sig-v1:" || WarrantID`, OAIP verifies that signature itself, and the
old and new constructions are disjoint on purpose — so an older Warrant makes
every acceptance fail, and a `.oaip/warrants` store signed before 2026-07-31
needs `warrant resign --key <keyfile>` once before it yields an acceptance edge
again. Re-signing moves no WarrantID and changes nothing else in the graph.
This is deliberately **not** the §6.4 legacy path: a superseded signature is
refused and diagnosed, never read in a weaker mode (SPEC §8.6). The wedge is
**provable agent-action acceptance for regulated / multi-agent development**, not
a general dev tool; for a solo human in an IDE, git is enough.

**Deliberately not here yet:** semantic-entity (tree-sitter) scope, a reaction
runtime, federation. Those are refinements above this input layer, added only
when a real workflow needs them.

License: MIT (implementation); the spec text is CC-BY-4.0.
