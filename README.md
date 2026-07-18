# OAIP — Observed Action & Intent Protocol

**A content-addressed causal graph of what humans, agents, and tools actually did — and on what observed basis you accepted the result.**

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

## Ten minutes

```bash
cd your-git-repo
oaip=~/…/oaip/impl/oaip.py

python3 $oaip init                                  # ledger + a local Warrant store + dev key
I=$(python3 $oaip intent "make login reject expired tokens")
python3 $oaip run --intent $I -- your-agent-command # snapshots workspace before/after, records effects
python3 $oaip claim --execution <id> \
        --predicate auth.rejects-expired \
        --check "python3 tests/test_auth.py"        # a SEPARATE validation, not the exit code
python3 $oaip accept --claim <id> --actor you@host  # -> a signed Warrant (refused if the check failed)

python3 $oaip log        # intent → execution → effects → claim → warrant
python3 $oaip verify     # the Warrant store verifies
```

`examples/auth-demo.sh` runs the whole thing, including the refusal case.

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

## Status

`v0.1` DRAFT — see [`SPEC.md`](SPEC.md). Reference implementation in
[`impl/oaip.py`](impl/oaip.py) (stdlib + the Warrant CLI). The wedge is
**provable agent-action acceptance for regulated / multi-agent development**, not
a general dev tool; for a solo human in an IDE, git is enough.

**Deliberately not here yet:** semantic-entity (tree-sitter) scope, a reaction
runtime, federation. Those are refinements above this input layer, added only
when a real workflow needs them.

License: MIT (implementation); the spec text is CC-BY-4.0.
