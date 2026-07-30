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

## Ten seconds

```bash
cd your-git-repo
oaip=~/…/oaip/impl/oaip.py
python3 $oaip init                                  # ledger + a local Warrant store + dev key

# one-shot: intent → run the agent action → validate → accept ONLY if the check passes
python3 $oaip do --intent "make login reject expired tokens" \
        --predicate auth.rejects-expired \
        --check "python3 tests/test_auth.py" \
        --actor you@host \
        -- your-agent-command

python3 $oaip log        # intent → execution → effects → claim → warrant
python3 $oaip verify     # artifacts match their addresses; the store verifies;
                         # and every OAIP acceptance was signed by a key bound
                         # to the actor it claims (see llms.txt for what that
                         # does and does not establish)
```

If the validation check passes, `do` files a signed Warrant. If the command
exits 0 but the check **fails**, `do` refuses and files nothing — that refusal
is the whole point (SPEC §4). The four verbs (`intent` / `run` / `claim` /
`accept`) are also available separately when you want to inspect each step;
`examples/auth-demo.sh` walks them, including the refusal case.

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

## Status

`v0.1` DRAFT — see [`SPEC.md`](SPEC.md). Reference implementation in
[`impl/oaip.py`](impl/oaip.py) (stdlib + the Warrant CLI), which as of
2026-07-30 emits the records SPEC §2 declares; ledgers written before that are
read under §6.4 legacy mode and marked, never rewritten. The wedge is
**provable agent-action acceptance for regulated / multi-agent development**, not
a general dev tool; for a solo human in an IDE, git is enough.

**Deliberately not here yet:** semantic-entity (tree-sitter) scope, a reaction
runtime, federation. Those are refinements above this input layer, added only
when a real workflow needs them.

License: MIT (implementation); the spec text is CC-BY-4.0.
