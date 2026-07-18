# OAIP — Observed Action & Intent Protocol — Specification v0.1

**Status:** DRAFT. Key words MUST / MUST NOT / SHOULD / MAY per RFC 2119.
**Purpose.** Turn the ephemeral behavior of humans, agents, and tools into a
**content-addressed causal graph** — from which claims, decisions, and reactions
can be built *honestly*. OAIP records **what was observed**; it does **not** decide
whether an action was correct, whether an intent was met, or which policy has
authority. Those are the decision layer (Warrant) and the policy layer.

**Normative dependencies.**
- **Warrant SPEC v0.3** ([github.com/s0fractal/warrant](https://github.com/s0fractal/warrant))
  — the decision layer. OAIP **reuses Warrant §4 canonicalization verbatim** and
  bridges accepted claims into Warrant records (§3). Not reimplemented here.
- **Σ-GLYPH Book I** (optional) — for `ski@v1` portable, budget-bounded checks
  where a predicate is worth compiling to an SKI term. Today most checks are
  `cmd@v1`; `ski@v1` is a forward path, not a v0.1 requirement.

**Design rule.** OAIP adds exactly one thing to the existing stack: a clean,
content-addressed *input* to the decision layer. It MUST NOT grow into the
decision layer, the policy engine, or a reaction runtime — those are separate
profiles above Warrant.

## 0. The stack (a ring, not a pipeline)

```
Observe → Record → Interpret → Decide → Settle → React → Observe again
  │         │          │          │        │        │
  Observer  Ledger     Claims  Warrants  Policies  Reactions
  └────────── OAIP ──────────┘   └──────── Warrant + profiles ────────┘
```

OAIP v0.1 specifies the Observer/Ledger records and the `ClaimCandidate` that
bridges to Warrant. Everything above the bridge is Warrant and its profiles.

## 1. Canonicalization and identity (MUST)

Every OAIP record is JCS-canonical I-JSON **exactly per Warrant SPEC §4**:
UTF-8, RFC 8785 key ordering, the pinned escaping rules, **integers only** (no
floats anywhere), strings measured and hashed as **exact Unicode code points**
(no NFC/NFD normalization), and **duplicate member names rejected**. All hashes
are lowercase hex SHA-256; git object ids are lowercase hex SHA-1 (40) where a
git tree/blob is referenced. All timestamps are Unix seconds in int64.

Two identity kinds:

- **Content-addressed** — identity is `SHA-256` of the canonical bytes (records)
  or the raw bytes (blobs): `Artifact`, `State`, and a claim's `subject`. Cited
  by hash; immutable by construction.
- **Event records** — identity is a monotone, time-sortable `id` (e.g. UUIDv7 /
  KSUID; the reference impl uses `<ms>-<rand>`), with integrity from the content
  hashes they cite: `Intent`, `Execution`, `Effect`, `Attribution`,
  `ClaimCandidate`.

## 2. Record types (v0.1)

### 2.1 `Artifact` — a citable blob
Any blob that may later be evidence: stdout, stderr, a diff, a test report,
compiler diagnostics, a prompt, a model response, a manifest. Identity =
`SHA-256(bytes)`. The ledger stores the reference, not necessarily the bytes.

```json
{ "artifact": "0.1", "hash": "<hex64>", "kind": "<string>", "size": <uint> }
```

### 2.2 `State` — a workspace snapshot (NOT `HEAD`)
A content-addressed snapshot of the **full workspace** at an instant.
`before_state = HEAD` is forbidden: HEAD ignores staged, untracked, worktree,
environment and toolchain state.

```json
{ "state": "0.1",
  "repo_commit": "<hex40 | null>",
  "worktree_tree": "<hex40>",
  "env_fingerprint": "<hex64>",
  "toolchain_fingerprint": "<hex64>" }
```

`worktree_tree` is a git **tree** object capturing tracked + staged + untracked
files, built in a **throwaway index** so no commit is added to history.
`StateID = SHA-256(canon(state))`. A verifier MAY re-materialize the exact file
set from `worktree_tree`. Using a normal `HEAD`/commit as a `State` is a MUST NOT.

### 2.3 `Intent` — a declared goal (not proof it was met)
```json
{ "intent": "0.1", "id": "<id>", "actor": "<string>", "parent": "<id | null>",
  "objective": "<string>", "constraints": ["<string>", "..."],
  "acceptance_refs": ["<hex64>", "..."], "ts": <int> }
```
`acceptance_refs` are hashes of artifacts that would *evidence* satisfaction
(a test, a spec clause). An Intent asserts a target; it never asserts success.

### 2.4 `Execution` — a controlled action container
```json
{ "execution": "0.1", "id": "<id>", "intent": "<id | null>",
  "executor": { "actor": "<string>", "runtime": "<string>" },
  "input_state": "<StateID>", "output_state": "<StateID>",
  "invocation": "<string>", "environment": "<hex64>",
  "status": "exited | failed | killed", "exit_code": <int | null>, "ts": <int> }
```
A shell command is one `executor.runtime` (`shell@v1`); an MCP call, an API edit,
a merge, a rollback are others. `status`/`exit_code` describe **execution**, not
acceptance (§4).

### 2.5 `Effect` — one state mutation
```json
{ "effect": "0.1", "execution": "<id>",
  "kind": "file.create | file.modify | file.delete | <string>",
  "target": "<string>", "before": "<hex40 | null>", "after": "<hex40 | null>",
  "entities": [ <SemanticEntityRef>, "..." ] }
```
`before`/`after` are content hashes (git blob OIDs) — deduplicated, exact.
`entities` (OPTIONAL, reserved) attaches semantic scope (function/class) so a
diff maps to logical units, not just files — a v0.2 refinement (a string scope
is insufficient: names collide, move, and one diff touches many scopes).

### 2.6 `Attribution` — causality, first-class and uncertain
```json
{ "attribution": "0.1", "effect": "<ref>", "cause": "<id>",
  "method": "<string>", "confidence_ppm": <uint 0..1000000>,
  "support": ["<hex64>", "..."] }
```
Causality is **not always certain** — the honest primitive. `confidence_ppm` is
parts-per-million as an **integer** (no floats — this is a deterministic graph).
`method` names how the link was drawn; `"exclusive-command-window"` (the observer
wrapped the command) is the high-confidence baseline. A File-Watcher-only guess
MUST carry a lower `confidence_ppm` and its own `method`. An honest
`"probably the agent"` (confidence < 1000000) beats a deterministic lie.

### 2.7 `ClaimCandidate` — a proposed assertion (not an accepted fact)
```json
{ "claim": "0.1", "id": "<id>", "subject": "<hex64>", "predicate": "<string>",
  "evidence": ["<hex64>", "..."],
  "validation": { "runtime": "cmd@v1 | ski@v1", "check": "<hex64>",
                  "verdict": "pass | fail", "transcript": "<hex64>" },
  "proposed_by": "<string>", "ts": <int> }
```
`subject` is the SHA-256 of a canonical claim-subject blob (what the decision is
*about* — e.g. a `{predicate, execution, effects}` summary). `validation` is the
**separate** check (§4). A `ClaimCandidate` is a *candidate* for a Warrant
subject; it is never itself an accepted fact.

## 3. The bridge to Warrant (MUST)

An **accepted** claim MUST be represented as a Warrant `accept` record, where:

- `subject.hash` = the claim's `subject` blob hash;
- `because` = `[ {kind:"prose", text: predicate}, {kind:"check", runtime, check,
  verdict, transcript} ]` per Warrant §3 — the validation is the check reason;
- `evidence` = the claim's `evidence` artifact hashes;
- `under` = the decision policy in force.

Reject / revise / supersede use Warrant's native `prior` chain
(`propose → reject → accept`). OAIP does **not** re-specify decision semantics —
it produces the subject and the evidence; Warrant owns the decision and its
signature, hash-addressing, and settlement.

## 4. The cardinal rule: execution success ≠ acceptance (MUST)

Three distinct successes, **never** conflated:

- **execution success** — the command ran (`exit_code = 0`);
- **validation success** — the invariant held (the claim's `validation.verdict`
  is `pass`);
- **acceptance** — a signed Warrant `accept` was filed under policy.

A verifier or bridge **MUST refuse** to file an `accept` warrant for a claim
whose `validation.verdict` is not `pass`. A zero exit code earns **execution
success only**; it grants no acceptance. This single rule is what separates OAIP
from a trace log where an agent's JSON is treated as fact because it was written.

## 5. Canonical layer vs projection (MUST)

The **canonical layer** is the content-addressed artifacts plus the Warrant store
(signed, hash-addressed, `warrant why` walkable). A relational index (SQLite,
a search DB, a timeline UI) is a **projection**: it MUST be reconstructable from
the canonical layer, and MUST NOT be the source of truth. Deleting the projection
and rebuilding it from artifacts + warrants MUST yield the same graph.

## 6. Non-goals (v0.1)

Semantic-entity extraction (tree-sitter scope — reserved `entities`, §2.5); an
`Observation` stream of raw observer events; a **Reaction runtime** (the ring's
last arc — when specified it MUST be budget-bounded, ATP-style, so agents cannot
self-excite into unbounded loops); federation / jurisdictions (that is Warrant
Book III territory); and any opinion on whether an intent was satisfied or which
policy has authority.

## 7. Reference implementation

`impl/oaip.py` — five verbs (`intent`, `run`, `claim`, `accept`) plus `log` /
`verify`. Workspace snapshots via git plumbing (throwaway index), effects via
`git diff-tree`, exclusive-window attribution, and the Warrant bridge (a real
signed `accept`). `examples/auth-demo.sh` is a worked end-to-end case, including
the §4 refusal: a command that exits 0 while breaking an invariant is not
accepted. Stdlib only, plus the Warrant reference CLI for the bridge.

---
*OAIP records what happened and on what observed basis. Warrant records the
decision. Σ-GLYPH computes the portable checks. The projection is disposable;
the content-addressed causal graph is the truth.*
