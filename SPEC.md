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

`impl/oaip.py` — four recording verbs (`intent`, `run`, `claim`, `accept`) and
the one-shot `do`, plus `log`, `verify`, `rebuild` (§5), `bind` (the keyring) and
`trust-root` (where the key and keyring live — §8.4). Workspace snapshots via git
plumbing (throwaway index), effects via `git diff-tree`, exclusive-window
attribution, and the Warrant bridge (a real signed `accept`).
`examples/auth-demo.sh` is a worked end-to-end case, including the §4 refusal: a
command that exits 0 while breaking an invariant is not accepted. Stdlib only,
plus the Warrant reference CLI for the bridge.

## 8. Security considerations

This section states what OAIP tries to make unforgeable, by which mechanism, and
**against whom it fails**. It is written by capability, because "is OAIP secure"
has no answer and "can a party who can write the workspace forge an acceptance"
has one. Every mechanism named here is implemented in `impl/oaip.py` and executed
by `tools/check.py`; where nothing stops an attacker, this section says so
instead of describing a control that does not exist.

### 8.1 What is being protected

Exactly one fact: **that a particular claim was accepted, by a particular actor,
under a policy** — the claim→warrant edge of §3/§4. Everything else OAIP records
is an observation, and an observation that is wrong is a bad record, not a forged
decision.

OAIP does **not** protect: the truthfulness of the observed work (a validation
check that tests the wrong thing passes); the availability of the ledger (anyone
who can write the store can delete records, loudly); or the secrecy of anything
(no field is confidential, and the ledger is not encrypted).

Note the asymmetry that follows: every control below is designed so that an
attacker's best outcome is a **refusal**. Refusals are recoverable and visible;
a derived edge that nobody decided is neither.

### 8.2 Attacker capability matrix

| Capability | Can forge an acceptance? | What they CAN do | Mechanism that stops them |
|---|---|---|---|
| **(a) The observed agent** — write access to the workspace, i.e. everything under the repository including `.oaip/`, running as the observer's uid *if unconfined* | **Not by workspace write alone** (default deployment). **Yes** if it also runs unconfined as the observer's uid | Write/delete artifacts and store records; plant a keyring at `.oaip/trust.json`; rewrite `.oaip/store.json`; edit the file a validation check tests **before the check runs**; cause refusals at will | Trust root (key + keyring) outside the workspace (§8.4 profile B) — the planted keyring is never read; in-process Ed25519 verification over the WarrantID OAIP recomputes; keyring binding; the signed `oaip-claim:<id>` link. **Nothing stops the check-target rewrite** — see §8.5(1) |
| **(b) A party with write access to the TRUST ROOT** | **Yes, completely** | Bind their own key to any actor, or read the key and sign directly | Nothing. This is the trust root's definition: whoever holds it decides. Mode bits (0600 key, 0600 keyring, 0700 directory, refused otherwise) exclude *other accounts on the host*, not this party |
| **(c) A party who controls the environment or PATH** | **Yes** | Set `OAIP_TRUST_ROOT`/`XDG_CONFIG_HOME` to a keyring they wrote; replace `git` or `sh` and lie about the snapshot; replace `$WARRANT_CLI` | Nothing for the trust root or the toolchain. `$WARRANT_CLI` alone is closed: signature validity is decided in process, so a hostile CLI can make OAIP **refuse** but not believe. The environment is part of the TCB and OAIP says so rather than pretending otherwise |
| **(d) A party with read-only access to the workspace** | **No** | Read every record, claim, transcript and the projection; correlate what an agent did | Nothing needs to: no OAIP record is secret. The signing key is not in the workspace (profile B) and is 0600 |
| **(e) A remote party with no local access** | **No** | Nothing directly — OAIP opens no sockets and fetches nothing. Reach is indirect: through a ledger someone *imports*, or through the toolchain (Warrant, Python, git) | Address-matching on every artifact and store record; size/count caps (`MAX_STORE_RECORD_BYTES`, `SIG_DECIDE_CAP`, `SIG_NOTE_CAP`) so an imported record cannot exhaust the verifier; keyring binding, so a record signed by a key this ledger does not vouch for produces no edge |

The matrix is executable: `tests/privilege_separation.py` is organised by these
rows, and each row's negative control — the arrangement where the attack **does**
work — is kept runnable in the same file.

### 8.3 The mechanisms, and what each is worth

1. **In-process Ed25519 verification** (`ed25519_verify`, RFC 8032, verify-only).
   The signature that decides is checked by OAIP itself, over the WarrantID OAIP
   recomputed from the record's own bytes. Removes the delegate — no program
   named by `$WARRANT_CLI` can manufacture an acceptance. Warrant is still
   consulted and may still veto.
2. **Keyring binding** (`.../trust.json`, OAIP's own rule). An edge is derived
   only from a signature by the actor the record NAMES, under a key this ledger
   binds to that actor. Warrant SPEC §5 makes binding a report, never a failure,
   so this rule is OAIP's.
3. **Trust root outside the workspace** (§8.4). Makes (2) meaningful against the
   observed agent: the keyring is not a file the observed command can write.
4. **File-mode custody** (0600 key, 0600 keyring, 0700 directory; refused
   otherwise, with the `chmod` in the message). Excludes other accounts on a
   shared host and the accidental widening (umask, tarball restore, mode-less
   filesystem). Says nothing about a same-uid process.
5. **The signed claim link** (`subject.note` = `oaip-claim:<id>`, inside the
   signed body). Which claim was accepted is read, not guessed; the subject blob
   alone cannot distinguish two claims with opposite verdicts over one execution.
6. **Untrusted-projection marker**. A rebuild that refuses leaves the bytes and
   withdraws the authority: `log` and `verify` refuse the projection until a
   rebuild succeeds. Without it a projection built once from a poisoned store
   kept asserting a forged acceptance forever.
7. **Size and count caps.** `sigs` lies outside the hashed body, so a record can
   be padded or flooded without breaking its address; only entries that could
   decide are verified, at most `SIG_DECIDE_CAP` per record, and a record over
   `MAX_STORE_RECORD_BYTES` is refused before parsing.
8. **Snapshot exclusion of the ledger and the trust root.** The observer must not
   write its own key into the object database of the repository it observes.

### 8.4 Deployment profiles

| Profile | Where the key lives | Stops | Status |
|---|---|---|---|
| **A — in-workspace trust root** | `.oaip/dev.key`, `.oaip/trust.json` | Only a party with no workspace access | Supported for existing ledgers; warns on every accept/bind/rebuild/verify; `oaip trust-root --migrate` leaves it |
| **B — relocated trust root** (default) | `$XDG_CONFIG_HOME/oaip/roots/<ledger>`, or `--trust-root` / `$OAIP_TRUST_ROOT` | An agent whose write access is confined to the workspace: a container mount, a CI checkout, a sandboxed tool. **Not** an unconfined same-uid process | **Implemented** |
| **C — separate uid** | A trust root owned by an `oaip-observer` user, mode 0700, with `oaip accept` run under it (sudo rule, setuid wrapper, or a queue directory the agent may write and the observer drains) | An agent running as its own uid, unconfined | **Documented, not implemented.** OAIP has no privilege-dropping code and does not attempt any |
| **D — observer daemon / signing service** | A long-running process holding the key, exposing "sign this WarrantID" over a socket, with its own policy on what it will sign | The same as C, plus it can apply a policy at signing time (rate limits, a human confirmation) | **Documented, not implemented.** Note it does not stop a same-uid agent from *asking* — it moves the question to what the daemon agrees to sign |
| **E — verify-only** | No key in the observed environment at all: the agent's environment runs `oaip run`/`claim`; `accept` runs elsewhere, on a store copied out | Everything an agent can do locally, since there is nothing local to forge with | **Achievable today** with profile B plus not installing a key: `oaip verify` and `oaip rebuild` work with an empty keyring and simply derive no edges |

Profiles C and D need an operating-system boundary OAIP cannot create from
inside a single stdlib process; they are named here so a deployment can be
described honestly rather than implied.

### 8.5 What remains open

1. **The validation check runs after the agent's command, against post-agent
   workspace state, through the shell.** An agent that rewrites the test it will
   be judged by passes honestly. This is the largest remaining hole in the §4
   gate and no mechanism here addresses it: it needs the check to run from a
   state the agent did not produce (a pinned revision, a separate checkout, a
   container), which is a deployment decision, not a format one.
2. **`claim@v1` artifacts are unsigned.** Anyone who can write
   `.oaip/artifacts` can add a claim record; only the acceptance side is pinned
   to a signed note.
3. **No key rotation, no revocation, no expiry.** A bound key is bound until the
   keyring is edited by hand.
4. **Availability is not protected.** A party with store write access can delete
   records or force refusals (including by rewriting the trust-root pointer);
   every such loss is reported loudly and non-zero, which is the whole of the
   defence.
5. **The environment is trusted.** `git`, `sh`, the Python interpreter and
   `$WARRANT_CLI`'s *availability* are inside the TCB; only `$WARRANT_CLI`'s
   *verdict* has been removed from it.
6. **`--actor` is unauthenticated free text.** The keyring binds a key to an
   actor id; nothing binds an actor id to a person.

---
*OAIP records what happened and on what observed basis. Warrant records the
decision. Σ-GLYPH computes the portable checks. The projection is disposable;
the content-addressed causal graph is the truth.*
