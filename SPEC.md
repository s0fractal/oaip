# OAIP — Observed Action & Intent Protocol — Specification v0.1

**Status:** DRAFT. Key words MUST / MUST NOT / SHOULD / SHOULD NOT / MAY per
RFC 2119 as updated by RFC 8174 ([R1], [R2]), and only when in ALL CAPS.
**Purpose.** Turn the ephemeral behavior of humans, agents, and tools into a
**content-addressed causal graph** — from which claims, decisions, and reactions
can be built *honestly*. OAIP records **what was observed**; it does **not** decide
whether an action was correct, whether an intent was met, or which policy has
authority. Those are the decision layer (Warrant) and the policy layer.

**Normative dependencies.**
- **Warrant SPEC v0.4** ([R3]), package **≥ 0.6.0** — the decision layer. OAIP
  **reuses Warrant §4 canonicalization verbatim** and bridges accepted claims
  into Warrant records (§3). Not reimplemented here.
  **The lower bound is normative, not advisory.** Warrant v0.4 is a breaking
  change to §5: the signed message is `"warrant-sig-v1:" || WarrantID_raw`
  (47 bytes) and **not** the bare 32-byte WarrantID. OAIP verifies that
  signature itself, in process (§8.3.1), so an implementation MUST use the v0.4
  construction and MUST NOT accept the pre-v1 one — the two are disjoint, and a
  verifier that took both would have no domain separation at all. See §8.6.
- **RFC 8785 (JCS)** [R4], **RFC 7493 (I-JSON)** [R5], **RFC 8259 (JSON)** [R6] —
  through Warrant §4, and directly for §1.
- **Σ-GLYPH Book I** [R7] (optional) — for `ski@v1` portable, budget-bounded
  checks. Reserved and **rejected** in v0.1 claim bodies (§7.3); a forward path,
  not a v0.1 requirement.

**Design rule.** OAIP adds exactly one thing to the existing stack: a clean,
content-addressed *input* to the decision layer. It MUST NOT grow into the
decision layer, the policy engine, or a reaction runtime — those are separate
profiles above Warrant.

**Relationship to prior art** is normative context, not a footnote: OAIP overlaps
W3C PROV [R8][R9], IETF SCITT [R10], and in-toto/SLSA [R11][R12], and §9 states
what it takes from each and what it adds. An implementer should read §9 before
§2.

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
are lowercase hex SHA-256 (`hex64`, `^[0-9a-f]{64}$`); git object ids are
lowercase hex SHA-1 (`hex40`, `^[0-9a-f]{40}$`) where a git tree/blob is
referenced. All timestamps are Unix seconds in int64.

A leading byte order mark makes a document **not** an OAIP record, even though
RFC 8259 §8.1 permits a receiver to ignore one: "MAY ignore" is unaffordable in a
content-addressed format, because the same record would then have two addresses.

Two identity kinds:

- **Content-addressed** — identity is `SHA-256` of the canonical bytes (records)
  or the raw bytes (blobs): `Artifact`, `State`, the environment/toolchain probes,
  and a claim's `ClaimSubject`. Cited by hash; immutable by construction.
- **Event records** — identity is a monotone, time-sortable `id` (e.g. UUIDv7 /
  KSUID; the reference impl uses `<ms>-<rand>`), with integrity from the content
  hashes they cite: `Intent`, `Execution`, `Effect`, `Attribution`,
  `ClaimCandidate`.

### 1.1 Record identification and closed schemas (MUST)

Every record carries exactly one **type tag**: a member whose name is a
registered record type (§7.1) and whose value is that record's **format version**
string. A document in which **two or more** registered type tags appear is
**invalid** — it is not "one of them with an extra field", because two readers
would disagree about which record it is.

Each `(type, version)` pair defines a **closed schema**. A member the schema does
not define makes the record **invalid** (MUST); a reader MUST NOT
accept-and-ignore it. Two reasons, and the first is the load-bearing one: a
member a lenient reader ignores and a strict reader reads is a member about which
two conforming implementations derive **different graphs from identical bytes**;
and an extension that changes meaning must change the version so that a reader
can refuse it (§6). Extension is by new version, never by new member.

A member declared OPTIONAL MAY be absent. A member declared MUST is required; its
absence makes the record invalid. Where a field's type is given as `X | null`,
`null` is a **value with meaning** and is never interchangeable with absence.

No member name used by any schema in §2 is also a registered type tag, and §7.1
requires that of every future registration — that is what makes the "exactly one
type tag" rule decidable by inspection.

**Deciding what a document is (MUST).** A reader classifies a JSON document in
this order, and the order is normative because otherwise two readers disagree
about which refusal to issue:

1. If it carries a member named `oaip_record` (or `oaip_subject`) whose value
   matches `^[a-z_]+@v[0-9]+$`, it is a **legacy** record (§6.4). This test comes
   **first**, and the order is normative: a pre-0.1 execution record carries a
   member named `intent` and a pre-0.1 claim one named `execution`, both of
   which are v0.1 type tags. Testing the tags first classifies every legacy
   execution as "an `execution` record whose version is an event id" and reports
   an intact ledger as corrupt. (That collision is the same one that forced the
   renames to `intent_id`/`execution_id` in §2.4/§2.5, met from the other side.)
2. Otherwise, if one or more of its member **names** is a registered type tag
   (§7.1), it is a record of that type. Two or more such names ⇒ `invalid`
   (§6.2). A type tag whose **value** is not a version string
   (`^[0-9]+\.[0-9]+$`) ⇒ `invalid`; the type is known, its version is
   unreadable, and guessing one is exactly the move this section exists to
   forbid.
3. Otherwise, if it carries a **type-tag-shaped** member — a name matching
   `^[a-z][a-z0-9_]*$` whose value is a version string — it is `unknown-type`.
4. Otherwise it is **not an OAIP record**, and a reader MUST NOT report it as a
   malformed one. A ledger holds blobs that are not records (a transcript, a
   captured stdout); calling those corrupt would make every ledger corrupt.

## 2. Record types (v0.1)

Field tables give the member name, its JSON type, whether it is required, and its
rule. Any value outside the stated rule makes the record invalid.

### 2.1 `Artifact` — a citable blob
Any blob that may later be evidence: stdout, stderr, a diff, a test report,
compiler diagnostics, a prompt, a model response, a manifest. Identity =
`SHA-256(bytes)` of the blob it describes — **not** of the Artifact record.

```json
{ "artifact": "0.1", "hash": "<hex64>", "kind": "<string>", "size": <uint> }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `artifact` | string | MUST | `"0.1"` |
| `hash` | string | MUST | `hex64` — SHA-256 of the blob's raw bytes |
| `kind` | string | MUST | a label from the open set §7.4 |
| `size` | integer | MUST | ≥ 0, the blob's length in bytes |

The ledger stores the reference, not necessarily the bytes. An implementation MAY
store `Artifact` records; it MAY instead hold the same three facts in its
projection (§5) and re-derive them, which is what the reference implementation
does. `kind` is the one **open** vocabulary in this specification (§7.4): an
artifact is any blob, and a closed list of blob kinds would be a closed list of
things that can be evidence.

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

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `state` | string | MUST | `"0.1"` |
| `repo_commit` | string \| null | MUST | `hex40`, or `null` where the repository has no commit |
| `worktree_tree` | string | MUST | `hex40` — a git **tree** object |
| `env_fingerprint` | string | MUST | `hex64` — §2.2.1 |
| `toolchain_fingerprint` | string | MUST | `hex64` — §2.2.2 |

`worktree_tree` captures tracked + staged + untracked files, built in a
**throwaway index** so no commit is added to history.
**`StateID = SHA-256(canon(State))`.** A verifier MAY re-materialize the exact
file set from `worktree_tree`. Using a normal `HEAD`/commit as a `State` is a
MUST NOT.

#### 2.2.1 `EnvironmentProbe` and the `env_fingerprint` (MUST)

`env_fingerprint` is `SHA-256(canon(EnvironmentProbe))`, where the probe record
is:

```json
{ "environment_probe": "0.1",
  "profile": "posix-base@v1",
  "os": "<string>",
  "arch": "<string>",
  "vars": { "LANG": "<string | null>", "LC_ALL": "<string | null>",
            "PATH": "<string | null>", "SOURCE_DATE_EPOCH": "<string | null>",
            "TZ": "<string | null>" } }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `environment_probe` | string | MUST | `"0.1"` |
| `profile` | string | MUST | a registered environment profile (§7.5); v0.1 defines exactly `posix-base@v1` |
| `os` | string | MUST | stdout of `uname -s`, §2.2.3 capture rule |
| `arch` | string | MUST | stdout of `uname -m`, §2.2.3 capture rule |
| `vars` | object | MUST | **exactly** the profile's variable names as members, no more and no fewer |

**Profile `posix-base@v1`** names exactly five environment variables, and this
list is the whole of it:

| Variable | Why it is in the profile |
| --- | --- |
| `PATH` | decides which binary a command name resolves to |
| `LANG` | decides message text, and therefore tool output bytes |
| `LC_ALL` | overrides `LANG`; also decides collation, and therefore sort order |
| `TZ` | decides timestamps rendered by tools |
| `SOURCE_DATE_EPOCH` | the reproducible-builds convention; when set it changes outputs |

Rules:
- Every one of the five names MUST appear as a member of `vars`. **Absence is
  encoded as `null`, never by omitting the member**, and `null` (unset) is
  distinct from `""` (set to the empty string). A probe that omits a member, or
  carries a name outside the profile, is invalid.
- Values are the variable's exact bytes decoded as UTF-8. If a value is not
  valid UTF-8, an implementation MUST refuse to compute the fingerprint and MUST
  report why; it MUST NOT substitute a replacement character, because two
  implementations would substitute differently and produce two fingerprints for
  one environment.
- No normalization: `PATH` is not de-duplicated, reordered, or made absolute.

**What this fingerprint is not.** An environment variable outside those five can
change what a command does, and it will not change this fingerprint. The
fingerprint is a cheap **discriminator** — "the environment was, or was not, the
one I recorded" — and it is not evidence of environmental equivalence. Saying so
here is deliberate: a fingerprint whose scope is undeclared is read as a proof it
cannot give.

#### 2.2.2 `ToolchainProbe` and the `toolchain_fingerprint` (MUST)

`toolchain_fingerprint` is `SHA-256(canon(ToolchainProbe))`, where:

```json
{ "toolchain_probe": "0.1",
  "profile": "posix-base@v1",
  "tools": [ { "name": "git", "argv": ["git", "--version"],
               "status": "ok", "stdout_sha256": "<hex64>" } ] }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `toolchain_probe` | string | MUST | `"0.1"` |
| `profile` | string | MUST | a registered toolchain profile (§7.5) |
| `tools` | array | MUST | **exactly** the profile's probes, in the profile's order |

Each element of `tools` is a closed object:

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `name` | string | MUST | the profile's name for this probe |
| `argv` | array of string | MUST | the profile's argv for this probe, element for element |
| `status` | string | MUST | `ok` \| `absent` \| `error` |
| `stdout_sha256` | string \| null | MUST | `hex64` when `status` is `ok` or `error`; `null` when `absent` |

- `ok` — the probe ran and exited 0.
- `absent` — the executable could not be found (`ENOENT`, or the equivalent).
- `error` — the probe ran and exited non-zero, or could not be executed for any
  other reason.

**Profile `posix-base@v1`** names exactly one probe: `{"name": "git", "argv":
["git", "--version"]}`. One, because git is the only external tool OAIP's own
State construction depends on, and a profile that listed tools an implementation
does not use would make two honest implementations of this specification produce
different fingerprints for the same host — a Python implementation hashing its
interpreter version and a Go one hashing its compiler would never agree. A richer
profile is a **new profile tag** (§7.5), and the tag is inside the hashed record
precisely so a reader can see which set of probes produced a fingerprint before
deciding whether it can reproduce it.

`stdout_sha256` is the SHA-256 of the process's **standard output bytes**, hashed
rather than embedded: process output is arbitrary bytes and may not be valid
UTF-8, which §1's domain forbids in a string. Standard error is excluded — it
carries locale- and warning-dependent noise that is not the tool's identity.

#### 2.2.3 Capturing `os` and `arch`

`os` and `arch` are the standard output of `uname -s` and `uname -m`, with
trailing U+0009, U+000A, U+000D and U+0020 removed and nothing else changed, then
decoded as UTF-8 (a decode failure is refused, per §2.2.1). They are specified as
**probes, not as a host API**, because host APIs disagree: `uname -s` reports
`Darwin` where one language runtime reports `darwin`, and a fingerprint that
depends on the implementation language is not a fingerprint of the environment.

#### 2.2.4 What a verifier does with a fingerprint (MUST)

A fingerprint has exactly three verification outcomes, and a conforming verifier
MUST distinguish all three in its report:

| Outcome | When |
| --- | --- |
| `matched` | the verifier re-ran the profile's probes and got the same hex64 |
| `mismatched` | the verifier re-ran the profile's probes and got a different hex64 |
| `unreproducible` | the verifier did not, or could not, re-run the probes |

The three are defined by **what the verifier did**, and deliberately not by
where it did it. An earlier draft of this table said `matched` required
re-running "on the host under audit", which is not decidable: no record carries
a host identity, so no implementation can tell the audited host from any other,
and a rule an implementation cannot evaluate is a rule that will be evaluated
wrongly. The cost is stated rather than hidden: **`mismatched` does not
distinguish "the same host, changed since" from "a different host entirely",
and a verifier MUST NOT report it as either.** A consumer that needs that
distinction must establish host identity by some means outside this
specification.

- A verifier that cannot re-run the probes (it is on another host, or the probe
  record is unavailable) MUST report `unreproducible`. It MUST NOT report
  `matched`, MUST NOT report `mismatched`, and MUST NOT treat the State as
  verified. **`unreproducible` MUST NOT be collapsed into `matched`** by a
  report, a summary, an exit status, or a machine-readable field — that collapse
  is how "nothing was checked" becomes "everything checked out".
- A verifier MUST NOT treat `mismatched` as evidence of tampering on its own.
  Environments change with time; a State asserts what was observed then, not a
  promise about now.
- Whether `mismatched` or `unreproducible` blocks anything is a **policy**
  question, decided above OAIP (§0). A policy MAY require `matched`. OAIP
  specifies the outcome, never the consequence — deciding is the layer above.
- A malformed fingerprint (not `hex64`) is not an outcome of this table: it makes
  the State record invalid (§1.1), and that **is** fail-closed.

An implementation that emits States SHOULD store the `EnvironmentProbe` and
`ToolchainProbe` records it hashed, as artifacts. A fingerprint whose probe
record no one can obtain is opaque by construction, and the only outcome
available to every reader is `unreproducible`.

### 2.3 `Intent` — a declared goal (not proof it was met)
```json
{ "intent": "0.1", "id": "<id>", "actor": "<string>", "parent": "<id | null>",
  "objective": "<string>", "constraints": ["<string>", "..."],
  "acceptance_refs": ["<hex64>", "..."], "ts": <int> }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `intent` | string | MUST | `"0.1"` |
| `id` | string | MUST | non-empty event id (§1) |
| `actor` | string | MUST | non-empty; who declared the intent. **Unauthenticated** — see §8 |
| `parent` | string \| null | MUST | a parent Intent's `id`, or `null` |
| `objective` | string | MUST | non-empty |
| `constraints` | array of string | MUST | possibly empty; each element non-empty |
| `acceptance_refs` | array of string | MUST | possibly empty; each element `hex64`, sorted ascending, no duplicates |
| `ts` | integer | MUST | Unix seconds |

`acceptance_refs` are hashes of artifacts that would *evidence* satisfaction
(a test, a spec clause). An Intent asserts a target; it never asserts success.

### 2.4 `Execution` — a controlled action container
```json
{ "execution": "0.1", "id": "<id>", "intent_id": "<id | null>",
  "executor": { "actor": "<string>", "runtime": "<string>" },
  "input_state": "<StateID>", "output_state": "<StateID>",
  "invocation": ["<string>", "..."], "environment": "<hex64>",
  "status": "exited | failed | killed", "exit_code": <int | null>,
  "output": "<hex64 | null>", "ts": <int> }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `execution` | string | MUST | `"0.1"` |
| `id` | string | MUST | non-empty event id |
| `intent_id` | string \| null | MUST | the Intent this was run under, or `null` |
| `executor` | object | MUST | closed: exactly `actor` (non-empty string) and `runtime` (a registered executor runtime, §7.2) |
| `input_state` | string | MUST | `hex64` StateID |
| `output_state` | string | MUST | `hex64` StateID |
| `invocation` | array of string | MUST | non-empty; interpreted by `executor.runtime` (§7.2) |
| `environment` | string | MUST | `hex64`; MUST equal the `env_fingerprint` of `input_state`'s State |
| `status` | string | MUST | `exited` \| `failed` \| `killed` |
| `exit_code` | integer \| null | MUST | integer 0–255 when `status` is `exited`; **`null`** when `failed` or `killed` |
| `output` | string \| null | MUST | `hex64` — the Artifact holding what the runtime captured, or `null` where nothing was captured |
| `ts` | integer | MUST | Unix seconds |

`status` values, exhaustively:
- **`exited`** — the process ran to completion and returned a code.
- **`killed`** — the process was terminated by a signal (or the platform
  equivalent) before returning a code.
- **`failed`** — the invocation never became a running process: the executable
  was absent, not executable, or the runtime refused to start it.

`status`/`exit_code` describe **execution**, not acceptance (§4).

`output` closes a gap this document had: §2.1 offers `Artifact` for "stdout,
stderr, a diff, a test report", and nothing in §2.4 could cite one, so an
execution's own captured output was reachable only through whatever claim
happened to name it later. What the member points at is decided by the runtime
(§7.2), and for both registered runtimes it is a **merged** stdout/stderr stream:
the interleaving is preserved and the split is not. That is a real loss, and it
is written here rather than left for a reader to discover — a second
implementation must merge the same way or the hashes will not agree.

**`invocation` is an array, not a string** (a change from this document's first
draft, made because the string form is not faithful): an argv vector cannot be
recovered from a space-joined string, so two different executions —
`["rm", "a b"]` and `["rm", "a", "b"]` — produce identical records. A provenance
record that cannot reconstruct the command it observed is not provenance, and the
reference implementation's `" ".join(argv)` was the same defect on the other side
of the wire. `executor.runtime` says how the array is interpreted (§7.2):
`exec@v1` executes it directly with no shell; `shell@v1` is a one-element array
holding a script for a POSIX shell.

### 2.5 `Effect` — one state mutation
```json
{ "effect": "0.1", "id": "<id>", "execution_id": "<id>",
  "kind": "file.create | file.modify | file.delete | file.typechange",
  "target": "<string>", "before": "<hex40 | null>", "after": "<hex40 | null>",
  "entities": [] }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `effect` | string | MUST | `"0.1"` |
| `id` | string | MUST | non-empty event id |
| `execution_id` | string | MUST | the Execution in whose window this mutation was observed |
| `kind` | string | MUST | a registered effect kind (§7.4) |
| `target` | string | MUST | non-empty; for `file.*`, a repository-root-relative POSIX path |
| `before` | string \| null | MUST | `hex40` git blob OID, or `null` |
| `after` | string \| null | MUST | `hex40` git blob OID, or `null` |
| `entities` | array | OPTIONAL | **reserved**: in `"0.1"` it MUST be absent or `[]` |

`before`/`after` are content hashes (git blob OIDs) — deduplicated, exact. Per
kind (MUST): `file.create` has `before = null` and `after` non-null;
`file.delete` has `after = null` and `before` non-null; `file.modify` and
`file.typechange` have both non-null and `before ≠ after`.

`entities` attaches semantic scope (function/class) so a diff maps to logical
units, not just files — a v0.2 refinement (a string scope is insufficient: names
collide, move, and one diff touches many scopes). In v0.1 it is reserved: a
non-empty `entities` makes the record invalid, so a v0.1 reader can never be
handed semantics it will silently drop.

An `Effect` says a mutation was observed in an Execution's window. It does not
say the Execution *caused* it — that is an `Attribution`, and it is a separate
record because it is a separate, uncertain claim.

### 2.6 `Attribution` — causality, first-class and uncertain
```json
{ "attribution": "0.1", "id": "<id>", "effect_id": "<id>", "cause": "<id>",
  "method": "<string>", "confidence_ppm": <uint 0..1000000>,
  "support": ["<hex64>", "..."] }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `attribution` | string | MUST | `"0.1"` |
| `id` | string | MUST | non-empty event id |
| `effect_id` | string | MUST | the `id` of the Effect this explains |
| `cause` | string | MUST | the `id` of the Execution asserted to have caused it |
| `method` | string | MUST | a registered attribution method (§7.6) |
| `confidence_ppm` | integer | MUST | 0 ≤ n ≤ 1000000, plus any ceiling the method imposes |
| `support` | array of string | MUST | possibly empty; each `hex64`, sorted ascending, no duplicates |

Causality is **not always certain** — the honest primitive. `confidence_ppm` is
parts-per-million as an **integer** (no floats — this is a deterministic graph).
`method` names how the link was drawn; `exclusive-command-window` (the observer
wrapped the command) is the high-confidence baseline, and §7.6 caps it *below*
certainty, because an observer that started one process cannot exclude a writer
it did not start. A weaker method MUST carry a lower `confidence_ppm` *and its
own registered `method`*. An honest "probably the agent" beats a deterministic
lie.

### 2.7 `ClaimCandidate` — a proposed assertion (not an accepted fact)
```json
{ "claim": "0.1", "id": "<id>", "subject": "<hex64>", "predicate": "<string>",
  "evidence": ["<hex64>", "..."],
  "validation": { "runtime": "oaip-host-shell@v1", "check": "<hex64>",
                  "verdict": "pass | fail", "transcript": "<hex64>" },
  "proposed_by": "<string>", "ts": <int> }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `claim` | string | MUST | `"0.1"` |
| `id` | string | MUST | non-empty event id |
| `subject` | string | MUST | `hex64` — SHA-256 of a canonical `ClaimSubject` (§2.8) |
| `predicate` | string | MUST | non-empty |
| `evidence` | array of string | MUST | possibly empty; each `hex64`, sorted ascending, no duplicates |
| `validation` | object | MUST | closed: exactly `runtime`, `check`, `verdict`, `transcript` |
| `validation.runtime` | string | MUST | a validation runtime admitted in `claim` `"0.1"` (§7.3) |
| `validation.check` | string | MUST | `hex64` — the **hash of the check blob**, not its text |
| `validation.verdict` | string | MUST | `pass` \| `fail` |
| `validation.transcript` | string | MUST | `hex64` — the check's captured output |
| `proposed_by` | string | MUST | non-empty; **unauthenticated** (§8) |
| `ts` | integer | MUST | Unix seconds |

`validation` is the **separate** check (§4). A `ClaimCandidate` is a *candidate*
for a Warrant subject; it is never itself an accepted fact. `check` is a hash
because the check is evidence: a reader must be able to fetch and re-run exactly
the bytes that were run, and a command echoed into a record is a *description* of
a check rather than the check.

**`validation.runtime` MUST name the profile the check actually ran under**, and
a filer MUST NOT record a runtime whose registered definition its execution did
not satisfy. This is stated as a MUST because it was violated: until 2026-07-31
this implementation ran the check through the host shell and recorded `cmd@v1`,
a tag Warrant SPEC §3 defines as execution in an isolated container, and passed
it into a signed decision (§3). A record that names an execution profile which
did not happen is a false record even when every hash in it is correct. §7.3
registers `oaip-host-shell@v1` for what actually happens.

**The check's own effects MUST be observed (MUST).** The Execution's
`output_state` (§2.4) is snapshotted when the observed command returns, which is
*before* the check runs — so anything the check writes lands after the last
observation, and a `ClaimSubject` (§2.8) built from that Execution lists effects
that were already stale when the decision was signed. A filer therefore MUST
snapshot the workspace immediately before and immediately after the check, and
where the two differ it MUST do one of exactly two things:

- **refuse** to file the claim, or
- file it and **cite the check's own effects as evidence**: a `check-effects`
  artifact (§7.4) whose bytes list them, with its hash in the claim's `evidence`.

Filing without either is what this rule forbids. A reader of a claim over a
mutating check MUST NOT be able to reach "the workspace was as the subject says"
from a record that omits the mutation. The window is the check's own — before to
after — and not the Execution's after-state, because the workspace may have
changed between the two commands for reasons the check did not cause, and
attributing those to the check would answer one false attribution with another.

This is **observation, not confinement**: the mutation has already happened when
it is seen, and §8.5 SA-13 says what that does and does not buy. (Found by
external audit — Codex, 2026-07-31 — with a working reproduction: a check of
`touch check-escaped-container` created that file in the observed workspace
while the signed decision recorded `effects=0`.)

### 2.8 `ClaimSubject` — what the decision is *about*

The claim's `subject` is the SHA-256 of the canonical bytes of:

```json
{ "claim_subject": "0.1", "predicate": "<string>", "execution_id": "<id>",
  "effects": [ { "target": "<string>", "kind": "<string>",
                 "after": "<hex40 | null>" } ] }
```

| Member | Type | Req | Rule |
| --- | --- | --- | --- |
| `claim_subject` | string | MUST | `"0.1"` |
| `predicate` | string | MUST | non-empty; MUST equal the claim's `predicate` |
| `execution_id` | string | MUST | the Execution the assertion is about |
| `effects` | array | MUST | possibly empty; elements are closed objects of exactly `target`, `kind`, `after`, each per §2.5; **sorted ascending by `target`, then `kind`** by Unicode code point, with no duplicate `(target, kind)` pair |

The ordering rule is normative because array order is significant in JCS: without
it, two implementations observing the same execution would produce two subject
hashes, and §3 addresses a decision *by* that hash.

**The subject deliberately excludes the validation.** It is what the decision is
about — the assertion — not how the assertion was checked. A consequence follows,
and it is a MUST rather than a caution: two claims over one execution with the
same predicate and opposite verdicts have **identical** subjects, so a subject
hash alone can never identify *which* claim was accepted. §3 therefore requires
the accepting record to name the claim explicitly.

## 3. The bridge to Warrant (MUST)

An **accepted** claim MUST be represented as a Warrant `accept` record, where:

- `subject.hash` = the claim's `subject` blob hash;
- `subject.note` = `"oaip-claim:"` followed by the accepted `ClaimCandidate`'s
  `id` (**MUST**, see §2.8: the subject hash cannot identify the claim, so an
  accept that omits this names no claim at all, and a reader MUST NOT guess one
  from the subject). Readers MUST match the prefix **case-insensitively**, so
  that its spelling cannot select a weaker code path;
- `because` begins with `{kind:"prose", text: predicate}`. How the **validation**
  enters depends on the claim's `validation.runtime`, and the rule is a MUST
  because getting it wrong puts a false statement inside a signature:
  - if that runtime is registered in **Warrant's** reason-runtime registry
    (Warrant SPEC §13.1) *and* the filer actually provided that runtime's
    profile, the validation is filed as `{kind:"check", runtime, check, verdict,
    transcript}` with all four members passed through unchanged;
  - **otherwise the filer MUST NOT substitute a Warrant runtime tag.** OAIP's
    own runtime registry (§7.3) is not Warrant's, an unregistered `runtime`
    makes the Warrant record invalid by Warrant §3's MUST, and a *registered*
    one whose profile did not happen is the defect this rule exists to stop. The
    validation is instead filed as a **prose** reason naming the runtime and the
    verdict, and `validation.check` and `validation.transcript` MUST be added to
    the accept's `evidence` so those bytes still resolve in the store and remain
    citable by hash;
- `evidence` = the claim's `evidence` artifact hashes, plus the check blob and
  transcript in the second case above;
- `under` = the decision policy in force.

**The reference implementation is always in the second case**, and will be until
either OAIP grows a validation runtime that genuinely satisfies a Warrant tag or
`oaip-host-shell@v1` is registered in Warrant §13.1 — a pull request against the
Warrant repository, since that registry has no operator (Warrant SPEC §13). What
the second case costs, stated rather than implied: the warrant carries no
machine-readable `because[].check`, so it contributes no check outcome
fingerprint to Warrant's §7(b) novelty test and a tool that looks for a check
reason finds none. The trade is deliberate — a decision that cites its check as
evidence and says in words how it ran is weaker than one whose check reason is
machine-readable, and stronger than one whose check reason is untrue.

Reject / revise / supersede use Warrant's native `prior` chain
(`propose → reject → accept`). OAIP does **not** re-specify decision semantics —
it produces the subject and the evidence; Warrant owns the decision and its
signature, hash-addressing, and settlement.

**The signature on that record is Warrant's to define and OAIP's to check.** An
acceptance edge (§5) MUST NOT be derived unless the signature by the actor the
record names verifies under Warrant SPEC §5's current construction —
`"warrant-sig-v1:" || WarrantID_raw` as of v0.4 — checked by the implementation
itself and not delegated (§8.3.1), against a WarrantID the implementation
recomputed from the record's own bytes. A signature valid only under a superseded
construction is governed by §8.6.

## 4. The cardinal rule: execution success ≠ acceptance (MUST)

Three distinct successes, **never** conflated:

- **execution success** — the command ran (`status = "exited"`, `exit_code = 0`);
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

A projection MAY name its columns as it likes, but where a column holds a record
field it SHOULD carry that field's name: a projection whose column names
contradict the records it projects is a second, unversioned vocabulary, and it is
how a converter comes to follow the implementation against the specification.

## 6. Versioning, unknown input, and migration (MUST)

### 6.1 The declared version decides

A record's format version is the value of its type tag (§1.1). A reader MUST
validate a record against the rules of **its declared version**, and MUST NOT
apply another version's rules to it. A reader MUST NOT pattern-match a version
prefix: `"0.2"` is not "a kind of 0.1".

### 6.2 What a v0.1 reader does with what it does not understand

| Input | Outcome | Reader behaviour (MUST) |
| --- | --- | --- |
| known type, known version, schema-valid | `valid` | interpret it |
| known type, known version, unknown member / wrong type / out-of-range value | `invalid` | refuse the record; report it; interpret no part of it |
| known type, **unknown version** (`{"intent": "0.2"}`) | `unsupported-version` | do not interpret it; do not delete or rewrite it; report it as its own outcome |
| **unknown type tag** (§1.1 step 3) | `unknown-type` | as above |
| two or more type tags | `invalid` | refuse (§1.1) |
| a type tag whose value is not a version string | `invalid` | refuse |
| `oaip_record`-tagged (§1.1 step 2) | `legacy` | §6.4: legacy-read mode, or `unknown-type` |
| no type tag at all (§1.1 step 4) | *not a record* | ignore it; it is a blob, not a malformed record |
| not canonical I-JSON per §1 | `invalid` | refuse |

`unsupported-version` and `unknown-type` are **distinct from both `valid` and
`invalid`**, and a reader MUST NOT collapse them into either. Collapsing into
`valid` reads a record it does not understand; collapsing into `invalid` calls a
future record corrupt, which makes a forward-compatible writer indistinguishable
from an attacker.

**A citation to an unreadable record fails closed (MUST).** Where a record the
reader *does* understand cites one it does not — an Execution at an unsupported
version cited by a claim's subject, say — the reader MUST NOT proceed as though
the citation were absent or satisfied. The derivation that needed it MUST fail,
and the report MUST name the unreadable record and why it was unreadable.

A ledger MAY hold records of several versions at once; a reader MUST NOT refuse a
whole store because one record in it is `unsupported-version`.

### 6.3 Adding a version

A new format version MUST NOT change the meaning of any record valid under an
earlier version, and MUST NOT make such a record invalid. A new member, a new
enum value, a registry entry that widens an existing version's validity surface,
and any change to an existing member's meaning each require a **new version** of
that record type (§7). Versions are per record type: `Intent` may reach `"0.2"`
while `Effect` is still `"0.1"`.

### 6.4 Records written before v0.1 was pinned (migration, MUST)

Before this section existed, the reference implementation wrote records tagged
`{"oaip_record": "<type>@v1", ...}` with a different member set: `description`
for `objective`; `command`, `before_tree`, `after_tree`, `env_fp` for
`invocation`, `input_state`, `output_state`, `environment`; `check`,
`check_exit`, `supported` for `validation`; and no `State`, `Effect`,
`Attribution` or probe records at all — effects and attributions were nested
inside the execution record. Stores in that shape exist.

The pre-0.1 claim subject blob carried its own tag, `oaip_subject`, and the
same rules apply to it.

- A v0.1 reader MAY implement a **legacy-read mode** that accepts
  `oaip_record`- and `oaip_subject`-tagged records. Where it does, it MUST: interpret them under the
  legacy rules and never the v0.1 rules; mark everything derived from them as
  legacy-format in its projection and its reports, so that no reader mistakes a
  git tree `hex40` in an `input_state` position for a StateID; and **write only
  v0.1 records** thereafter. Migration is read-side.
- A reader that does **not** implement legacy-read mode MUST treat an
  `oaip_record`-tagged document as `unknown-type` (§6.2) — reported, not silently
  ignored, and not rewritten.
- No implementation may rewrite a legacy record into v0.1 shape in place. The
  record is addressed by the hash of its own bytes; rewriting produces a
  different record at a different address, and the old address is cited by the
  Warrant store.
- Legacy records carry no `State`, so a legacy Execution's state references are
  git tree object ids, not StateIDs, and it carries no toolchain fingerprint at
  all. A verifier MUST NOT report a legacy execution's fingerprints as `matched`
  (§2.2.4); the outcome is `unreproducible`.

## 7. Registries

Several of this format's extension points are closed sets: a new value requires
editing this document. This section says how each set grows and what a
registration must contain. **There is no registry operator.** Until one exists (a
neutral IANA-style registry is out of scope for a DRAFT spec by one maintainer),
a registration is a pull request against this repository containing the fields
below, and the registry is the tables in this section. Saying that plainly is the
point: an unstaffed registry described as if it were staffed is worse than none.

**Rules common to every registry here:**
- Where a value carries a version it is spelled `name@vN`. **A tag is
  immutable**: a semantic change is a NEW tag, never a redefinition.
- An **unregistered** value in a closed registered field makes the record
  **invalid** (MUST). Unknown-means-invalid is what stops a forward-dated value
  from meaning "valid" to one implementation and "invalid" to another.
- Adding a value to a record version that already exists changes that version's
  validity surface and therefore requires a new record version (§6.3).
- Experimental and private-use values MUST use the prefix `x-` (e.g.
  `x-mycorp-wasm@v1`). Records carrying an `x-` value are not interoperable by
  construction and MUST NOT be published to a ledger anyone else verifies. A
  registered value MUST NOT begin with `x-`.
- Every registration MUST supply: the value; the record type and versions it is
  valid in; a normative definition sufficient for a second implementer; and at
  least one positive and one negative conformance vector (§10) added in the same
  change.

### 7.1 Record types (type tags)

Policy: **maintainer action**, recorded in this section. A new type tag MUST NOT
collide with any member name used by any registered record type, in either
direction — that constraint is what makes §1.1's "exactly one type tag" decidable
by inspection.

| Tag | Versions | Status | Defined in |
| --- | --- | --- | --- |
| `artifact` | `0.1` | current | §2.1 |
| `state` | `0.1` | current | §2.2 |
| `environment_probe` | `0.1` | current | §2.2.1 |
| `toolchain_probe` | `0.1` | current | §2.2.2 |
| `intent` | `0.1` | current | §2.3 |
| `execution` | `0.1` | current | §2.4 |
| `effect` | `0.1` | current | §2.5 |
| `attribution` | `0.1` | current | §2.6 |
| `claim` | `0.1` | current | §2.7 |
| `claim_subject` | `0.1` | current | §2.8 |

### 7.2 Executor runtimes (`Execution.executor.runtime`) — closed

Policy: **Specification Required** in the IETF sense [R13] — a registration MUST
cite a stable, publicly readable document sufficient for an independent
implementer, and MUST say exactly how `invocation` is interpreted, since that is
the only thing that makes an Execution reproducible.

| Tag | Versions | Status | `invocation` |
| --- | --- | --- | --- |
| `exec@v1` | `execution` `0.1` | current | an argv vector passed directly to the platform's process-creation call: **no shell**, no word splitting, no glob expansion, no variable substitution. Element 0 is the executable, resolved through `PATH` |
| `shell@v1` | `execution` `0.1` | current | **exactly one** element: a script for a POSIX shell, executed as `sh -c <script>`. More or fewer than one element makes the record invalid |

Both registered runtimes capture `output` (§2.4) as the process's standard output
and standard error **merged into one stream in arrival order**, and neither
records which bytes came from which. A registration that captures them
separately, or not at all, is a different tag.

An MCP call, an API edit, a merge and a rollback are each candidates for their own
runtime tag; none is registered, because none is implemented.

### 7.3 Validation runtimes (`ClaimCandidate.validation.runtime`) — closed

Policy: **Specification Required**. A validation runtime is a promise about
*re-verification*, so the bar is what a second implementer needs in order to
re-run the check and get the same verdict, including the budget it may spend.

| Tag | Versions | Status | Definition |
| --- | --- | --- | --- |
| `oaip-host-shell@v1` | `claim` `0.1` | current | the check blob is executed by the host's POSIX shell — `sh -c <blob>` — **in the observed workspace**, as the process that ran the claim, with that process's full ambient authority: **no container and no isolation of the filesystem, the network, the user or the environment**. Exit 0 = `pass`, non-zero = `fail`. Re-running it reproduces the verdict only on a host configured like the filer's, and re-running a stranger's is running a stranger's shell script |
| `cmd@v1` | `claim` `0.1` | current — **readable, never written by this implementation** | Warrant §3's tag [R3]: the check blob is executed as a command **in an isolated container**; exit 0 = `pass`, non-zero = `fail` |
| `ski@v1` | — | **reserved; MUST be rejected in `claim` `0.1`** | Σ-GLYPH Book I [R7] SKI term evaluation under an ATP budget |

**Why `cmd@v1` is registered and not written.** Until 2026-07-31 this
implementation ran every check with `subprocess.run(check, shell=True)` on the
observer's own host and recorded `cmd@v1`, and §3 passed that tag into a signed
Warrant record — where Warrant §3 defines it as execution in an isolated
container. The signed decision therefore promised an execution profile that
never existed. Found by external audit (Codex, 2026-07-31) with a working
reproduction, reproduced here before it was changed. `cmd@v1` stays **readable**
because every claim written before that date carries it and §6 forbids making a
record invalid that an earlier reading called valid; nothing in this
specification, and nothing an implementation may do, makes it writable again
without an execution that actually provides a container.

**Why the honest tag stops at OAIP's own records.** `oaip-host-shell@v1` is
registered *here*, in OAIP's registry. Warrant's reason-runtime registry (Warrant
SPEC §13.1) is a different registry with the same policy (Specification
Required), **no registry operator**, and registration by pull request against the
Warrant repository; an unregistered `runtime` in a Warrant record makes that
record invalid by MUST. So an OAIP-namespaced runtime is *not* currently
legitimate in a Warrant record, and §3 forbids putting it there — the bridge
files the validation as prose plus evidence instead. Making it legitimate is
cross-repository coordination, not an OAIP edit; this specification does not
presume the outcome.

`ski@v1` is reserved rather than admitted because Σ-GLYPH is an *optional*
dependency of this specification: a v0.1 verifier without a Book I oracle cannot
evaluate the check, and a runtime that some conforming verifiers can evaluate and
others cannot is a runtime about which conforming verifiers disagree. Admitting
it is a `claim` `0.2` change — exactly as Warrant admitted it in body version
`0.2` and keeps it rejected in `0.1` [R3].

A container runtime, an MCP call and a hosted CI job are each candidates for
their own validation tag. None is registered, because none is implemented — and
registering a tag for a profile no code provides is precisely the defect above,
written down in advance.

### 7.4 Effect kinds — closed; artifact kinds — open

Policy for effect kinds: **Specification Required**. Closed, because a reader
that meets an unregistered kind does not know whether the mutation it describes
adds or removes state.

| Kind | Versions | Status | Meaning |
| --- | --- | --- | --- |
| `file.create` | `effect` `0.1` | current | the target did not exist and now does |
| `file.modify` | `effect` `0.1` | current | the target existed, exists, and its content hash changed |
| `file.delete` | `effect` `0.1` | current | the target existed and does not now |
| `file.typechange` | `effect` `0.1` | current | the target exists before and after with a different object type (e.g. file ↔ symlink) |

`Artifact.kind` (§2.1) is by contrast an **open** vocabulary: an artifact is any
blob, and the kinds of thing that can be evidence cannot be enumerated in advance.
The following are registered as the core set and SHOULD be used where they apply;
any other string is permitted and MUST NOT make a record invalid.

| Kind | Meaning |
| --- | --- |
| `stdout` | the merged standard output/error of an execution |
| `check` | the bytes of a validation check, as run |
| `check-transcript` | the captured output of a validation check |
| `check-effects` | the per-file mutations a validation check made to the observed workspace, between a snapshot taken immediately before it and one immediately after (§2.7). The bytes are canonical per §1 and carry the two `worktree_tree` ids and an array of `{target, kind, before, after}` elements as in §2.5, sorted by `(target, kind)`. **This artifact MUST NOT be shaped like a record**: it carries no member whose value is a version string, so §1.1 classifies it `not-a-record`. A record-shaped one would classify as `unknown-type`, and §6.2's fail-closed rule would then make every claim citing it unreadable — the citation is the whole point of writing it |
| `claim-subject` | the canonical bytes of a `ClaimSubject` (§2.8) |
| `environment-probe` | the canonical bytes of an `EnvironmentProbe` (§2.2.1) |
| `toolchain-probe` | the canonical bytes of a `ToolchainProbe` (§2.2.2) |
| `record:<type>` | the canonical bytes of a record of registered type `<type>` |

### 7.5 Environment and toolchain profiles (`profile`) — closed

Policy: **Specification Required**, and the registration MUST enumerate the exact
probe set, in order, with its capture rules — a profile is the whole of what makes
a fingerprint reproducible.

| Profile | Applies to | Status | Content |
| --- | --- | --- | --- |
| `posix-base@v1` | `environment_probe` `0.1` | current | `os` = `uname -s`, `arch` = `uname -m`, and exactly the five variables of §2.2.1 |
| `posix-base@v1` | `toolchain_probe` `0.1` | current | exactly one probe: `git --version` (§2.2.2) |

### 7.6 Attribution methods (`Attribution.method`) — closed

Policy: **Specification Required**, and a registration MUST state the maximum
`confidence_ppm` the method may carry and the observational conditions that
justify it. One entry, because one method is implemented; naming methods nobody
computes would be a registry of intentions.

| Method | Versions | Status | Max `confidence_ppm` | Definition |
| --- | --- | --- | --- | --- |
| `exclusive-command-window` | `attribution` `0.1` | current | **999999** | the observer started the process itself, took the `input_state` snapshot immediately before starting it and the `output_state` snapshot immediately after it terminated, and started no other writer in that window |

The ceiling is below certainty and that is the point: an observer that started one
process cannot exclude a writer it did not start (a daemon, a watcher, a second
agent, the operator's editor). A record asserting `1000000` under this method is
invalid — the format refuses to let the most confident method available claim a
certainty it cannot have.

## 8. Security considerations

This section states what OAIP tries to make unforgeable, by which mechanism, and
**against whom it fails**. It is written by capability, because "is OAIP secure"
has no answer and "can a party who can write the workspace forge an acceptance"
has one. Every mechanism named here is implemented in `impl/oaip.py` and executed
by `tools/check.py`; where nothing stops an attacker, this section says so
instead of describing a control that does not exist.

It is **informative about the record format**: nothing here changes whether a
document is `valid`, `invalid`, `unsupported-version` or `unknown-type` — §1.1
and §6.2 decide that alone. What it describes is the threat model the formats
were written against, and what the reference implementation enforces around
them; a deployment can give up every property below without emitting a single
invalid record, which is exactly why the properties are written down.

### 8.1 What is being protected

Exactly one fact: **that a particular claim was accepted, by a particular actor,
under a policy** — the claim→warrant edge of §3/§4. Everything else OAIP records
is an observation, and an observation that is wrong is a bad record, not a forged
decision.

OAIP does **not** protect: the truthfulness of the observed work (a validation
check that tests the wrong thing passes); the availability of the ledger (anyone
who can write the store can delete records, loudly); or the secrecy of anything
(no field is confidential, and the ledger is not encrypted).

Three properties an implementer MUST NOT assume, stated here because §2's field
tables point at this section for them:

- **`Intent.actor`, `Execution.executor.actor` and `ClaimCandidate.proposed_by`
  are unauthenticated strings.** Nothing in §2 binds them to a key.
  Authentication enters only at the bridge (§3), where the Warrant record is
  signed — and there it binds the *decider*, not the *executor*.
- **No OAIP record is signed** (§11 makes that a non-goal). A record's integrity
  is its address: it cannot be *changed* without becoming a different record.
  Nothing stops a party who can write the artifact directory from *adding* one;
  only the acceptance side is pinned to a signature.
- **A fingerprint is not a control.** `env_fingerprint` and
  `toolchain_fingerprint` (§2.2.1, §2.2.2) discriminate over five environment
  variables and one tool probe; §2.2.1 says in as many words that any other
  variable can change what a command does without changing the number, and
  §2.2.4 forbids reading `mismatched` as evidence of tampering. A party who can
  change the environment can change what the probes report of it.

Note the asymmetry that follows: every control below is designed so that an
attacker's best outcome is a **refusal**. Refusals are recoverable and visible;
a derived edge that nobody decided is neither.

### 8.2 Attacker capability matrix

| Capability | Can forge an acceptance? | What they CAN do | Mechanism that stops them |
|---|---|---|---|
| **(a) The observed agent** — write access to the workspace, i.e. everything under the repository including `.oaip/`, running as the observer's uid *if unconfined* | **Not by workspace write alone** (default deployment). **Yes** if it also runs unconfined as the observer's uid | Write/delete artifacts and store records; plant a keyring at `.oaip/trust.json`; rewrite `.oaip/store.json`; edit the file a validation check tests **before the check runs**; where the check invokes a script that lives in the workspace, mutate the workspace **from inside the check**, after the Execution was snapshotted; cause refusals at will | Trust root (key + keyring) outside the workspace (§8.4 profile B) — the planted keyring is never read; in-process Ed25519 verification over `"warrant-sig-v1:" \|\| WarrantID`, the WarrantID being one OAIP recomputes; keyring binding; the signed `oaip-claim:<id>` link (§3); a mutation made from inside the check is observed and the claim is refused or made to cite it (§2.7). **Nothing stops the check-target rewrite, and nothing prevents the mutation — it is seen, not blocked** — see §8.5 SA-1 and SA-13 |
| **(b) A party with write access to the TRUST ROOT** | **Yes, completely** | Bind their own key to any actor, or read the key and sign directly | Nothing. This is the trust root's definition: whoever holds it decides. Mode bits (§8.3(4)) exclude *other accounts on the host*, not this party |
| **(c) A party who controls the environment or PATH** | **Yes** | Set `OAIP_TRUST_ROOT`/`XDG_CONFIG_HOME` to a keyring they wrote; replace `git` or `sh` and lie about the snapshot; replace `$WARRANT_CLI` | Nothing for the trust root or the toolchain. `$WARRANT_CLI` alone is closed: signature validity is decided in process, so a hostile CLI can make OAIP **refuse** but not believe. The `posix-base@v1` probes (§2.2.1) record `PATH` but neither `OAIP_TRUST_ROOT` nor `XDG_CONFIG_HOME`, and they are a discriminator, not a barrier. The environment is part of the TCB and OAIP says so rather than pretending otherwise |
| **(d) A party with read-only access to the workspace** | **No** | Read every record, claim, transcript and the projection; correlate what an agent did | Nothing needs to: no OAIP record is secret. The signing key is not in the workspace (profile B) and is not readable by anyone else on the host (§8.3(4)) |
| **(e) A remote party with no local access** | **No** | Nothing directly — OAIP opens no sockets and fetches nothing. Reach is indirect: through a ledger someone *imports*, or through the toolchain (Warrant, Python, git) | Address-matching on every artifact and store record; record-shape validation on ingestion (§1.1, §6.2), so an imported record that is not what it says it is produces a reported outcome and no graph; size/count caps (`MAX_STORE_RECORD_BYTES`, `SIG_DECIDE_CAP`, `SIG_NOTE_CAP`) so an imported record cannot exhaust the verifier; keyring binding, so a record signed by a key this ledger does not vouch for produces no edge |

The matrix is executable: `tests/privilege_separation.py` is organised by these
rows, and each row's negative control — the arrangement where the attack **does**
work — is kept runnable in the same file.

### 8.3 The mechanisms, and what each is worth

1. **In-process Ed25519 verification** (`ed25519_verify`, RFC 8032 [R14],
   verify-only). The signature that decides is checked by OAIP itself, over
   Warrant SPEC §5's domain-separated message — `"warrant-sig-v1:"` followed by
   the 32 raw bytes of the WarrantID **OAIP recomputed from the record's own
   bytes**, 47 bytes in total. Removes the delegate — no program named by
   `$WARRANT_CLI` can manufacture an acceptance. Warrant is still consulted and
   may still veto.
   The cost of removing the delegate is that OAIP holds its own copy of that
   construction, and two copies of one rule can drift; §8.6 states what OAIP
   does when they have. The 15-byte separator also narrows §8.2 row (c): a
   signature by one of this ledger's bound keys made in another protocol over a
   bare 32-byte digest is no longer syntactically an OAIP acceptance.
2. **Keyring binding** (`.../trust.json`, OAIP's own rule). An edge is derived
   only from a signature by the actor the record NAMES, under a key this ledger
   binds to that actor. Warrant SPEC §5 makes binding a report, never a failure,
   so this rule is OAIP's.
3. **Trust root outside the workspace** (§8.4). Makes (2) meaningful against the
   observed agent: the keyring is not a file the observed command can write.
4. **File-mode custody.** The signing key MUST NOT be readable or writable by
   group or other; the keyring and the trust-root directory MUST NOT be
   *writable* by group or other (a keyring anyone may read is harmless — it holds
   public keys; one anyone may write vouches for their key). The implementation
   creates them 0600/0600/0700, refuses to sign, bind or rebuild while a fault
   remains, and prints the `chmod`. This excludes other accounts on a shared host
   and the accidental widening (umask, tarball restore, mode-less filesystem). It
   says nothing about a same-uid process.
5. **The signed claim link** (`subject.note` = `oaip-claim:<id>`, inside the
   signed body; a MUST at the bridge, §3). Which claim was accepted is read, not
   guessed: §2.8's subject deliberately excludes the validation, so two claims
   with opposite verdicts over one execution have identical subjects and the
   subject alone can never say which was accepted.
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

### 8.5 Security assumptions and non-goals

The boundary of the threat model above, in the form a standards reader expects.
Every item is one of two things:

- a **scoped assumption** (`SA-n`) — a condition the §4 gate requires of its
  deployment and that OAIP does not itself establish. Stating it is what makes
  §8.1's guarantee precise; omitting it would make that guarantee false.
- an **explicit non-goal** (`NG-n`) — a property deliberately not provided, with
  the reason it is out of scope rather than merely absent.

Inside the boundary, a failure is a **defect** and is in scope for a report. An
item stated here is **not** a defect — but a demonstration that reality is *worse
than the item states* is, and four rounds of adversarial review produced exactly
that, repeatedly. This section states limits; it does not claim they are the only
ones. `§11` carries the scope non-goals, `llms.txt` carries the defect history
and the release state, and a limit found in neither and true is a defect in this
section.

#### Scoped assumptions

**SA-1. The validation check is assumed to run from a state the agent did not
produce.** The check runs *after* the agent's command, against post-agent
workspace state, through the shell. **An agent that rewrites the test it will be
judged by passes honestly.** §2.7 stores the check by hash, so a reader can fetch
and re-run exactly the bytes that ran — that makes the check auditable, not
un-rewritable. This is the largest remaining hole in the §4 gate and no mechanism
in §8.3 addresses it: closing it needs the check to run from a state the agent
did not produce (a pinned revision, a separate checkout, a container), which is a
deployment decision, not a format one. Since 2026-07-31 the *record* says so: the
runtime tag is `oaip-host-shell@v1` (§7.3, SA-12), not a tag that means container.

**SA-2. The environment is assumed to be trusted.** `git`, `sh`, the Python
interpreter and `$WARRANT_CLI`'s *availability* are inside the TCB; only
`$WARRANT_CLI`'s *verdict* has been removed from it. Recording five of the
environment's variables in a fingerprint (§2.2.1) **describes** that TCB; it does
not shrink it. A party who controls the environment or `PATH` can forge an
acceptance completely (§8.2 row (c)), and nothing here stops them.

**SA-3. An actor id is assumed to be bound to a person out of band.** Actor
identity is unauthenticated free text, at the CLI (`--actor`) and in the records
(§8.1). The keyring binds a key to an actor id; **nothing binds an actor id to a
person.**

**SA-4. A bound key is assumed valid until the keyring is edited by hand.** There
is no key rotation, no revocation and no expiry.

**SA-5. The observer's uid is assumed not to be shared with the observed agent.**
An agent running unconfined as the observer's uid shares the filesystem with both
the signing key and the validation check's target, and can therefore defeat §4
operationally whatever §4 says semantically. Profile B (§8.4) moves the key out
of the *workspace* — the boundary an agent confined to the workspace cannot
cross — and **does not** move it out of the *user*. Full privilege separation
between observer and observed is profiles C and D, and this version does not
implement them. A party with write access to the trust root forges acceptances
completely and by definition (§8.2 row (b)).

**SA-6. Legacy records are assumed to be pre-convention, on evidence the filer
partly controls.** An acceptance filed before this store required the
`oaip-claim:<id>` note names no claim, and `oaip rebuild --allow-legacy-links`
will guess one by subject hash — which §2.8 says cannot distinguish two claims
with opposite verdicts over one execution. The fallback is gated twice (an
operator flag, and a record older than the moment `oaip init` stamped this
store), but the second gate reads the accept's own signed `ts`, **which whoever
holds the signing key chooses.** Legacy records also carry no `State`, so nothing
about the environment they ran in can be re-checked: the only available
fingerprint outcome is `unreproducible`.

**SA-6 is about record SHAPE and stops there.** It does not extend, and MUST NOT
be extended, to a signature made under a superseded construction: §8.6 states
why, and its whole argument is that this assumption is the one thing that must
not be reused there.

**SA-7. "Conformant" is assumed on one implementation's agreement with itself.**
There is one implementation (Python). The conformance vectors of §10 are checked
by that implementation against itself, and a second implementation is what would
make "conformant" mean something. This is why §10 requires the negative half: a
second implementation agreeing only on well-formed records would prove nothing.

**SA-8. A `State` fingerprint is assumed to discriminate, not to establish
equivalence.** `env_fingerprint` and `toolchain_fingerprint` are SHA-256 over the
`posix-base@v1` probes, whose scope is five environment variables and one tool
probe (§2.2.1). **Any other variable can change what a command does without
changing this number.** A `mismatched` outcome does not distinguish "the same
host, changed since" from "a different host entirely" — no record carries a host
identity, so no implementation can tell those apart (§2.2.4). It is also **not a
security control**: neither `OAIP_TRUST_ROOT` nor `XDG_CONFIG_HOME` is in the
profile, and a party who can change the environment can change what the probes
report of it (SA-2).

**SA-9. Attribution is assumed to be exclusive-window causality.** §2.6 provides
for uncertain causality — a weaker method MUST carry a lower `confidence_ppm` and
its own registered `method` — and the method registry (§7.6) is closed with
exactly one entry, capped at 999999 rather than at certainty. So a
File-Watcher-style guess is not merely unimplemented: it cannot be recorded at
all until someone registers it. The hard case is specified as an extension point
and is not implemented.

**SA-10. The snapshot's ledger exclusion is assumed sound, and is fundamentally
by name.** It has been broken four times by review — a nested ledger, cwd-relative
pathspecs, a case-sensitive match on a case-insensitive filesystem, and a
symlinked ledger. The pathspecs are now repo-rooted, depth-agnostic and
case-insensitive, `init` refuses a symlinked ledger, and the snapshot excludes a
symlink's target. **This is not a claim that no arrangement of a git repository
can defeat it** — four arrangements already did, and the mechanism is still
matching by name. A hardlinked file, a `core.excludesFile` interaction, and a
ledger reached through a symlinked *parent* directory have not been tested.

The exclusion also costs observation, which is a limit and not only a protection:
`icase` drops **any** path whose component case-folds to `.oaip`, at any depth, on
any filesystem, whoever created it. A user's own `src/.Oaip/config.yml` is
therefore never in a snapshot and no effect over it is ever attributed. The
snapshot now names every excluded path that is not a ledger; the exclusion itself
stays, because leaving things out is the safe direction for a signing key.

**SA-11. A bound key is assumed not to be used for anything else.** The keyring
says a key MAY sign as an actor; **nothing says what else that key may sign.**
Warrant SPEC §5's `warrant-sig-v1` separator means a signature made in another
protocol over a bare 32-byte digest is no longer syntactically an acceptance here
(§8.3.1) — a real narrowing, from "any protocol signing a bare 32-byte digest" to
"any protocol whose signed message is `warrant-sig-v1:` followed by 32 bytes",
which is this one. It is **not** closure: a key reused in a protocol that happens
to prefix the same 15 bytes, or used for anything an OAIP acceptance does not
describe, is outside what this format can reach. Key purpose is a PKI property
and OAIP has no PKI (SA-3, SA-4).

This assumption was **absent** before 2026-07-31, and its absence was a defect in
this section by this section's own rule ("a limit found in neither and true is a
defect in this section"). Until Warrant v0.4 the message an OAIP acceptance
covered was a bare SHA-256 digest, byte-indistinguishable from an in-toto/DSSE
payload digest — and `tools/intoto.py` puts one exactly one hop from this ledger
— from a Σ-GLYPH NodeHash, or from a git object id. No `SA-n` said so. It is
recorded here in its narrowed form rather than quietly dropped, because the
residue is the part that is still true.

**SA-12. The validation check is assumed to run unconfined, and the record is
assumed to say so.** OAIP provides no isolation for the check: `sh -c` on the
host, as the observer's own user, in the observed workspace, with the network
and the environment the observer has (§7.3, `oaip-host-shell@v1`). A check can
therefore read the operator's files, reach the network, and — since the trust
root is outside the *workspace* but not outside the *user* (SA-5) — read the
signing key. Nothing in §8.3 stops any of that, and nothing here claims to.

What changed on 2026-07-31 is not the confinement but the honesty of the record.
Before it, the claim and the signed Warrant both said `cmd@v1` — Warrant §3's
tag for execution in an isolated container — so a reader who applied the only
published definition of that tag would conclude the check ran confined. **The
assumption above was true the whole time and the record contradicted it.** That
is the defect class this section exists to catch: not "a control is missing" but
"a signed record describes a control that was never there". Found by external
audit (Codex, 2026-07-31) with a working reproduction.

The residue, stated plainly: a reader of an OAIP claim can now tell that the
check was unconfined, and a reader of the Warrant record can read it in prose
(§3). Neither can tell **what** an unconfined check did, beyond the workspace
mutations SA-13 requires to be observed.

**SA-13. The check's side effects are assumed to be visible in the workspace
tree, and only there.** §2.7 requires the filer to snapshot the workspace
immediately before and after the check and either refuse the claim or cite a
`check-effects` artifact. That closes exactly one hole — the reproduction where
a check of `touch check-escaped-container` created a file in the observed
workspace and the signed decision recorded `effects=0` — and it closes it by
**observing**, never by preventing. The check runs unconfined (SA-12); by the
time the second snapshot is taken, whatever it did it has already done.

**What this does NOT catch, in the order an attacker would try them:**

- **Anything outside the worktree.** Writes to `$HOME`, `/tmp`, another
  repository, the git object database, the network, or an installed package are
  not in the snapshot and are not effects here. Reading a secret is invisible by
  construction: reads are not mutations.
- **A mutation the check reverts before it exits.** The window compares two
  trees, not a trace of syscalls. `touch x && rm x` is indistinguishable from
  doing nothing, as is a file written and restored byte-for-byte.
- **Anything the snapshot already excludes.** `.oaip/` at any depth and any
  letter case is outside every snapshot (SA-10), so a check that writes there
  produces no observed effect. The same exclusion that keeps the signing key
  out of the tree keeps the ledger directory out of this observation.
- **Metadata the tree does not carry.** Mode bits beyond git's
  executable/symlink distinction, timestamps, xattrs and ownership.
- **The check rewriting what it tests before testing it** — SA-1, unchanged and
  still the largest hole in the §4 gate. Observing that the check changed a file
  does not make the verdict it then reported trustworthy.

What it *does* buy is narrower and worth stating exactly: **a claim whose check
mutated the tracked workspace is either refused or carries a list of those
mutations that a reader can fetch by hash** — the record can no longer be silent
about them. It is not a statement that the check was confined, that its verdict
is sound, or that nothing else happened.

#### Explicit non-goals

**NG-1. Signing OAIP records themselves.** No OAIP record is signed (§8.1).
Anyone who can write `.oaip/artifacts` can add a `claim` record — or an
`execution`, or an `attribution` — and only the acceptance side is pinned to a
signed note. Content-addressing means such a record cannot silently *replace*
another; **nothing makes filing one cost anything.** Out of scope because
integrity of the decision is what §8.1 protects, and an observation that is wrong
is a bad record rather than a forged decision.

**NG-2. Availability.** A party with store write access can delete records or
force refusals — including by rewriting the trust-root pointer, and including by
placing more than `SIG_DECIDE_CAP` signature entries that name the record's actor
under a bound key ahead of the real one, or by padding a record past
`MAX_STORE_RECORD_BYTES`. Each of those is a real griefing surface and each is
**fail-closed**: `oaip rebuild` exits non-zero and names the lost edge with the
reason it was refused. Out of scope because that party can already delete the
record outright, which is equally loud and equally destructive. Appending cannot
un-decide anything — the honest signature is reached first.

**NG-3. Confidentiality.** No OAIP record is secret (§8.2 row (d)). A party with
read-only workspace access can read every record, claim, transcript and the
projection, and correlate what an agent did. Nothing needs to stop them; the
signing key is what is protected, and under profile B it is not in the workspace.

**NG-4. A normative threat model.** §8 states a threat model and states it as
**informative about the record format**: nothing in §8 changes whether a document
is `valid`, `invalid`, `unsupported-version` or `unknown-type` — §1.1 and §6.2
decide that alone. A deployment can give up every property in §8 without emitting
a single invalid record, which is exactly why the properties are written down.

The remaining non-goals are matters of scope rather than of security and are
listed once, in **§11**: semantic-entity extraction, an `Observation` stream, a
Reaction runtime, federation and jurisdictions, and any opinion on whether an
intent was satisfied or which policy has authority.

### 8.6 Superseded signature constructions (MUST)

Warrant SPEC v0.4 (package 0.6.0, 2026-07-31) replaced the §5 signed message
with `"warrant-sig-v1:" || WarrantID_raw`. OAIP verifies that signature itself
(§8.3.1), so OAIP has an opinion about records signed under the previous
construction, and this section is it.

**The rule.** An implementation:

- **MUST** verify the current construction and **MUST NOT** derive an acceptance
  edge from a signature valid only under a superseded one, under any flag, at any
  time. There is no dual-accept window — a verifier accepting both has no domain
  separation at all, since an adversary simply presents the older message.
- **SHOULD** *diagnose* such a signature rather than reporting it as a generic
  bad signature, and when it does, **MUST** use Warrant SPEC §5's exact report
  string, which names the construction and the remedy (`warrant resign`). A
  corrupted byte, a truncated file, a wrong key and a store from before the flag
  day are otherwise one indistinguishable message, and the operator's next action
  differs in every case.

Refusal and diagnosis are not alternatives. **The refusal is unconditional and
the diagnosis is a sentence about it** — a diagnosis that changed a verdict would
be an acceptance path wearing a different name.

**This is NOT §6.4 legacy-read mode, and conflating them would be a mistake.**
The two look alike — both are "an old ledger, still on disk, written before a
change" — and they are different in the one place that matters:

| | §6.4 legacy-read (record shape) | §8.6 (signature construction) |
|---|---|---|
| The question | syntactic: the same facts, differently spelled | cryptographic: which bytes did the key cover? |
| Old bytes are | fully trustworthy; only the spelling moved | not evidence of an OAIP acceptance at all |
| Correct outcome | translate, mark as legacy, **derive the edge** | refuse, diagnose, **derive nothing** |
| Operator control | `--allow-legacy-links`, a flag that WIDENS derivation | none, and none may be added |
| Gated on | the store-format marker's `ts` — **which whoever holds the signing key chooses** (SA-6) | nothing; the construction is checked on every record, every time |
| Remedy | none needed; migration is read-side | `warrant resign`, which rewrites `sigs` and moves no WarrantID |

Two consequences of routing §8.6 through §6.4 are worth stating because each
would be reached by an ordinary next step:

1. §6.4 has a flag that widens what produces an edge. Giving signatures the same
   framing eventually produces `--allow-legacy-signatures`, which is the
   dual-accept window arriving through the back door.
2. §6.4's second gate is the accept's own signed `ts` — a value SA-6 already
   records as chosen by whoever holds the signing key. Applying that gate to
   signatures would let that party select the weaker *cryptographic* rule by
   choosing a timestamp, promoting SA-6's known weakness from "which claim was
   accepted" to "is this signature valid at all". Strictly worse than SA-6.

So the two paths share no flag, no code path and no vocabulary. An implementation
that reports a superseded signature MUST NOT describe it as "legacy mode", and
MUST NOT let a §6.4 legacy record reach a weaker signature rule.

**Migration is not a format concern.** A record re-signed under the current
construction keeps its WarrantID — the WarrantID is SHA-256 of the canonical body
and the envelope is not hashed (Warrant §4/§5) — so no `evidence`, `under`,
`prior`, `subject` or `oaip-claim:` reference moves, and the OAIP graph is
unchanged. A record whose signing key no longer exists cannot be migrated at all;
it stays in the store, readable and unaccepted, and no implementation may invent
an edge for it.

## 9. Relationship to prior art (normative context)

OAIP is not the first model of "who did what to what". It MUST be read against
these, and an implementer choosing between OAIP and one of them should choose one
of them unless the two additions in §9.4 are the reason they are here.

### 9.1 W3C PROV [R8][R9]

PROV-DM is the canonical model for this shape, and OAIP's records map onto it:

| OAIP | PROV |
| --- | --- |
| `Execution` | `prov:Activity` |
| `Artifact`, `State`, an `Effect`'s before/after blobs | `prov:Entity` |
| `executor.actor`, `Intent.actor`, `proposed_by` | `prov:Agent` |
| `Attribution` | `prov:wasAttributedTo` / qualified `prov:Attribution` |
| `Effect` | `prov:wasGeneratedBy` / `prov:wasInvalidatedBy` |
| `Intent` | *no PROV equivalent* — PROV records what happened, not what was wanted |

OAIP differs deliberately in being **content-addressed and closed-schema**: PROV
is an open RDF vocabulary in which an unknown term is ordinary, which is right for
interchange and wrong for a format whose identity is the hash of its bytes. An
implementation MAY publish an OAIP graph as PROV; it MUST NOT expect a PROV
consumer to preserve OAIP identities, because a serialization round-trip through
RDF does not preserve canonical bytes.

### 9.2 IETF SCITT [R10]

SCITT is the closest IETF work to "a claim filed under a registration policy on a
transparent, append-only log". A SCITT Signed Statement corresponds to an OAIP
claim *after* §3 has accepted and signed it — that is, to the bridge's output, not
to the `ClaimCandidate`. The candidate has no SCITT equivalent, because SCITT
statements are signed by construction and the candidate — proposed, checked,
possibly refused — is the state OAIP exists to record. OAIP specifies no
transparency service and no receipt; where one is needed, a Warrant store is not a
substitute for a SCITT registry, and this specification does not claim it is.

### 9.3 in-toto Attestation and SLSA Provenance [R11][R12]

| OAIP | in-toto / SLSA |
| --- | --- |
| `Execution` | SLSA `runDetails` (`builder`, `invocation`, `metadata`) |
| `Effect` | SLSA `byproducts` / `materials` |
| `Artifact`, `State` | in-toto `ResourceDescriptor` |
| `ClaimCandidate` | in-toto `Statement` (`subject` digest + `predicateType` + `predicate`) |

Those four are duplication. The right posture is to be **expressible as** in-toto
rather than to re-specify it, and `tools/intoto.py` implements exactly that
mapping. OAIP defines neither signing nor transparency: DSSE and Rekor are
separate steps with separate trust.

### 9.4 What OAIP adds

1. **The acceptance boundary (§4).** in-toto, SLSA and PROV attest what
   *happened*. None has a notion of a claim being *accepted*, nor of a refusal
   being a record rather than the absence of one.
2. **Attribution with declared uncertainty (§2.6).** `confidence_ppm` as an
   integer, with a registered `method` and a registered ceiling. Neither
   attestation ecosystem has a vocabulary for "probably this agent, by this
   inference, at this confidence".

If neither is what a reader needs, in-toto plus PROV is the better-supported
answer, and this specification says so rather than competing for the overlap.

## 10. Conformance vectors (MUST)

Two vector files; an implementation MUST pass both.

- `examples/vectors.json` — **canonicalization**. `records` pin canonical bytes
  and their SHA-256 byte-exactly; `reject` pins byte sequences a conforming
  implementation MUST refuse to ingest at all (duplicate members, NaN/Infinity,
  lone surrogates, floats, a leading BOM, and non-JSON).
- `examples/record-vectors.json` — **record shapes**. `accept` are records that
  MUST validate as the stated `(type, version)`; `reject` are documents that MUST
  NOT, each pinned with the outcome it MUST produce (`invalid`,
  `unsupported-version`, `unknown-type`, `legacy`, `not-a-record` — five, because
  returning one of them for another is a real interoperability defect that a
  pass/fail assertion would hide) — including records whose
  canonicalization is impeccable and whose *shape* is wrong, which is the half a
  canonicalization vector cannot reach.

Passing the first and not the second means an implementation agrees about how to
serialize JSON, not about what a record is. Positive vectors alone establish
neither: an implementation that accepts everything passes every positive vector,
which is why the reject half of each file is the load-bearing half.

## 11. Non-goals (v0.1)

Semantic-entity extraction (tree-sitter scope — reserved `entities`, §2.5); an
`Observation` stream of raw observer events; a **Reaction runtime** (the ring's
last arc — when specified it MUST be budget-bounded, ATP-style, so agents cannot
self-excite into unbounded loops); federation / jurisdictions (that is Warrant
Book III territory); signing of OAIP records themselves; a normative threat model
(§8 states one, and states it as informative about the format); and any opinion
on whether an intent was satisfied or which policy has authority.

## 12. Reference implementation

`impl/oaip.py` — `init`; the four recording verbs `intent`, `run`, `claim`,
`accept` and the one-shot `do`; `log`, `verify`, `rebuild` (§5); `bind` (the
keyring) and `trust-root` (where the key and keyring live — §8.4); and the two
vector runners `conformance` (§1 canonicalization, `examples/vectors.json`) and
`records` (§10 record shapes, `examples/record-vectors.json`). It writes the
records of §2, including `State` with the `EnvironmentProbe` and `ToolchainProbe`
behind its fingerprints (§2.2.1, §2.2.2), and `oaip verify` reports all three
fingerprint outcomes of §2.2.4 rather than one verdict. Workspace snapshots via
git plumbing (throwaway index), effects via `git diff-tree`, exclusive-window
attribution, and the Warrant bridge (a real signed `accept`).
`examples/auth-demo.sh` is a worked end-to-end case, including the §4 refusal: a
command that exits 0 while breaking an invariant is not accepted. Stdlib only,
plus the Warrant reference CLI for the bridge.

It implements legacy-read mode (§6.4) for stores written before the record
formats above were pinned: those records are read under the legacy rules,
marked as legacy wherever they reach the projection or a report, and never
rewritten — with the consequences §8.5 SA-6 records.

## 13. References

- [R1] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [R2] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [R3] Warrant SPEC v0.4 (package 0.6.0; pinned in CI at commit `8508a4a`),
  s0fractal. <https://github.com/s0fractal/warrant>
- [R4] Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme
  (JCS)", RFC 8785, June 2020. <https://www.rfc-editor.org/rfc/rfc8785>
- [R5] Bray, T., "The I-JSON Message Format", RFC 7493, March 2015.
  <https://www.rfc-editor.org/rfc/rfc7493>
- [R6] Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format",
  STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
- [R7] Σ-GLYPH Book I, s0fractal. <https://github.com/s0fractal/sigma-glyph>
- [R8] Moreau, L., Missier, P., eds., "PROV-DM: The PROV Data Model", W3C
  Recommendation, 30 April 2013. <https://www.w3.org/TR/prov-dm/>
- [R9] Lebo, T., Sahoo, S., McGuinness, D., eds., "PROV-O: The PROV Ontology",
  W3C Recommendation, 30 April 2013. <https://www.w3.org/TR/prov-o/>
- [R10] IETF SCITT Working Group, "An Architecture for Trustworthy and
  Transparent Digital Supply Chains", `draft-ietf-scitt-architecture` — **work in
  progress**; cite the current revision from the working group's datatracker page
  rather than this line. <https://datatracker.ietf.org/wg/scitt/documents/>
- [R11] in-toto Attestation Framework, Statement v1.
  <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
- [R12] SLSA Provenance v1.0, OpenSSF. <https://slsa.dev/spec/v1.0/provenance>
- [R13] Cotton, M., Leiba, B., Narten, T., "Guidelines for Writing an IANA
  Considerations Section in RFCs", BCP 26, RFC 8126, June 2017 — the source of
  the "Specification Required" policy used in §7.
  <https://www.rfc-editor.org/rfc/rfc8126>
- [R14] Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm
  (EdDSA)", RFC 8032, January 2017 — used by the decision layer, not by OAIP
  records. <https://www.rfc-editor.org/rfc/rfc8032>

---
*OAIP records what happened and on what observed basis. Warrant records the
decision. Σ-GLYPH computes the portable checks. The projection is disposable;
the content-addressed causal graph is the truth.*
