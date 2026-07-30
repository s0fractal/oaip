# OAIP — Observed Action & Intent Protocol — Specification v0.1

**Status:** DRAFT. Key words MUST / MUST NOT / SHOULD / SHOULD NOT / MAY per
RFC 2119 as updated by RFC 8174 ([R1], [R2]), and only when in ALL CAPS.
**Purpose.** Turn the ephemeral behavior of humans, agents, and tools into a
**content-addressed causal graph** — from which claims, decisions, and reactions
can be built *honestly*. OAIP records **what was observed**; it does **not** decide
whether an action was correct, whether an intent was met, or which policy has
authority. Those are the decision layer (Warrant) and the policy layer.

**Normative dependencies.**
- **Warrant SPEC v0.3** ([R3]) — the decision layer. OAIP **reuses Warrant §4
  canonicalization verbatim** and bridges accepted claims into Warrant records
  (§3). Not reimplemented here.
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
  "validation": { "runtime": "cmd@v1", "check": "<hex64>",
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
| `cmd@v1` | `claim` `0.1` | current | the check blob is executed as a command; exit 0 = `pass`, non-zero = `fail`. The same tag as Warrant §3 `cmd@v1`, so the bridge (§3) passes it through unchanged |
| `ski@v1` | — | **reserved; MUST be rejected in `claim` `0.1`** | Σ-GLYPH Book I [R7] SKI term evaluation under an ATP budget |

`ski@v1` is reserved rather than admitted because Σ-GLYPH is an *optional*
dependency of this specification: a v0.1 verifier without a Book I oracle cannot
evaluate the check, and a runtime that some conforming verifiers can evaluate and
others cannot is a runtime about which conforming verifiers disagree. Admitting
it is a `claim` `0.2` change — exactly as Warrant admitted it in body version
`0.2` and keeps it rejected in `0.1` [R3].

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

## 8. Security considerations (informative in v0.1)

OAIP has no threat model yet, and this section says so rather than implying one.
Two properties an implementer MUST NOT assume:

- **`actor`, `executor.actor` and `proposed_by` are unauthenticated strings.**
  Nothing in this specification binds them to a key. Authentication enters only
  at the bridge (§3), where the Warrant record is signed — and there it binds the
  *decider*, not the *executor*.
- **OAIP records are not signed.** Integrity comes from content-addressing plus
  the signed Warrant record at the decision layer. An adversary who can write the
  artifact directory can add records; what they cannot do is change one without
  changing its address, or produce a signed acceptance.

A consequence worth stating plainly: an agent that shares a filesystem with the
observer's signing key and with the validation check's target can defeat §4
operationally, whatever §4 says semantically. Privilege separation between the
observer and the observed is a design problem this version does not solve.

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
  `unsupported-version`, `unknown-type`) — including records whose
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
Book III territory); signing of OAIP records themselves; a threat model (§8); and
any opinion on whether an intent was satisfied or which policy has authority.

## 12. Reference implementation

`impl/oaip.py` — the verbs `intent`, `run`, `claim`, `accept` (plus the one-shot
`do`) and `log` / `verify` / `rebuild` / `conformance` / `records`. Workspace
snapshots via git plumbing (throwaway index), effects via `git diff-tree`,
exclusive-window attribution, and the Warrant bridge (a real signed `accept`).
`examples/auth-demo.sh` is a worked end-to-end case, including the §4 refusal: a
command that exits 0 while breaking an invariant is not accepted. Stdlib only,
plus the Warrant reference CLI for the bridge.

It implements legacy-read mode (§6.4) for stores written before the record
formats above were pinned.

## 13. References

- [R1] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [R2] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [R3] Warrant SPEC v0.3, s0fractal. <https://github.com/s0fractal/warrant>
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
